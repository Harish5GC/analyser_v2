"""Application runner and CLI-facing orchestration for T01-T25."""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from harness.attempts import (
    ProcedureAttempt,
    ResolvedProcedureProfile,
    ResolvedProfileRegistry,
    SegmentAttemptsRequest,
    load_resolved_profile_registry,
    open_attempts_reader,
    segment_attempts,
)
from harness.decoder.errors import DecoderPartialError
from harness.decoder.manifest import ArtifactDescriptor
from harness.decoder.runner import DecodeCaptureRequest, DecodeCaptureResult, run_decode
from harness.decoder.validation import validate_all_artifacts, validate_manifest
from harness.diagnostics import (
    BuildPFCPNodeStateCatalogRequest,
    DetectMissingTransitionsRequest,
    FindHTTPFailuresRequest,
    FindNASNGAPFailuresRequest,
    FindPFCPFailuresRequest,
    GetAttemptTimelineRequest,
    GetUERequestRequest,
    build_pfcp_node_state_catalog,
    detect_missing_transitions,
    find_http_failures,
    find_nas_ngap_failures,
    find_pfcp_failures,
    get_attempt_timeline,
    get_ue_request,
    open_pfcp_node_state_catalog_reader,
)
from harness.identity import BuildIdentityGraphRequest, build_identity_graph, open_identity_graph_reader
from harness.normalize import NormalizeEventsRequest, normalize_events, open_primary_event_reader
from harness.post_analysis import (
    AnalysisState,
    BuildExpandedEvidenceRequest,
    BuildInitialEvidenceRequest,
    CompareAttemptsRequest,
    DependencyEvidenceRequest,
    GenerateDiagnosisRequest,
    InspectNRFFlowRequest,
    InspectUDRFlowRequest,
    ParseScenarioRequest,
    ProviderConfig,
    RankRootCausesRequest,
    RenderReportRequest,
    RootCauseResult,
    ValidateScenarioRequest,
    build_expanded_evidence_packet,
    build_initial_evidence_packet,
    compare_attempts,
    generate_diagnosis,
    inspect_nrf_flow,
    inspect_udr_flow,
    parse_scenario,
    rank_root_causes,
    render_report,
    validate_scenario,
)
from harness.shared import (
    CaptureMetadata,
    ProtocolCodepointRegistry,
    ResolvedPolicy,
    compact_json_bytes,
    sha256_file,
)

APP_RUNNER_VERSION = "2.0.0"

StageStatus = Literal["pending", "running", "success", "partial", "failed", "skipped", "cancelled"]


class ApplicationRunConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID = Field(default_factory=uuid4)
    capture_path: Path
    run_dir: Path
    decoder_binary: Path
    profile_registry_path: Path | None = None
    profile_registry: ResolvedProfileRegistry | None = None
    scenario_text: str | None = None
    provider_config: ProviderConfig = Field(default_factory=ProviderConfig)
    attempt_id: UUID | None = None
    resume: bool = False
    stop_after_stage: str | None = None
    decoder_timeout_seconds: int = 600
    decoder_protocols: set[Literal["http2", "ngap", "pfcp"]] = Field(default_factory=lambda: {"http2", "ngap", "pfcp"})
    enabled_capabilities: set[str] = Field(default_factory=set)
    policy_versions: dict[str, str] = Field(default_factory=dict)
    protocol_registry: ProtocolCodepointRegistry = Field(default_factory=lambda: ProtocolCodepointRegistry(
        registry_name="default",
        registry_version="default",
        schema_version="2.0",
        sha256="sha256:default-protocol-registry",
    ))
    partition_policy: ResolvedPolicy = Field(default_factory=lambda: ResolvedPolicy(
        name="default-partition-policy",
        version="default",
        sha256="sha256:default-partition-policy",
        payload={},
    ))
    identity_rules: ResolvedPolicy = Field(default_factory=lambda: ResolvedPolicy(
        name="default-identity-rules",
        version="default",
        sha256="sha256:default-identity-rules",
        payload={"masking_key_source": "provided"},
    ))
    topology_rules: ResolvedPolicy = Field(default_factory=lambda: ResolvedPolicy(
        name="default-topology-rules",
        version="default",
        sha256="sha256:default-topology-rules",
        payload={},
    ))
    masking_policy: ResolvedPolicy = Field(default_factory=lambda: ResolvedPolicy(
        name="default-masking-policy",
        version="default",
        sha256="sha256:default-masking-policy",
        payload={},
    ))
    masking_key: SecretStr | None = Field(default=None, exclude=True)


class StageRunRecord(BaseModel):
    tool: str
    status: StageStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    elapsed_ms: int | None = None
    revision: str | None = None
    error: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class ApplicationRunManifest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    runner_version: str = APP_RUNNER_VERSION
    analysis_id: UUID
    status: Literal["success", "partial", "failed", "cancelled"]
    input_fingerprint: str
    resume_of: str | None = None
    stages: list[StageRunRecord] = Field(default_factory=list)
    analysis_state_path: str
    report_manifest_path: str | None = None
    warnings: list[str] = Field(default_factory=list)
    started_at: datetime
    completed_at: datetime | None = None


class ApplicationRunResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    status: Literal["success", "partial", "failed", "cancelled"]
    manifest_path: Path
    analysis_state_path: Path
    report_manifest_path: Path | None = None
    stage_statuses: dict[str, str] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class RunnerHooks:
    decode: Callable[[DecodeCaptureRequest], DecodeCaptureResult] = run_decode


@dataclass
class _RuntimeState:
    config: ApplicationRunConfig
    app_dir: Path
    run_manifest_path: Path
    analysis_state_path: Path
    records: dict[str, StageRunRecord]
    started_at: datetime
    input_fingerprint: str
    warnings: list[str]


def run_analysis(config: ApplicationRunConfig, hooks: RunnerHooks | None = None) -> ApplicationRunResult:
    hooks = hooks or RunnerHooks()
    run_dir = config.run_dir.resolve()
    app_dir = run_dir / "app"
    app_dir.mkdir(parents=True, exist_ok=True)
    run_manifest_path = app_dir / "run_manifest.json"
    analysis_state_path = app_dir / "analysis_state.json"
    input_fingerprint = _input_fingerprint(config)
    if config.resume and run_manifest_path.exists():
        previous = ApplicationRunManifest.model_validate(json.loads(run_manifest_path.read_text(encoding="utf-8")))
        if previous.input_fingerprint != input_fingerprint:
            raise ValueError("resume requested with different immutable inputs")
        if previous.status == "success" and previous.report_manifest_path is not None:
            return ApplicationRunResult(
                analysis_id=previous.analysis_id,
                status=previous.status,
                manifest_path=run_manifest_path,
                analysis_state_path=analysis_state_path,
                report_manifest_path=run_dir / previous.report_manifest_path,
                stage_statuses={record.tool: record.status for record in previous.stages},
                warnings=[*previous.warnings, "resume_returned_completed_run"],
            )

    runtime = _RuntimeState(
        config=config,
        app_dir=app_dir,
        run_manifest_path=run_manifest_path,
        analysis_state_path=analysis_state_path,
        records={},
        started_at=datetime.now(tz=timezone.utc),
        input_fingerprint=input_fingerprint,
        warnings=["resume_restarted_from_same_inputs"] if config.resume and run_manifest_path.exists() else [],
    )
    state = AnalysisState(
        analysis_id=config.analysis_id,
        capture={},
        run_dir=run_dir,
        report_dir=run_dir / "report",
        stage_statuses={},
        stage_revisions={},
        timings_ms={},
    )

    try:
        decode_result = _run_stage(runtime, state, "T01", lambda: hooks.decode(_decode_request(config)))
        state.capture.update(
            {
                "source_sha256": decode_result.source.sha256,
                "completed_at": decode_result.completed_at.isoformat(),
            }
        )
        if _should_stop(runtime, state, "T01"):
            return _finish_without_report(runtime, state, "cancelled")

        normalization = _run_stage(
            runtime,
            state,
            "T02",
            lambda: normalize_events(
                NormalizeEventsRequest(
                    analysis_id=config.analysis_id,
                    decoder_result=decode_result,
                    run_dir=run_dir,
                    normalized_dir=run_dir / "normalized",
                    indexes_dir=run_dir / "indexes",
                    protocol_registry=config.protocol_registry,
                    partition_policy=config.partition_policy,
                    enabled_capabilities=config.enabled_capabilities,
                    policy_versions=config.policy_versions,
                )
            ),
        )
        primary_reader = open_primary_event_reader(normalization)
        primary_events = list(primary_reader.by_frame(0, 10**12))
        capture = _capture_metadata(decode_result, primary_events)
        state.capture.update(
            {
                "packet_count": capture.packet_count,
                "first_frame": capture.first_frame,
                "last_frame": capture.last_frame,
            }
        )
        if _should_stop(runtime, state, "T02"):
            return _finish_without_report(runtime, state, "cancelled")

        identity_result = _run_stage(
            runtime,
            state,
            "T03",
            lambda: build_identity_graph(
                BuildIdentityGraphRequest(
                    analysis_id=config.analysis_id,
                    normalization=normalization,
                    primary_reader=primary_reader,
                    capture=capture,
                    run_dir=run_dir,
                    identity_dir=run_dir / "normalized" / "identity",
                    indexes_dir=run_dir / "indexes",
                    identity_rules=config.identity_rules,
                    topology_rules=config.topology_rules,
                    masking_policy=config.masking_policy,
                    masking_key=config.masking_key,
                    enabled_capabilities=config.enabled_capabilities,
                    policy_versions=config.policy_versions,
                )
            ),
        )
        identity_graph = open_identity_graph_reader(identity_result)
        if _should_stop(runtime, state, "T03"):
            return _finish_without_report(runtime, state, "cancelled")

        profile_registry = _profile_registry(config)
        attempts_result = _run_stage(
            runtime,
            state,
            "T04",
            lambda: segment_attempts(
                SegmentAttemptsRequest(
                    analysis_id=config.analysis_id,
                    normalization=normalization,
                    identity_result=identity_result,
                    primary_reader=primary_reader,
                    identity_graph=identity_graph,
                    capture=capture,
                    profile_registry=profile_registry,
                    run_dir=run_dir,
                    attempts_dir=run_dir / "normalized" / "attempts",
                    indexes_dir=run_dir / "indexes",
                    enabled_capabilities=config.enabled_capabilities,
                    policy_versions={"profile_registry": profile_registry.registry_version},
                )
            ),
        )
        attempts_reader = open_attempts_reader(attempts_result)
        selected_attempts = _select_attempts(config, attempts_reader.attempts)
        state.attempts = selected_attempts
        if _should_stop(runtime, state, "T04"):
            return _finish_without_report(runtime, state, "cancelled")

        if not selected_attempts:
            _set_stage(runtime, state, "T05", "skipped", details={"reason": "no_attempts"})
            return _render_final(runtime, state, status_hint="partial")

        profile_by_id = {profile.profile_id: profile for profile in profile_registry.profiles}
        _run_stage(
            runtime,
            state,
            "T08_CATALOG",
            lambda: build_pfcp_node_state_catalog(
                BuildPFCPNodeStateCatalogRequest(
                    analysis_id=config.analysis_id,
                    normalization=normalization,
                    primary_reader=primary_reader,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized" / "diagnostics",
                )
            ),
        )
        catalog_result = build_pfcp_node_state_catalog(
            BuildPFCPNodeStateCatalogRequest(
                analysis_id=config.analysis_id,
                normalization=normalization,
                primary_reader=primary_reader,
                run_dir=run_dir,
                diagnostics_dir=run_dir / "normalized" / "diagnostics",
            )
        )
        catalog_reader = open_pfcp_node_state_catalog_reader(catalog_result, run_dir)

        request_results = []
        detector_candidates_by_attempt: dict[UUID, list[Any]] = {}
        terminal_effects_by_attempt: dict[UUID, list[Any]] = {}
        missing_results_by_attempt: dict[UUID, Any] = {}
        timelines = []

        for attempt in selected_attempts:
            request_result = get_ue_request(
                GetUERequestRequest(
                    analysis_id=config.analysis_id,
                    attempt=attempt,
                    attempts_revision=attempts_result.revision,
                    primary_reader=primary_reader,
                    identity_graph=identity_graph,
                    masking_policy={"salt": config.input_fingerprint if hasattr(config, "input_fingerprint") else input_fingerprint},
                    run_dir=run_dir,
                    requests_dir=run_dir / "normalized" / "requests",
                )
            )
            request_results.append(request_result)
        state.request_results = request_results
        _set_stage(runtime, state, "T05", "success", revision=";".join(sorted(item.revision for item in request_results)))
        if _should_stop(runtime, state, "T05"):
            return _finish_without_report(runtime, state, "cancelled")

        request_by_attempt = {item.attempt_id: item for item in request_results}
        http_results = []
        nas_results = []
        pfcp_results = []
        for attempt in selected_attempts:
            profile = profile_by_id.get(attempt.profile_id) or profile_registry.profiles[0]
            http_result = find_http_failures(
                FindHTTPFailuresRequest(
                    analysis_id=config.analysis_id,
                    attempt=attempt,
                    attempts_revision=attempts_result.revision,
                    primary_reader=primary_reader,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized" / "diagnostics" / str(attempt.attempt_id) / "T06",
                )
            )
            nas_result = find_nas_ngap_failures(
                FindNASNGAPFailuresRequest(
                    analysis_id=config.analysis_id,
                    attempt=attempt,
                    attempts_revision=attempts_result.revision,
                    primary_reader=primary_reader,
                    profile=profile,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized" / "diagnostics" / str(attempt.attempt_id) / "T07",
                )
            )
            pfcp_result = find_pfcp_failures(
                FindPFCPFailuresRequest(
                    analysis_id=config.analysis_id,
                    attempt=attempt,
                    attempts_revision=attempts_result.revision,
                    primary_reader=primary_reader,
                    identity_graph=identity_graph,
                    node_state_catalog=catalog_reader,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized" / "diagnostics" / str(attempt.attempt_id) / "T08",
                )
            )
            http_results.append(http_result)
            nas_results.append(nas_result)
            pfcp_results.append(pfcp_result)
            detector_candidates_by_attempt[attempt.attempt_id] = [
                *http_result.candidates,
                *nas_result.candidates,
                *pfcp_result.candidates,
            ]
            terminal_effects_by_attempt[attempt.attempt_id] = list(nas_result.terminal_effects)
            missing_result = detect_missing_transitions(
                DetectMissingTransitionsRequest(
                    analysis_id=config.analysis_id,
                    attempt=attempt,
                    attempts_revision=attempts_result.revision,
                    profile=profile,
                    http_result=http_result,
                    nas_ngap_result=nas_result,
                    pfcp_result=pfcp_result,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized" / "diagnostics" / str(attempt.attempt_id) / "T09",
                )
            )
            missing_results_by_attempt[attempt.attempt_id] = missing_result
            detector_candidates_by_attempt[attempt.attempt_id].extend(missing_result.candidates)
            timelines.append(
                get_attempt_timeline(
                    GetAttemptTimelineRequest(
                        analysis_id=config.analysis_id,
                        attempt=attempt,
                        request_result=request_by_attempt[attempt.attempt_id],
                        primary_reader=primary_reader,
                        http_result=http_result,
                        nas_ngap_result=nas_result,
                        pfcp_result=pfcp_result,
                        missing_result=missing_result,
                        run_dir=run_dir,
                        diagnostics_dir=run_dir / "normalized" / "diagnostics" / str(attempt.attempt_id) / "T10",
                    )
                )
            )
        state.timelines = timelines
        _set_stage(runtime, state, "T06", _aggregate_result_status(item.status for item in http_results), revision=";".join(item.revision for item in http_results))
        _set_stage(runtime, state, "T07", _aggregate_result_status(item.status for item in nas_results), revision=";".join(item.revision for item in nas_results))
        _set_stage(runtime, state, "T08", _aggregate_result_status(item.status for item in pfcp_results), revision=";".join(item.revision for item in pfcp_results))
        _set_stage(runtime, state, "T09", _aggregate_result_status(item.status for item in missing_results_by_attempt.values()), revision=";".join(item.revision for item in missing_results_by_attempt.values()))
        _set_stage(runtime, state, "T10", "success", revision=";".join(item.revision for item in timelines))
        if _should_stop(runtime, state, "T10"):
            return _finish_without_report(runtime, state, "cancelled")

        comparisons = []
        root_causes: list[RootCauseResult] = []
        for attempt in selected_attempts:
            request_result = request_by_attempt[attempt.attempt_id]
            comparison = compare_attempts(
                CompareAttemptsRequest(
                    analysis_id=config.analysis_id,
                    failed_attempt=attempt,
                    candidate_baselines=[item for item in attempts_reader.attempts if item.attempt_id != attempt.attempt_id],
                    failed_request=request_result,
                    baseline_requests=request_results,
                )
            )
            comparisons.append(comparison)
            root_causes.append(
                rank_root_causes(
                    RankRootCausesRequest(
                        analysis_id=config.analysis_id,
                        attempt=attempt,
                        candidates=detector_candidates_by_attempt[attempt.attempt_id],
                        terminal_effects=terminal_effects_by_attempt[attempt.attempt_id],
                        comparison=comparison.comparisons[0] if comparison.comparisons else None,
                        dependency_results=[],
                        pass_stage="primary",
                    )
                )
            )
        state.comparisons = comparisons
        state.root_cause_results = root_causes
        _set_stage(runtime, state, "T11", "success")
        _set_stage(runtime, state, "T12", "success", revision=";".join(item.ranking_revision for item in root_causes))

        scenario_validation = None
        if config.scenario_text:
            parsed = parse_scenario(ParseScenarioRequest(analysis_id=config.analysis_id, scenario_text=config.scenario_text, provider_mode=config.provider_config.mode))
            _set_stage(runtime, state, "T13", parsed.status)
            if parsed.spec is not None:
                scenario_validation = validate_scenario(
                    ValidateScenarioRequest(
                        analysis_id=config.analysis_id,
                        scenario=parsed.spec,
                        explicit_attempt_id=config.attempt_id,
                        attempts=selected_attempts,
                        requests=request_results,
                        root_causes=root_causes,
                        pass_stage="primary",
                    )
                )
                state.scenario_validation = scenario_validation
                _set_stage(runtime, state, "T14", scenario_validation.overall_status, revision=scenario_validation.validation_revision)
        else:
            _set_stage(runtime, state, "T13", "skipped")
            _set_stage(runtime, state, "T14", "skipped")

        evidence_results = []
        diagnoses = []
        root_by_attempt = {item.attempt_id: item for item in root_causes}
        timeline_by_attempt = {item.attempt_id: item for item in timelines}
        comparison_by_attempt = {item.failed_attempt_id: item for item in comparisons}
        for attempt in selected_attempts:
            root = root_by_attempt[attempt.attempt_id]
            packet_result = build_initial_evidence_packet(
                BuildInitialEvidenceRequest(
                    analysis_id=config.analysis_id,
                    attempt=attempt,
                    request_result=request_by_attempt[attempt.attempt_id],
                    root_cause=root,
                    timeline=timeline_by_attempt[attempt.attempt_id],
                    comparison=comparison_by_attempt.get(attempt.attempt_id),
                    scenario_validation=scenario_validation,
                    provider_mode=config.provider_config.mode,
                    run_dir=run_dir,
                    evidence_dir=run_dir / "evidence" / str(attempt.attempt_id) / "T15",
                )
            )
            evidence_results.append(packet_result)
            diagnoses.append(
                generate_diagnosis(
                    GenerateDiagnosisRequest(
                        analysis_id=config.analysis_id,
                        attempt_id=attempt.attempt_id,
                        packet=packet_result.packet,
                        pass_stage="initial",
                        provider_config=config.provider_config,
                    )
                )
            )
        state.diagnoses = diagnoses
        _set_stage(runtime, state, "T15", "success", revision=";".join(item.manifest.revision or "" for item in evidence_results))
        _set_stage(runtime, state, "T16", _aggregate_result_status(item.status for item in diagnoses))

        dependency_results = _run_dependency_requests(config, normalization, run_dir, evidence_results, diagnoses)
        state.dependency_results = dependency_results
        if dependency_results:
            _set_stage(runtime, state, "T24/T25", _aggregate_result_status(getattr(item, "status", "unknown") for item in dependency_results))
            expanded_roots = []
            for root in root_causes:
                dependency_candidates = [
                    candidate
                    for result in dependency_results
                    for candidate in getattr(result, "failure_candidates", [])
                    if getattr(result, "attempt_id", None) == root.attempt_id
                ]
                if dependency_candidates:
                    attempt = next(item for item in selected_attempts if item.attempt_id == root.attempt_id)
                    expanded_roots.append(
                        rank_root_causes(
                            RankRootCausesRequest(
                                analysis_id=config.analysis_id,
                                attempt=attempt,
                                candidates=[*root.candidate_records, *dependency_candidates],
                                dependency_results=dependency_results,
                                pass_stage="dependency_expanded",
                                primary_ranking_revision=root.ranking_revision,
                            )
                        )
                    )
            if expanded_roots:
                state.root_cause_results = expanded_roots
                _set_stage(runtime, state, "T12_FINAL", "success", revision=";".join(item.ranking_revision for item in expanded_roots))
                for packet_result, diagnosis in zip(evidence_results, diagnoses):
                    root = next((item for item in expanded_roots if item.attempt_id == diagnosis.attempt_id), None)
                    if root is None:
                        continue
                    expanded_packet = build_expanded_evidence_packet(
                        BuildExpandedEvidenceRequest(
                            initial_packet=packet_result.packet,
                            dependency_results=dependency_results,
                            expanded_root_cause=root,
                            scenario_validation=scenario_validation,
                            run_dir=run_dir,
                            evidence_dir=run_dir / "evidence" / str(root.attempt_id) / "T15_final",
                        )
                    )
                    state.diagnoses.append(
                        generate_diagnosis(
                            GenerateDiagnosisRequest(
                                analysis_id=config.analysis_id,
                                attempt_id=root.attempt_id,
                                packet=expanded_packet.packet,
                                pass_stage="final",
                                provider_config=config.provider_config,
                            )
                        )
                    )
        else:
            _set_stage(runtime, state, "T24/T25", "skipped")

        return _render_final(runtime, state, status_hint="success")
    except Exception as exc:
        runtime.warnings.append(str(exc))
        return _render_final(runtime, state, status_hint="failed", error=exc)


def _run_stage(runtime: _RuntimeState, state: AnalysisState, tool: str, func: Callable[[], Any]) -> Any:
    started = datetime.now(tz=timezone.utc)
    _set_stage(runtime, state, tool, "running", started_at=started)
    start = time.monotonic()
    try:
        result = func()
    except DecoderPartialError as exc:
        result = _decode_result_from_manifest(Path(exc.manifest_path or ""), runtime.config.analysis_id, runtime.config.run_dir)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    completed = datetime.now(tz=timezone.utc)
    status = str(getattr(result, "status", "success"))
    if status == "completed":
        status = "success"
    if status == "empty":
        status = "partial"
    revision = getattr(result, "revision", None)
    _set_stage(runtime, state, tool, _normalize_stage_status(status), started_at=started, completed_at=completed, elapsed_ms=elapsed_ms, revision=revision)
    return result


def _set_stage(
    runtime: _RuntimeState,
    state: AnalysisState,
    tool: str,
    status: str,
    *,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    elapsed_ms: int | None = None,
    revision: str | None = None,
    error: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    record = runtime.records.get(tool)
    runtime.records[tool] = StageRunRecord(
        tool=tool,
        status=_normalize_stage_status(status),
        started_at=started_at or (None if record is None else record.started_at),
        completed_at=completed_at,
        elapsed_ms=elapsed_ms,
        revision=revision,
        error=error,
        details=details or {},
    )
    state.stage_statuses[tool] = _normalize_stage_status(status)
    if revision:
        state.stage_revisions[tool] = revision
    if elapsed_ms is not None:
        state.timings_ms[tool] = elapsed_ms
    _write_runtime_files(runtime, state, "partial")


def _render_final(
    runtime: _RuntimeState,
    state: AnalysisState,
    *,
    status_hint: Literal["success", "partial", "failed"],
    error: Exception | None = None,
) -> ApplicationRunResult:
    if error is not None:
        failed_tool = next((tool for tool, record in reversed(runtime.records.items()) if record.status == "running"), "runner")
        _set_stage(runtime, state, failed_tool, "failed", completed_at=datetime.now(tz=timezone.utc), error=str(error))
        state.publication_warnings.append(str(error))
    report_result = None
    try:
        report_result = render_report(RenderReportRequest(analysis_id=runtime.config.analysis_id, analysis_state=state))
        _set_stage(runtime, state, "T17", report_result.status, revision=report_result.report_manifest.revision)
    except Exception as report_exc:
        runtime.warnings.append(f"report_publication_failed: {report_exc}")
        _set_stage(runtime, state, "T17", "failed", error=str(report_exc))
        if status_hint != "failed":
            status_hint = "failed"
    status = "failed" if status_hint == "failed" or state.stage_statuses.get("T17") == "failed" else "partial" if any(value in {"partial", "failed"} for value in state.stage_statuses.values()) else "success"
    if report_result is not None and report_result.status == "failed":
        status = "failed"
    elif report_result is not None and report_result.status == "partial" and status == "success":
        status = "partial"
    _write_runtime_files(runtime, state, status, report_manifest_path=None if report_result is None else report_result.report_manifest.relative_path)
    return ApplicationRunResult(
        analysis_id=runtime.config.analysis_id,
        status=status,
        manifest_path=runtime.run_manifest_path,
        analysis_state_path=runtime.analysis_state_path,
        report_manifest_path=None if report_result is None else runtime.config.run_dir / report_result.report_manifest.relative_path,
        stage_statuses=dict(state.stage_statuses),
        warnings=list(runtime.warnings),
    )


def _finish_without_report(runtime: _RuntimeState, state: AnalysisState, status: Literal["partial", "cancelled"]) -> ApplicationRunResult:
    _write_runtime_files(runtime, state, status)
    return ApplicationRunResult(
        analysis_id=runtime.config.analysis_id,
        status=status,
        manifest_path=runtime.run_manifest_path,
        analysis_state_path=runtime.analysis_state_path,
        stage_statuses=dict(state.stage_statuses),
        warnings=list(runtime.warnings),
    )


def _write_runtime_files(
    runtime: _RuntimeState,
    state: AnalysisState,
    status: Literal["success", "partial", "failed", "cancelled"],
    *,
    report_manifest_path: str | None = None,
) -> None:
    state.generated_at = datetime.now(tz=timezone.utc)
    _atomic_write_json(runtime.analysis_state_path, state.model_dump(mode="json", exclude_none=True))
    manifest = ApplicationRunManifest(
        analysis_id=runtime.config.analysis_id,
        status=status,
        input_fingerprint=runtime.input_fingerprint,
        stages=list(runtime.records.values()),
        analysis_state_path=str(runtime.analysis_state_path.relative_to(runtime.config.run_dir)),
        report_manifest_path=report_manifest_path,
        warnings=runtime.warnings,
        started_at=runtime.started_at,
        completed_at=datetime.now(tz=timezone.utc) if status in {"success", "partial", "failed", "cancelled"} else None,
    )
    _atomic_write_json(runtime.run_manifest_path, manifest.model_dump(mode="json", exclude_none=True))


def _decode_request(config: ApplicationRunConfig) -> DecodeCaptureRequest:
    return DecodeCaptureRequest(
        analysis_id=config.analysis_id,
        retained_pcap_path=config.capture_path,
        run_dir=config.run_dir,
        decoder_binary=config.decoder_binary,
        timeout_seconds=config.decoder_timeout_seconds,
        protocols=config.decoder_protocols,
        enabled_capabilities=config.enabled_capabilities,
        policy_versions=config.policy_versions,
    )


def _decode_result_from_manifest(manifest_path: Path, analysis_id: UUID, run_dir: Path) -> DecodeCaptureResult:
    if not manifest_path:
        raise ValueError("partial decoder result did not provide manifest_path")
    manifest = validate_manifest(run_dir, manifest_path)
    validate_all_artifacts(run_dir, manifest)
    manifest_desc = ArtifactDescriptor(
        artifact_id="",
        relative_path="decoder/decoder_manifest.json",
        artifact_type="decoder_manifest",
        media_type="application/json",
        format_schema_version=manifest.schema_version,
        sha256=sha256_file(manifest_path),
        byte_size=manifest_path.stat().st_size,
        record_count=1,
        creation_stage="T01",
    )
    return DecodeCaptureResult(
        analysis_id=analysis_id,
        status=manifest.status,
        revision=manifest.revision,
        source=manifest.source,
        manifest=manifest_desc,
        protocols=manifest.protocols,
        artifacts=manifest.artifacts,
        collections=manifest.collections,
        decoder_version=manifest.decoder.version,
        tshark_version=manifest.decoder.tshark_version,
        started_at=_parse_time(manifest.started_at),
        completed_at=_parse_time(manifest.completed_at),
        elapsed_ms=manifest.elapsed_ms,
        warnings=[*manifest.warnings, *[warning for result in manifest.protocols.values() for warning in result.warnings]],
        manifest_path=manifest_path,
    )


def _profile_registry(config: ApplicationRunConfig) -> ResolvedProfileRegistry:
    if config.profile_registry is not None:
        return config.profile_registry
    if config.profile_registry_path is None:
        raise ValueError("profile_registry_path is required")
    return load_resolved_profile_registry(config.profile_registry_path)


def _select_attempts(config: ApplicationRunConfig, attempts: list[ProcedureAttempt]) -> list[ProcedureAttempt]:
    if config.attempt_id is None:
        return attempts
    selected = [attempt for attempt in attempts if attempt.attempt_id == config.attempt_id]
    if not selected:
        raise ValueError(f"selected attempt_id {config.attempt_id} was not produced by T04")
    return selected


def _capture_metadata(decode_result: DecodeCaptureResult, events: list[Any]) -> CaptureMetadata:
    if events:
        timestamped = [event for event in events if event.timestamp is not None]
        return CaptureMetadata(
            first_frame=min(event.frame for event in events),
            last_frame=max(event.frame for event in events),
            first_timestamp=min((event.timestamp for event in timestamped), default=None),
            last_timestamp=max((event.timestamp for event in timestamped), default=None),
            packet_count=sum(result.input_packets for result in decode_result.protocols.values()),
            source_sha256=decode_result.source.sha256,
        )
    return CaptureMetadata(
        first_frame=0,
        last_frame=0,
        first_timestamp=None,
        last_timestamp=None,
        packet_count=sum(result.input_packets for result in decode_result.protocols.values()),
        source_sha256=decode_result.source.sha256,
    )


def _run_dependency_requests(
    config: ApplicationRunConfig,
    normalization: Any,
    run_dir: Path,
    evidence_results: list[Any],
    diagnoses: list[Any],
) -> list[Any]:
    packet_by_id = {result.packet.packet_id: result.packet for result in evidence_results}
    results = []
    for diagnosis in diagnoses:
        if diagnosis.diagnosis is None:
            continue
        for request in diagnosis.diagnosis.dependency_evidence_requests:
            packet = packet_by_id.get(diagnosis.packet_id)
            if packet is None:
                continue
            results.append(_run_dependency_request(config, normalization, run_dir, packet.packet_id, request))
    return results


def _run_dependency_request(
    config: ApplicationRunConfig,
    normalization: Any,
    run_dir: Path,
    initial_packet_id: UUID,
    request: DependencyEvidenceRequest,
) -> Any:
    if request.tool == "inspect_nrf_flow":
        return inspect_nrf_flow(
            InspectNRFFlowRequest(
                request_id=uuid4(),
                analysis_id=config.analysis_id,
                initial_packet_id=initial_packet_id,
                attempt_id=request.attempt_id,
                reason_code=request.reason_code,
                rationale=request.rationale,
                initial_evidence_ids=request.initial_evidence_ids,
                frame_start=request.frame_start,
                frame_end=request.frame_end,
                nf_type=request.nf_type,
                service_name=request.service_name,
                nf_instance_id=request.nf_instance_id,
                fqdn=request.fqdn,
                consumer_nf=request.consumer_nf,
                normalization=normalization,
                run_dir=run_dir,
                diagnostics_dir=run_dir / "normalized" / "diagnostics" / "T24",
            )
        )
    return inspect_udr_flow(
        InspectUDRFlowRequest(
            request_id=uuid4(),
            analysis_id=config.analysis_id,
            initial_packet_id=initial_packet_id,
            attempt_id=request.attempt_id,
            reason_code=request.reason_code,
            rationale=request.rationale,
            initial_evidence_ids=request.initial_evidence_ids,
            frame_start=request.frame_start,
            frame_end=request.frame_end,
            consumer_nf=request.consumer_nf,
            resource_or_operation=request.resource_or_operation,
            masked_correlation_key=request.masked_correlation_key,
            normalization=normalization,
            run_dir=run_dir,
            diagnostics_dir=run_dir / "normalized" / "diagnostics" / "T25",
        )
    )


def _should_stop(runtime: _RuntimeState, state: AnalysisState, stage: str) -> bool:
    if runtime.config.stop_after_stage != stage:
        return False
    _set_stage(runtime, state, "RUNNER", "cancelled", details={"reason": f"stopped_after_{stage}"})
    return True


def _aggregate_result_status(statuses: Any) -> str:
    values = [str(item) for item in statuses]
    if not values:
        return "skipped"
    if any(value == "failed" for value in values):
        return "failed"
    if any(value in {"partial", "inconclusive", "unknown"} for value in values):
        return "partial"
    if all(value == "disabled" for value in values):
        return "skipped"
    return "success"


def _normalize_stage_status(status: str) -> StageStatus:
    if status in {"success", "verified", "completed", "disabled"}:
        return "success" if status != "disabled" else "skipped"
    if status in {"partial", "inconclusive", "unknown", "empty"}:
        return "partial"
    if status in {"failed"}:
        return "failed"
    if status in {"skipped", "not_applicable", "not_run"}:
        return "skipped"
    if status in {"running", "cancelled", "pending"}:
        return status  # type: ignore[return-value]
    return "partial"


def _input_fingerprint(config: ApplicationRunConfig) -> str:
    payload = {
        "analysis_id": str(config.analysis_id),
        "capture_sha256": sha256_file(config.capture_path) if config.capture_path.exists() else None,
        "decoder_binary": str(config.decoder_binary),
        "profile_registry_path": None if config.profile_registry_path is None else str(config.profile_registry_path),
        "profile_registry_sha256": sha256_file(config.profile_registry_path) if config.profile_registry_path and config.profile_registry_path.exists() else None,
        "scenario_text": config.scenario_text,
        "attempt_id": None if config.attempt_id is None else str(config.attempt_id),
        "provider_mode": config.provider_config.mode,
        "protocol_registry": config.protocol_registry.model_dump(mode="json"),
        "partition_policy": config.partition_policy.model_dump(mode="json"),
        "identity_rules": config.identity_rules.model_dump(mode="json"),
        "topology_rules": config.topology_rules.model_dump(mode="json"),
        "masking_policy": config.masking_policy.model_dump(mode="json"),
    }
    import hashlib

    return "sha256:" + hashlib.sha256(compact_json_bytes(payload)).hexdigest()


def _atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(compact_json_bytes(payload) + b"\n")
    with temporary.open("rb") as handle:
        os.fsync(handle.fileno())
    temporary.replace(path)
    directory = os.open(str(path.parent), os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
