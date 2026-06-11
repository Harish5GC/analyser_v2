"""T05-T10 per-attempt request, detector, and timeline stages."""
from __future__ import annotations

import base64
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, DefaultDict, Iterable, Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from harness.attempts import (
    ProcedureAttempt,
    ResolvedProcedureProfile,
    SegmentAttemptsResult,
    StageDefinition,
)
from harness.decoder.manifest import ArtifactDescriptor
from harness.identity import IdentityGraphReader
from harness.normalize import JsonlPrimaryEventReader, NormalizeEventsResult
from harness.shared import (
    CanonicalEvent,
    EventIdentifiers,
    Issue,
    JsonArtifactWriter,
    JsonlArtifactWriter,
    SourceRef,
    artifact_by_relative_path,
    compact_json_bytes,
    deterministic_uuid,
    iter_jsonl,
    mask_identifier,
    publish_closed_artifacts,
    sample_issues,
    sha256_bytes,
    sha256_file,
    validate_inside_run,
)

SCHEMA_VERSION = "2.0"
REQUEST_VERSION = "2.0.0"
DETECTOR_VERSION = "2.0.0"
TIMELINE_VERSION = "2.0.0"


class MissingField(BaseModel):
    name: str
    reason_codes: list[str] = Field(default_factory=list)


class RequestFieldConflict(BaseModel):
    name: str
    values: list[Any]
    source_event_ids: list[UUID]
    source_frames: list[int]


class RequestedField(BaseModel):
    name: str
    value: Any | None = None
    status: Literal["explicit", "derived_from_request", "conflicting", "unknown"]
    source_event_ids: list[UUID] = Field(default_factory=list)
    source_frames: list[int] = Field(default_factory=list)
    raw_refs: list[SourceRef] = Field(default_factory=list)
    field_paths: list[str] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low", "inconclusive"] = "high"
    notes: list[str] = Field(default_factory=list)


class MaskedUEIdentity(BaseModel):
    display: str
    kinds: dict[str, str] = Field(default_factory=dict)


class GetUERequestRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt: ProcedureAttempt
    attempts_revision: str
    primary_reader: JsonlPrimaryEventReader
    identity_graph: IdentityGraphReader
    masking_policy: dict[str, Any] = Field(default_factory=dict)
    run_dir: Path
    requests_dir: Path
    max_issue_samples_per_code: int = 20
    fsync_outputs: bool = True


class UERequestResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt_id: UUID
    revision: str
    status: Literal["decoded", "partial", "unknown"]
    procedure: str
    procedure_subtype: str | None = None
    initiator: Literal["UE", "NETWORK", "UNKNOWN"]
    fields: dict[str, RequestedField]
    ue: MaskedUEIdentity | None = None
    trigger_event_ids: list[UUID] = Field(default_factory=list)
    trigger_frames: list[int] = Field(default_factory=list)
    missing_fields: list[MissingField] = Field(default_factory=list)
    conflicts: list[RequestFieldConflict] = Field(default_factory=list)
    stage_timings: list[Any] = Field(default_factory=list)
    artifact: ArtifactDescriptor
    manifest: ArtifactDescriptor
    issues: list[Issue] = Field(default_factory=list)
    manifest_path: Path


class ScoreTerm(BaseModel):
    kind: Literal["base", "bonus", "penalty"]
    rationale_code: str
    value: Decimal


class FailureCandidate(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    candidate_id: UUID
    attempt_id: UUID
    source_event_ids: list[UUID] = Field(default_factory=list)
    protocol: str
    category: str
    severity: Literal["info", "warning", "error", "critical"]
    frame: int
    related_frames: list[int] = Field(default_factory=list)
    component: str | None = None
    summary: str
    observed: dict[str, Any]
    expected: dict[str, Any] | None = None
    explicit: bool
    downstream: bool = False
    cleanup: bool = False
    evidence_ids: list[UUID] = Field(default_factory=list)
    detector: str
    detector_score: Decimal
    score_terms: list[ScoreTerm] = Field(default_factory=list)
    capture_phase: str = "unknown"
    relevance: Literal[
        "attempt_related",
        "dependency_related",
        "startup_background",
        "concurrent_background",
        "post_call_background",
        "unresolved_infrastructure",
    ] = "attempt_related"
    call_impact: Literal["causal", "contributing", "unrelated", "inconclusive"] = "inconclusive"


class HTTPRetryGroup(BaseModel):
    retry_group_id: UUID
    method: str | None = None
    path: str | None = None
    event_ids: list[UUID] = Field(default_factory=list)
    frames: list[int] = Field(default_factory=list)


class DependencySuspicion(BaseModel):
    suspicion_id: UUID
    reason_code: str
    event_ids: list[UUID] = Field(default_factory=list)


class FindHTTPFailuresRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt: ProcedureAttempt
    attempts_revision: str
    primary_reader: JsonlPrimaryEventReader
    run_dir: Path
    diagnostics_dir: Path
    max_issue_samples_per_code: int = 20
    fsync_outputs: bool = True


class FindHTTPFailuresResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt_id: UUID
    status: Literal["success", "partial", "failed"]
    revision: str
    manifest: ArtifactDescriptor
    artifacts: list[ArtifactDescriptor]
    candidates: list[FailureCandidate]
    retry_groups: list[HTTPRetryGroup]
    dependency_suspicions: list[DependencySuspicion]
    inspected_event_count: int
    warning_counts: dict[str, int]
    elapsed_ms: int
    issues: list[Issue] = Field(default_factory=list)
    manifest_path: Path


class TerminalEffect(BaseModel):
    effect_id: UUID
    attempt_id: UUID
    event_id: UUID
    frame: int
    summary: str
    downstream_possible: bool = False
    evidence_ids: list[UUID] = Field(default_factory=list)


class RequestOnlyObservation(BaseModel):
    observation_id: UUID
    attempt_id: UUID
    event_id: UUID
    expected_stage_ids: list[str]
    frame: int
    reason_codes: list[str] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(default_factory=list)


class FindNASNGAPFailuresRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt: ProcedureAttempt
    attempts_revision: str
    primary_reader: JsonlPrimaryEventReader
    profile: ResolvedProcedureProfile
    run_dir: Path
    diagnostics_dir: Path
    max_issue_samples_per_code: int = 20
    fsync_outputs: bool = True


class FindNASNGAPFailuresResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt_id: UUID
    status: Literal["success", "partial", "failed"]
    revision: str
    manifest: ArtifactDescriptor
    artifacts: list[ArtifactDescriptor]
    candidates: list[FailureCandidate]
    terminal_effects: list[TerminalEffect]
    request_only_observations: list[RequestOnlyObservation]
    inspected_event_count: int
    warning_counts: dict[str, int]
    elapsed_ms: int
    issues: list[Issue] = Field(default_factory=list)
    manifest_path: Path


class PFCPAssociationObservation(BaseModel):
    observation_id: UUID
    node_pair_key: str
    event_id: UUID
    frame: int
    state: str


class PFCPAssociationAttemptLink(BaseModel):
    link_id: UUID
    attempt_id: UUID
    observation_id: UUID
    reason_codes: list[str] = Field(default_factory=list)


class PFCPSessionReportObservation(BaseModel):
    observation_id: UUID
    event_id: UUID
    frame: int
    summary: str


class PFCPConsistencyResult(BaseModel):
    check_id: UUID
    event_id: UUID
    frame: int
    outcome: Literal["pass", "warning", "failure", "inconclusive"]
    summary: str


class PFCPTransactionGroup(BaseModel):
    transaction_id: UUID
    key: str
    event_ids: list[UUID] = Field(default_factory=list)
    frames: list[int] = Field(default_factory=list)
    outcome: Literal["success", "failure", "unknown"]


class BuildPFCPNodeStateCatalogRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    normalization: NormalizeEventsResult
    primary_reader: JsonlPrimaryEventReader
    run_dir: Path
    diagnostics_dir: Path
    fsync_outputs: bool = True


class BuildPFCPNodeStateCatalogResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    revision: str
    manifest: ArtifactDescriptor
    observations: ArtifactDescriptor
    node_pair_index: ArtifactDescriptor
    manifest_path: Path


class PFCPNodeStateCatalogReader(Protocol):
    @property
    def revision(self) -> str: ...

    def for_node_pair(self, node_pair_key: str, start: int, end: int) -> list[PFCPAssociationObservation]: ...


class _PFCPNodeStateCatalogReader:
    def __init__(self, revision: str, observations: list[PFCPAssociationObservation]) -> None:
        self.revision = revision
        self._observations = observations
        self._by_pair: DefaultDict[str, list[PFCPAssociationObservation]] = defaultdict(list)
        for observation in observations:
            self._by_pair[observation.node_pair_key].append(observation)

    def for_node_pair(self, node_pair_key: str, start: int, end: int) -> list[PFCPAssociationObservation]:
        return [
            record
            for record in self._by_pair.get(node_pair_key, [])
            if start <= record.frame <= end
        ]


class FindPFCPFailuresRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt: ProcedureAttempt
    attempts_revision: str
    primary_reader: JsonlPrimaryEventReader
    identity_graph: IdentityGraphReader
    node_state_catalog: PFCPNodeStateCatalogReader | None = None
    run_dir: Path
    diagnostics_dir: Path
    max_issue_samples_per_code: int = 20
    fsync_outputs: bool = True


class FindPFCPFailuresResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt_id: UUID
    status: Literal["success", "partial", "failed"]
    revision: str
    manifest: ArtifactDescriptor
    artifacts: list[ArtifactDescriptor]
    candidates: list[FailureCandidate]
    transactions: list[PFCPTransactionGroup]
    association_observations: list[PFCPAssociationObservation]
    association_links: list[PFCPAssociationAttemptLink]
    session_reports: list[PFCPSessionReportObservation]
    consistency_checks: list[PFCPConsistencyResult]
    inspected_event_count: int
    warning_counts: dict[str, int]
    elapsed_ms: int
    issues: list[Issue] = Field(default_factory=list)
    manifest_path: Path


class StageVisibilityResult(BaseModel):
    domain: Literal["reference_point", "sbi_service", "sbi_api"]
    key: str
    state: Literal["visible", "partial", "not_observed", "unknown"]
    minimum_state: Literal["visible", "partial"]
    satisfied: bool


class StageResult(BaseModel):
    stage_result_id: UUID
    attempt_id: UUID
    stage_id: str
    stage_name: str
    order: int
    state: Literal["completed", "missing", "skipped", "suppressed"]
    anchor_event_id: UUID | None = None
    anchor_frame: int
    observed_event_ids: list[UUID] = Field(default_factory=list)
    visibility: list[StageVisibilityResult] = Field(default_factory=list)
    deadline_seconds: Decimal | None = None
    reason_codes: list[str] = Field(default_factory=list)


class MissingStageSuppression(BaseModel):
    suppression_id: UUID
    stage_id: str
    explicit_candidate_ids: list[UUID] = Field(default_factory=list)
    request_observation_ids: list[UUID] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    decision: Literal["linked_downstream", "duplicate_suppressed", "not_suppressed"]


class DetectMissingTransitionsRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt: ProcedureAttempt
    attempts_revision: str
    profile: ResolvedProcedureProfile
    http_result: FindHTTPFailuresResult
    nas_ngap_result: FindNASNGAPFailuresResult
    pfcp_result: FindPFCPFailuresResult
    run_dir: Path
    diagnostics_dir: Path
    max_issue_samples_per_code: int = 20
    fsync_outputs: bool = True


class DetectMissingTransitionsResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt_id: UUID
    status: Literal["success", "partial", "failed"]
    revision: str
    manifest: ArtifactDescriptor
    artifacts: list[ArtifactDescriptor]
    stage_results: list[StageResult]
    candidates: list[FailureCandidate]
    linked_suppressions: list[MissingStageSuppression]
    stage_timings: list[Any] = Field(default_factory=list)
    first_missing_stage_id: str | None = None
    last_completed_stage_id: str | None = None
    warning_counts: dict[str, int]
    elapsed_ms: int
    issues: list[Issue] = Field(default_factory=list)
    manifest_path: Path


TimelineMode = Literal["internal", "report", "model", "dependency_expanded"]
TimelineLabel = Literal[
    "expected",
    "anomalous",
    "failure",
    "retry",
    "cleanup",
    "terminal",
    "missing_transition",
    "dependency_evidence",
]


class TimelineItem(BaseModel):
    item_id: UUID
    attempt_id: UUID
    child_attempt_id: UUID | None = None
    event_id: UUID | None = None
    candidate_id: UUID | None = None
    checkpoint_id: UUID | None = None
    source_kind: Literal[
        "event",
        "transition",
        "retry",
        "candidate",
        "terminal_effect",
        "stage_result",
        "dependency_result",
        "request",
    ]
    synthetic: bool = False
    frame: int
    timestamp: Decimal | None = None
    deadline_timestamp: Decimal | None = None
    sort_ordinal: int
    protocol: str
    direction: str
    stage_id: str | None = None
    message: str
    label: TimelineLabel
    outcome: str | None = None
    identifiers: dict[str, str] = Field(default_factory=dict)
    evidence_ids: list[UUID] = Field(default_factory=list)
    full_record_available: bool = False
    summary_attributes: dict[str, Any] = Field(default_factory=dict)


class GetAttemptTimelineRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt: ProcedureAttempt
    request_result: UERequestResult
    primary_reader: JsonlPrimaryEventReader
    http_result: FindHTTPFailuresResult
    nas_ngap_result: FindNASNGAPFailuresResult
    pfcp_result: FindPFCPFailuresResult
    missing_result: DetectMissingTransitionsResult
    run_dir: Path
    diagnostics_dir: Path
    mode: TimelineMode = "internal"
    limit: int | None = None
    cursor: str | None = None
    max_issue_samples_per_code: int = 20
    fsync_outputs: bool = True


class AttemptTimelineResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    attempt_id: UUID
    mode: TimelineMode
    items: list[TimelineItem]
    total_matching: int
    returned: int
    truncated: bool
    next_cursor: str | None = None
    revision: str
    issues: list[Issue] = Field(default_factory=list)
    manifest: ArtifactDescriptor
    artifact: ArtifactDescriptor
    manifest_path: Path


def get_ue_request(request: GetUERequestRequest) -> UERequestResult:
    started = datetime.now(tz=timezone.utc)
    validate_inside_run(request.run_dir, request.requests_dir)
    events = _events_for_attempt(request.primary_reader, request.attempt)
    issues: list[Issue] = []
    fields: dict[str, RequestedField] = {}
    conflicts: list[RequestFieldConflict] = []

    _collect_field(fields, conflicts, "registration_type", _registration_type(request.attempt, events))
    _collect_field(fields, conflicts, "access_type", request.attempt.access_family, events=events[:1], path="attempt.access_family")
    _collect_field(fields, conflicts, "pdu_session_id", request.attempt.correlation_identifiers.pdu_session_id, events=events, path="identifiers.pdu_session_id")
    _collect_field(fields, conflicts, "procedure_transaction_id", request.attempt.correlation_identifiers.procedure_transaction_id, events=events, path="identifiers.procedure_transaction_id")
    _collect_field(fields, conflicts, "request_type", request.attempt.procedure_type, events=events[:1], path="attempt.procedure_type")
    _collect_field(fields, conflicts, "service_request_type", _service_request_type(request.attempt, events))
    _collect_field(fields, conflicts, "dnn", _first_attr(events, "request.dnn"))
    _collect_field(fields, conflicts, "s_nssai", _first_attr(events, "request.s_nssai"))
    _collect_field(fields, conflicts, "pdu_session_type", _first_attr(events, "request.pdu_session_type"))
    _collect_field(fields, conflicts, "ssc_mode", _first_attr(events, "request.ssc_mode"))
    _collect_field(fields, conflicts, "release_origin", _release_origin(request.attempt))

    missing = [
        MissingField(name=name, reason_codes=["field_missing"])
        for name in ("registration_type", "access_type")
        if fields.get(name) is None or fields[name].value is None
    ]
    if missing:
        issues.append(Issue(code="T05_FIELD_MISSING", stage="T05", message="one or more request fields were missing"))

    if conflicts:
        issues.append(Issue(code="T05_FIELD_CONFLICT", stage="T05", message="one or more request fields had conflicting values"))

    revision = "sha256:" + sha256_bytes(
        compact_json_bytes(
            {
                "tool": "T05",
                "version": REQUEST_VERSION,
                "analysis_id": str(request.analysis_id),
                "attempt_id": str(request.attempt.attempt_id),
                "attempts_revision": request.attempts_revision,
                "event_ids": [str(event.event_id) for event in events],
                "fields": {name: field.model_dump(mode="json") for name, field in sorted(fields.items())},
            }
        )
    )
    ue = _masked_ue_identity(request, events)
    status: Literal["decoded", "partial", "unknown"] = "decoded"
    if missing or conflicts:
        status = "partial"
    if not fields:
        status = "unknown"

    request_dir = request.requests_dir / str(request.attempt.attempt_id)
    artifact_relative = f"normalized/requests/{request.attempt.attempt_id}/request.json"
    manifest_relative = f"normalized/requests/{request.attempt.attempt_id}/request_manifest.json"
    staging_root = request.run_dir / "staging" / f"T05-{request.attempt.attempt_id}"
    if staging_root.exists():
        for existing in sorted(staging_root.rglob("*"), reverse=True):
            if existing.is_file():
                existing.unlink()
            elif existing.is_dir():
                existing.rmdir()
    staging_root.mkdir(parents=True, exist_ok=True)

    payload = {
        "schema_version": SCHEMA_VERSION,
        "analysis_id": str(request.analysis_id),
        "attempt_id": str(request.attempt.attempt_id),
        "revision": revision,
        "status": status,
        "procedure": request.attempt.procedure_type,
        "procedure_subtype": request.attempt.subtype,
        "initiator": request.attempt.initiator,
        "fields": {name: field.model_dump(mode="json", exclude_none=True) for name, field in sorted(fields.items())},
        "ue": None if ue is None else ue.model_dump(mode="json"),
        "trigger_event_ids": [str(item) for item in request.attempt.trigger_event_ids],
        "trigger_frames": [event.frame for event in events if event.event_id in request.attempt.trigger_event_ids],
        "missing_fields": [item.model_dump(mode="json") for item in missing],
        "conflicts": [item.model_dump(mode="json") for item in conflicts],
        "stage_timings": [item.model_dump(mode="json") for item in request.attempt.stage_timings],
        "issues": [item.model_dump(mode="json") for item in sample_issues(issues, request.max_issue_samples_per_code)],
    }
    artifact_closed = JsonArtifactWriter(staging_root, request.run_dir, artifact_relative, "ue_request").write(payload)
    manifest_payload = {
        "schema_version": SCHEMA_VERSION,
        "tool": "T05",
        "analysis_id": str(request.analysis_id),
        "attempt_id": str(request.attempt.attempt_id),
        "revision": revision,
        "attempts_revision": request.attempts_revision,
        "artifact": artifact_closed.descriptor(creation_stage="T05", parent_source_sha256=request.attempts_revision),
        "issues": payload["issues"],
    }
    manifest_closed = JsonArtifactWriter(staging_root, request.run_dir, manifest_relative, "ue_request_manifest").write(manifest_payload)
    publish_closed_artifacts(request.run_dir, [artifact_closed, manifest_closed], manifest_relative_path=manifest_relative)
    artifact_path = request.run_dir / artifact_relative
    manifest_path = request.run_dir / manifest_relative
    artifact_descriptor = ArtifactDescriptor(
        artifact_id=str(deterministic_uuid(request.analysis_id, "T05", revision, "artifact")),
        relative_path=artifact_relative,
        artifact_type="ue_request",
        media_type="application/json",
        format_schema_version=SCHEMA_VERSION,
        sha256=sha256_file(artifact_path),
        byte_size=artifact_path.stat().st_size,
        record_count=1,
        creation_stage="T05",
        parent_source_sha256=request.attempts_revision,
        revision=revision,
    )
    manifest_descriptor = ArtifactDescriptor(
        artifact_id=str(deterministic_uuid(request.analysis_id, "T05", revision, "manifest")),
        relative_path=manifest_relative,
        artifact_type="ue_request_manifest",
        media_type="application/json",
        format_schema_version=SCHEMA_VERSION,
        sha256=sha256_file(manifest_path),
        byte_size=manifest_path.stat().st_size,
        record_count=1,
        creation_stage="T05",
        parent_source_sha256=request.attempts_revision,
        revision=revision,
    )
    del started
    return UERequestResult(
        analysis_id=request.analysis_id,
        attempt_id=request.attempt.attempt_id,
        revision=revision,
        status=status,
        procedure=request.attempt.procedure_type,
        procedure_subtype=request.attempt.subtype,
        initiator=request.attempt.initiator,
        fields=fields,
        ue=ue,
        trigger_event_ids=list(request.attempt.trigger_event_ids),
        trigger_frames=payload["trigger_frames"],
        missing_fields=missing,
        conflicts=conflicts,
        stage_timings=list(request.attempt.stage_timings),
        artifact=artifact_descriptor,
        manifest=manifest_descriptor,
        issues=sample_issues(issues, request.max_issue_samples_per_code),
        manifest_path=manifest_path,
    )


def build_pfcp_node_state_catalog(request: BuildPFCPNodeStateCatalogRequest) -> BuildPFCPNodeStateCatalogResult:
    validate_inside_run(request.run_dir, request.diagnostics_dir)
    staging_root = request.run_dir / "staging" / f"T08-pfcp-catalog-{request.analysis_id}"
    if staging_root.exists():
        for existing in sorted(staging_root.rglob("*"), reverse=True):
            if existing.is_file():
                existing.unlink()
            elif existing.is_dir():
                existing.rmdir()
    staging_root.mkdir(parents=True, exist_ok=True)
    observations_writer = JsonlArtifactWriter(
        staging_root,
        request.run_dir,
        "normalized/diagnostics/pfcp_node_state/observations.jsonl",
        "pfcp_node_state_observations",
    )
    index: DefaultDict[str, list[str]] = defaultdict(list)
    observations: list[PFCPAssociationObservation] = []
    for event in request.primary_reader.by_protocol("PFCP"):
        key = _pfcp_node_pair_key(event)
        if key is None:
            continue
        state = "heartbeat" if bool(event.attributes.get("pfcp.routine")) else "session_signaling"
        observation = PFCPAssociationObservation(
            observation_id=deterministic_uuid(request.analysis_id, "T08", "pfcp_catalog", event.event_id),
            node_pair_key=key,
            event_id=event.event_id,
            frame=event.frame,
            state=state,
        )
        observations.append(observation)
        observations_writer.write(observation)
        index[key].append(str(observation.observation_id))
    observations_closed = observations_writer.close()
    index_closed = JsonArtifactWriter(
        staging_root,
        request.run_dir,
        "normalized/diagnostics/pfcp_node_state/node_pair_index.json",
        "pfcp_node_state_index",
    ).write(dict(sorted(index.items())))
    revision = "sha256:" + sha256_bytes(
        compact_json_bytes(
            {
                "tool": "T08_PFCP_NODE_STATE",
                "analysis_id": str(request.analysis_id),
                "normalization_revision": request.normalization.revision,
                "observations": [str(item.observation_id) for item in observations],
            }
        )
    )
    manifest_payload = {
        "schema_version": SCHEMA_VERSION,
        "tool": "T08_PFCP_NODE_STATE",
        "analysis_id": str(request.analysis_id),
        "revision": revision,
        "normalization_revision": request.normalization.revision,
    }
    manifest_closed = JsonArtifactWriter(
        staging_root,
        request.run_dir,
        "normalized/diagnostics/pfcp_node_state/catalog_manifest.json",
        "pfcp_node_state_manifest",
    ).write(manifest_payload)
    publish_closed_artifacts(
        request.run_dir,
        [observations_closed, index_closed, manifest_closed],
        manifest_relative_path="normalized/diagnostics/pfcp_node_state/catalog_manifest.json",
    )
    manifest_path = request.run_dir / "normalized/diagnostics/pfcp_node_state/catalog_manifest.json"
    observations_path = request.run_dir / "normalized/diagnostics/pfcp_node_state/observations.jsonl"
    index_path = request.run_dir / "normalized/diagnostics/pfcp_node_state/node_pair_index.json"
    return BuildPFCPNodeStateCatalogResult(
        analysis_id=request.analysis_id,
        revision=revision,
        manifest=ArtifactDescriptor(
            artifact_id=str(deterministic_uuid(request.analysis_id, "T08_PFCP_NODE_STATE", revision, "manifest")),
            relative_path="normalized/diagnostics/pfcp_node_state/catalog_manifest.json",
            artifact_type="pfcp_node_state_manifest",
            media_type="application/json",
            format_schema_version=SCHEMA_VERSION,
            sha256=sha256_file(manifest_path),
            byte_size=manifest_path.stat().st_size,
            record_count=1,
            creation_stage="T08",
            parent_source_sha256=request.normalization.manifest.sha256,
            revision=revision,
        ),
        observations=ArtifactDescriptor(
            artifact_id=str(deterministic_uuid(request.analysis_id, "T08_PFCP_NODE_STATE", revision, "observations")),
            relative_path="normalized/diagnostics/pfcp_node_state/observations.jsonl",
            artifact_type="pfcp_node_state_observations",
            media_type="application/x-ndjson",
            format_schema_version=SCHEMA_VERSION,
            sha256=sha256_file(observations_path),
            byte_size=observations_path.stat().st_size,
            record_count=len(observations),
            creation_stage="T08",
            parent_source_sha256=request.normalization.manifest.sha256,
            revision=revision,
        ),
        node_pair_index=ArtifactDescriptor(
            artifact_id=str(deterministic_uuid(request.analysis_id, "T08_PFCP_NODE_STATE", revision, "index")),
            relative_path="normalized/diagnostics/pfcp_node_state/node_pair_index.json",
            artifact_type="pfcp_node_state_index",
            media_type="application/json",
            format_schema_version=SCHEMA_VERSION,
            sha256=sha256_file(index_path),
            byte_size=index_path.stat().st_size,
            record_count=1,
            creation_stage="T08",
            parent_source_sha256=request.normalization.manifest.sha256,
            revision=revision,
        ),
        manifest_path=manifest_path,
    )


def open_pfcp_node_state_catalog_reader(result: BuildPFCPNodeStateCatalogResult, run_dir: Path) -> PFCPNodeStateCatalogReader:
    observations = [
        PFCPAssociationObservation.model_validate(record)
        for record in iter_jsonl(run_dir / "normalized/diagnostics/pfcp_node_state/observations.jsonl")
    ]
    return _PFCPNodeStateCatalogReader(result.revision, observations)


def find_http_failures(request: FindHTTPFailuresRequest) -> FindHTTPFailuresResult:
    started = datetime.now(tz=timezone.utc)
    validate_inside_run(request.run_dir, request.diagnostics_dir)
    events = [event for event in _events_for_attempt(request.primary_reader, request.attempt) if event.protocol == "HTTP2"]
    candidates: list[FailureCandidate] = []
    retry_groups: list[HTTPRetryGroup] = []
    suspicions: list[DependencySuspicion] = []
    issues: list[Issue] = []
    warnings: DefaultDict[str, int] = defaultdict(int)

    transaction_groups = _http_transaction_groups(events)
    failed_or_incomplete_groups: list[tuple[str, list[CanonicalEvent], str]] = []
    for transaction_key, grouped in transaction_groups:
        representative = _http_representative_event(grouped)
        status = _http_status(grouped)
        completion_state = _http_completion_state(grouped)
        problem_details = _http_problem_details(grouped)
        method = _first_http_attr(grouped, "http.method")
        path = _first_http_attr(grouped, "http.path") or _first_http_attr(grouped, "http.uri")
        if isinstance(status, int) and status >= 400:
            candidates.append(
                _candidate_from_event(
                    request.analysis_id,
                    request.attempt.attempt_id,
                    detector="T06",
                    category="http_status_failure",
                    severity="critical" if status >= 500 else "error",
                    event=representative,
                    summary=f"HTTP failure status {status}",
                    observed={
                        "status": status,
                        "method": method,
                        "path": path,
                        "transaction_key": transaction_key,
                        "problem_details": problem_details,
                    },
                    related_events=grouped,
                    score_terms=[
                        ScoreTerm(kind="base", rationale_code="http_error_status", value=Decimal("0.80")),
                        ScoreTerm(kind="bonus", rationale_code="server_error" if status >= 500 else "client_error", value=Decimal("0.10")),
                    ],
                    explicit=True,
                )
            )
            failed_or_incomplete_groups.append((transaction_key, grouped, "http_status_failure"))
        elif completion_state != "complete":
            category = _http_incomplete_category(completion_state, request.attempt.completion_reason)
            rationale = {
                "http_timeout": "http_timeout",
                "http_reset": "http_reset",
                "http_incomplete_capture": "http_incomplete_capture",
            }[category]
            candidates.append(
                _candidate_from_event(
                    request.analysis_id,
                    request.attempt.attempt_id,
                    detector="T06",
                    category=category,
                    severity="error" if category == "http_timeout" else "warning",
                    event=representative,
                    summary=f"HTTP transaction was not complete ({completion_state})",
                    observed={
                        "completion_state": completion_state,
                        "method": method,
                        "path": path,
                        "transaction_key": transaction_key,
                    },
                    related_events=grouped,
                    score_terms=[ScoreTerm(kind="base", rationale_code=rationale, value=Decimal("0.70"))],
                    explicit=False,
                )
            )
            failed_or_incomplete_groups.append((transaction_key, grouped, category))

    retry_buckets: DefaultDict[tuple[str, str], list[tuple[str, list[CanonicalEvent]]]] = defaultdict(list)
    for transaction_key, grouped in transaction_groups:
        method = str(_first_http_attr(grouped, "http.method") or "")
        path = str(_first_http_attr(grouped, "http.path") or _first_http_attr(grouped, "http.uri") or "")
        retry_buckets[(method, path)].append((transaction_key, grouped))
    for (method, path), grouped_transactions in sorted(retry_buckets.items()):
        distinct = sorted(grouped_transactions, key=lambda item: (_http_representative_event(item[1]).frame, item[0]))
        if len(distinct) < 2 or not any(_http_group_failed_or_incomplete(item[1]) for item in distinct[:-1]):
            continue
        grouped_events = [event for _, group in distinct for event in group]
        retry_groups.append(
            HTTPRetryGroup(
                retry_group_id=deterministic_uuid(request.analysis_id, "T06", "retry_group", method, path),
                method=method or None,
                path=path or None,
                event_ids=[item.event_id for item in sorted(grouped_events, key=lambda event: (event.frame, str(event.event_id)))],
                frames=[item.frame for item in sorted(grouped_events, key=lambda event: (event.frame, str(event.event_id)))],
            )
        )

    for transaction_key, grouped, reason in failed_or_incomplete_groups:
        dependency_reason = _dependency_suspicion_reason(grouped)
        if dependency_reason is None:
            continue
        suspicions.append(
            DependencySuspicion(
                suspicion_id=deterministic_uuid(request.analysis_id, "T06", "dependency_suspicion", transaction_key, dependency_reason),
                reason_code=f"{dependency_reason}_{reason}",
                event_ids=[event.event_id for event in grouped],
            )
        )

    return _publish_http_result(request, started, candidates, retry_groups, suspicions, dict(sorted(warnings.items())), sample_issues(issues, request.max_issue_samples_per_code))


def find_nas_ngap_failures(request: FindNASNGAPFailuresRequest) -> FindNASNGAPFailuresResult:
    started = datetime.now(tz=timezone.utc)
    validate_inside_run(request.run_dir, request.diagnostics_dir)
    events = [event for event in _events_for_attempt(request.primary_reader, request.attempt) if event.protocol in {"NAS", "NGAP"}]
    candidates: list[FailureCandidate] = []
    terminal_effects: list[TerminalEffect] = []
    request_only: list[RequestOnlyObservation] = []

    terminal_seen = any(
        "ACCEPT" in event.message_type or "COMPLETE" in event.message_type or "REJECT" in event.message_type
        for event in events
    )
    for event in events:
        message = event.message_type.upper()
        cause = event.attributes.get("nas.cause") or event.attributes.get("ngap.cause")
        cause_class = _nas_ngap_cause_class(event, cause)
        if cause_class == "failure":
            category = "reachability_failure" if _is_reachability_failure(event, cause) else "nas_ngap_failure"
            candidates.append(
                _candidate_from_event(
                    request.analysis_id,
                    request.attempt.attempt_id,
                    detector="T07",
                    category=category,
                    severity="error",
                    event=event,
                    summary=f"NAS/NGAP failure observed in {event.message_type}",
                    observed={
                        "cause": cause,
                        "message_type": event.message_type,
                        "profile_release": request.profile.release,
                        "profile_id": request.profile.profile_id,
                        "codepoint_registry": event.attributes.get("t02.protocol_registry_version"),
                    },
                    score_terms=[ScoreTerm(kind="base", rationale_code=category, value=Decimal("0.80"))],
                    explicit=True,
                )
            )
        if ("REQUEST" in message or "INITIAL_UE_MESSAGE" in message) and not terminal_seen:
            request_only.append(
                RequestOnlyObservation(
                    observation_id=deterministic_uuid(request.analysis_id, "T07", "request_only", event.event_id),
                    attempt_id=request.attempt.attempt_id,
                    event_id=event.event_id,
                    expected_stage_ids=[
                        stage.stage_id
                        for stage in request.profile.stages
                        if stage.terminal_success or stage.terminal_failure
                    ],
                    frame=event.frame,
                    reason_codes=["initiating_message_without_terminal"],
                    evidence_ids=[deterministic_uuid(request.analysis_id, "T07", "request_only_evidence", event.event_id)],
                )
            )
        if (
            "RELEASE" in message
            or "DEREGISTRATION" in message
            or (cause_class in {"failure", "success"} and _is_terminal_profile_event(request.profile, event))
        ):
            terminal_effects.append(
                TerminalEffect(
                    effect_id=deterministic_uuid(request.analysis_id, "T07", "terminal_effect", event.event_id),
                    attempt_id=request.attempt.attempt_id,
                    event_id=event.event_id,
                    frame=event.frame,
                    summary=event.message_type,
                    downstream_possible=bool(candidates),
                    evidence_ids=[deterministic_uuid(request.analysis_id, "T07", "terminal_effect_evidence", event.event_id)],
                )
            )

    return _publish_nas_ngap_result(request, started, candidates, terminal_effects, request_only)


def find_pfcp_failures(request: FindPFCPFailuresRequest) -> FindPFCPFailuresResult:
    started = datetime.now(tz=timezone.utc)
    validate_inside_run(request.run_dir, request.diagnostics_dir)
    events = [event for event in _events_for_attempt(request.primary_reader, request.attempt) if event.protocol == "PFCP"]
    candidates: list[FailureCandidate] = []
    transactions: list[PFCPTransactionGroup] = []
    association_observations: list[PFCPAssociationObservation] = []
    association_links: list[PFCPAssociationAttemptLink] = []
    session_reports: list[PFCPSessionReportObservation] = []
    consistency_checks: list[PFCPConsistencyResult] = []

    by_key: DefaultDict[str, list[CanonicalEvent]] = defaultdict(list)
    for event in events:
        key = _pfcp_transaction_key(event)
        by_key[key].append(event)
        node_pair_key = _pfcp_node_pair_key(event)
        if node_pair_key is not None:
            observation_id = deterministic_uuid(request.analysis_id, "T08", "association_observation", event.event_id)
            association_observations.append(
                PFCPAssociationObservation(
                    observation_id=observation_id,
                    node_pair_key=node_pair_key,
                    event_id=event.event_id,
                    frame=event.frame,
                    state="attempt_correlated",
                )
            )
            association_links.append(
                PFCPAssociationAttemptLink(
                    link_id=deterministic_uuid(request.analysis_id, "T08", "association_link", request.attempt.attempt_id, observation_id),
                    attempt_id=request.attempt.attempt_id,
                    observation_id=observation_id,
                    reason_codes=["shared_pfcp_endpoints"],
                )
            )
        session_report = _pfcp_session_report(event)
        if session_report is not None:
            session_reports.append(session_report)
        tunnel_check = _pfcp_tunnel_consistency(request.analysis_id, event)
        if tunnel_check is not None:
            consistency_checks.append(tunnel_check)
            if tunnel_check.outcome == "failure":
                candidates.append(
                    _candidate_from_event(
                        request.analysis_id,
                        request.attempt.attempt_id,
                        detector="T08",
                        category="pfcp_tunnel_direction_mismatch",
                        severity="error",
                        event=event,
                        summary=tunnel_check.summary,
                        observed={
                            "expected_tunnel_role": event.attributes.get("pfcp.expected_tunnel_role"),
                            "observed_tunnel_role": event.attributes.get("pfcp.f_teid_direction") or event.attributes.get("pfcp.tunnel_direction"),
                        },
                        score_terms=[ScoreTerm(kind="base", rationale_code="pfcp_tunnel_direction_mismatch", value=Decimal("0.76"))],
                        explicit=True,
                    )
                )
    for key, grouped in sorted(by_key.items()):
        grouped = sorted(grouped, key=lambda item: (item.frame, str(item.event_id)))
        outcome = _pfcp_transaction_outcome(grouped)
        transactions.append(
            PFCPTransactionGroup(
                transaction_id=deterministic_uuid(request.analysis_id, "T08", "transaction", key),
                key=key,
                event_ids=[item.event_id for item in grouped],
                frames=[item.frame for item in grouped],
                outcome=outcome,
            )
        )
        if outcome == "failure":
            event = _pfcp_failure_event(grouped)
            candidates.append(
                _candidate_from_event(
                    request.analysis_id,
                    request.attempt.attempt_id,
                    detector="T08",
                    category="pfcp_failure",
                    severity="error",
                    event=event,
                    summary=f"PFCP transaction failed for {key}",
                    observed={"transaction_key": key, "cause": event.attributes.get("pfcp.cause")},
                    score_terms=[ScoreTerm(kind="base", rationale_code="pfcp_failure", value=Decimal("0.78"))],
                    explicit=True,
                )
            )
        for report in [item for item in session_reports if item.event_id in {event.event_id for event in grouped}]:
            event = next(item for item in grouped if item.event_id == report.event_id)
            if _pfcp_cause_class(event.attributes.get("pfcp.cause")) == "failure" or _report_indicates_failure(event):
                candidates.append(
                    _candidate_from_event(
                        request.analysis_id,
                        request.attempt.attempt_id,
                        detector="T08",
                        category="pfcp_session_report_failure",
                        severity="error",
                        event=event,
                        summary=report.summary,
                        observed={"transaction_key": key, "report_type": event.attributes.get("pfcp.report_type"), "cause": event.attributes.get("pfcp.cause")},
                        score_terms=[ScoreTerm(kind="base", rationale_code="pfcp_session_report_failure", value=Decimal("0.74"))],
                        explicit=True,
                    )
                )
        if outcome == "unknown":
            event = grouped[-1]
            consistency_checks.append(
                PFCPConsistencyResult(
                    check_id=deterministic_uuid(request.analysis_id, "T08", "consistency", event.event_id),
                    event_id=event.event_id,
                    frame=event.frame,
                    outcome="inconclusive",
                    summary="PFCP request had no matching response in attempt scope",
                )
            )

    return _publish_pfcp_result(request, started, candidates, transactions, association_observations, association_links, session_reports, consistency_checks)


def detect_missing_transitions(request: DetectMissingTransitionsRequest) -> DetectMissingTransitionsResult:
    started = datetime.now(tz=timezone.utc)
    validate_inside_run(request.run_dir, request.diagnostics_dir)
    transitions_by_stage: DefaultDict[str, list[Any]] = defaultdict(list)
    for transition in request.attempt.transitions:
        transitions_by_stage[transition.stage_id].append(transition)
    first_frame = request.attempt.start_frame
    last_completed_stage_id: str | None = None
    first_missing_stage_id: str | None = None
    stage_results: list[StageResult] = []
    candidates: list[FailureCandidate] = []
    suppressions: list[MissingStageSuppression] = []
    explicit_candidates = request.http_result.candidates + request.nas_ngap_result.candidates + request.pfcp_result.candidates
    request_only = request.nas_ngap_result.request_only_observations
    stage_evaluation: dict[str, str] = {}
    candidate_by_stage_hint = {
        stage.stage_id: [
            candidate
            for candidate in explicit_candidates
            if _candidate_relates_to_stage(candidate, stage)
            and request.attempt.start_frame <= candidate.frame <= request.attempt.end_frame
        ]
        for stage in request.profile.stages
    }

    for stage in sorted(request.profile.stages, key=lambda item: (item.order, item.stage_id)):
        applicability = _stage_applicability_result(request.attempt, stage)
        visibility = _stage_visibility_results(request.attempt, stage)
        visibility_satisfied = all(result.satisfied for result in visibility)
        predecessor_states = [stage_evaluation.get(predecessor_id) for predecessor_id in stage.predecessor_ids]
        predecessor_blocked = any(state != "completed" for state in predecessor_states)
        matched_transitions = sorted(
            transitions_by_stage.get(stage.stage_id, []),
            key=lambda item: (item.frame, str(item.transition_id)),
        )
        if matched_transitions:
            matched_events = [transition.event_id for transition in matched_transitions]
            anchor_transition = matched_transitions[-1]
            reason_codes = ["observed_stage"]
            deadline = _stage_deadline_frame(request.attempt, stage, transitions_by_stage)
            if deadline is not None and anchor_transition.frame > deadline:
                reason_codes.append("deadline_missed")
            last_completed_stage_id = stage.stage_id
            stage_evaluation[stage.stage_id] = "completed"
            stage_results.append(
                StageResult(
                    stage_result_id=deterministic_uuid(request.analysis_id, "T09", "stage_result", request.attempt.attempt_id, stage.stage_id),
                    attempt_id=request.attempt.attempt_id,
                    stage_id=stage.stage_id,
                    stage_name=stage.name,
                    order=stage.order,
                    state="completed",
                    anchor_event_id=matched_events[-1],
                    anchor_frame=anchor_transition.frame,
                    observed_event_ids=matched_events,
                    visibility=visibility,
                    deadline_seconds=stage.timeout_seconds,
                    reason_codes=reason_codes,
                )
            )
            continue

        if applicability is False:
            stage_evaluation[stage.stage_id] = "skipped"
            stage_results.append(
                StageResult(
                    stage_result_id=deterministic_uuid(request.analysis_id, "T09", "stage_result", request.attempt.attempt_id, stage.stage_id),
                    attempt_id=request.attempt.attempt_id,
                    stage_id=stage.stage_id,
                    stage_name=stage.name,
                    order=stage.order,
                    state="skipped",
                    anchor_frame=request.attempt.end_frame,
                    visibility=visibility,
                    deadline_seconds=stage.timeout_seconds,
                    reason_codes=["applicability_condition_false"],
                )
            )
            continue
        if applicability is None:
            stage_evaluation[stage.stage_id] = "skipped"
            stage_results.append(
                StageResult(
                    stage_result_id=deterministic_uuid(request.analysis_id, "T09", "stage_result", request.attempt.attempt_id, stage.stage_id),
                    attempt_id=request.attempt.attempt_id,
                    stage_id=stage.stage_id,
                    stage_name=stage.name,
                    order=stage.order,
                    state="skipped",
                    anchor_frame=request.attempt.end_frame,
                    visibility=visibility,
                    deadline_seconds=stage.timeout_seconds,
                    reason_codes=["applicability_fact_unknown"],
                )
            )
            continue
        if predecessor_blocked:
            stage_evaluation[stage.stage_id] = "skipped"
            stage_results.append(
                StageResult(
                    stage_result_id=deterministic_uuid(request.analysis_id, "T09", "stage_result", request.attempt.attempt_id, stage.stage_id),
                    attempt_id=request.attempt.attempt_id,
                    stage_id=stage.stage_id,
                    stage_name=stage.name,
                    order=stage.order,
                    state="skipped",
                    anchor_frame=request.attempt.end_frame,
                    visibility=visibility,
                    deadline_seconds=stage.timeout_seconds,
                    reason_codes=["predecessor_not_reached"],
                )
            )
            continue

        mandatory = stage.applicability in {"mandatory", "conditional"}
        if not mandatory:
            stage_evaluation[stage.stage_id] = "skipped"
            stage_results.append(
                StageResult(
                    stage_result_id=deterministic_uuid(request.analysis_id, "T09", "stage_result", request.attempt.attempt_id, stage.stage_id),
                    attempt_id=request.attempt.attempt_id,
                    stage_id=stage.stage_id,
                    stage_name=stage.name,
                    order=stage.order,
                    state="skipped",
                    anchor_frame=request.attempt.end_frame,
                    visibility=visibility,
                    deadline_seconds=stage.timeout_seconds,
                    reason_codes=["optional_stage"],
                )
            )
            continue
        if visibility and not visibility_satisfied:
            stage_evaluation[stage.stage_id] = "skipped"
            stage_results.append(
                StageResult(
                    stage_result_id=deterministic_uuid(request.analysis_id, "T09", "stage_result", request.attempt.attempt_id, stage.stage_id),
                    attempt_id=request.attempt.attempt_id,
                    stage_id=stage.stage_id,
                    stage_name=stage.name,
                    order=stage.order,
                    state="skipped",
                    anchor_frame=request.attempt.end_frame,
                    visibility=visibility,
                    deadline_seconds=stage.timeout_seconds,
                    reason_codes=["visibility_not_satisfied"],
                )
            )
            continue
        if request.attempt.incomplete_history:
            stage_evaluation[stage.stage_id] = "skipped"
            stage_results.append(
                StageResult(
                    stage_result_id=deterministic_uuid(request.analysis_id, "T09", "stage_result", request.attempt.attempt_id, stage.stage_id),
                    attempt_id=request.attempt.attempt_id,
                    stage_id=stage.stage_id,
                    stage_name=stage.name,
                    order=stage.order,
                    state="skipped",
                    anchor_frame=request.attempt.end_frame,
                    visibility=visibility,
                    deadline_seconds=stage.timeout_seconds,
                    reason_codes=["capture_truncated_before_stage"],
                )
            )
            continue

        explicit_for_stage = candidate_by_stage_hint.get(stage.stage_id, [])
        request_obs = [obs for obs in request_only if stage.stage_id in obs.expected_stage_ids]
        decision = "not_suppressed"
        if explicit_for_stage:
            decision = "linked_downstream"
        elif request_obs and not stage.terminal_success:
            decision = "duplicate_suppressed"
        suppression = MissingStageSuppression(
            suppression_id=deterministic_uuid(request.analysis_id, "T09", "suppression", request.attempt.attempt_id, stage.stage_id),
            stage_id=stage.stage_id,
            explicit_candidate_ids=[candidate.candidate_id for candidate in explicit_for_stage],
            request_observation_ids=[obs.observation_id for obs in request_obs],
            reason_codes=["explicit_evidence_present"] if explicit_for_stage else ["request_only_observation"] if request_obs else [],
            decision=decision,
        )
        suppressions.append(suppression)
        if decision != "not_suppressed":
            stage_evaluation[stage.stage_id] = "suppressed"
            stage_results.append(
                StageResult(
                    stage_result_id=deterministic_uuid(request.analysis_id, "T09", "stage_result", request.attempt.attempt_id, stage.stage_id),
                    attempt_id=request.attempt.attempt_id,
                    stage_id=stage.stage_id,
                    stage_name=stage.name,
                    order=stage.order,
                    state="suppressed",
                    anchor_frame=request.attempt.end_frame,
                    visibility=visibility,
                    deadline_seconds=stage.timeout_seconds,
                    reason_codes=suppression.reason_codes,
                )
            )
            continue

        if first_missing_stage_id is None:
            first_missing_stage_id = stage.stage_id
        stage_evaluation[stage.stage_id] = "missing"
        stage_results.append(
            StageResult(
                stage_result_id=deterministic_uuid(request.analysis_id, "T09", "stage_result", request.attempt.attempt_id, stage.stage_id),
                attempt_id=request.attempt.attempt_id,
                stage_id=stage.stage_id,
                stage_name=stage.name,
                order=stage.order,
                state="missing",
                anchor_frame=request.attempt.end_frame,
                visibility=visibility,
                deadline_seconds=stage.timeout_seconds,
                reason_codes=["missing_required_stage"],
            )
        )
        candidates.append(
            FailureCandidate(
                candidate_id=deterministic_uuid(request.analysis_id, "T09", "missing", request.attempt.attempt_id, stage.stage_id),
                attempt_id=request.attempt.attempt_id,
                source_event_ids=[],
                protocol="MULTI",
                category="missing_transition",
                severity="warning",
                frame=request.attempt.end_frame,
                related_frames=[request.attempt.start_frame, request.attempt.end_frame],
                component=stage.stage_id,
                summary=f"Required stage {stage.name} was not observed",
                observed={"stage_id": stage.stage_id, "last_completed_stage_id": last_completed_stage_id},
                expected={"stage_name": stage.name},
                explicit=False,
                evidence_ids=[deterministic_uuid(request.analysis_id, "T09", "missing_evidence", request.attempt.attempt_id, stage.stage_id)],
                detector="T09",
                detector_score=Decimal("0.65"),
                score_terms=[
                    ScoreTerm(kind="base", rationale_code="missing_transition_base", value=Decimal("0.65")),
                    *(
                        [ScoreTerm(kind="penalty", rationale_code="deadline_not_declared", value=Decimal("-0.05"))]
                        if stage.timeout_seconds is None
                        else []
                    ),
                ],
                capture_phase="unknown",
                relevance="attempt_related",
                call_impact="inconclusive",
            )
        )

    return _publish_missing_result(
        request,
        started,
        stage_results,
        candidates,
        suppressions,
        first_missing_stage_id,
        last_completed_stage_id,
    )


def get_attempt_timeline(request: GetAttemptTimelineRequest) -> AttemptTimelineResult:
    validate_inside_run(request.run_dir, request.diagnostics_dir)
    mode_cap = {"internal": 50, "report": 100, "model": 20, "dependency_expanded": 50}[request.mode]
    limit = mode_cap if request.limit is None else min(request.limit, mode_cap)
    events = _events_for_attempt(request.primary_reader, request.attempt)
    items: list[TimelineItem] = []

    for event in events:
        items.append(
            TimelineItem(
                item_id=deterministic_uuid(request.analysis_id, "T10", "event", event.event_id),
                attempt_id=request.attempt.attempt_id,
                event_id=event.event_id,
                frame=event.frame,
                timestamp=event.timestamp,
                sort_ordinal=0,
                protocol=event.protocol,
                direction=event.direction,
                stage_id=None,
                message=event.message_type,
                label="terminal" if "ACCEPT" in event.message_type or "COMPLETE" in event.message_type else "expected",
                outcome=event.outcome,
                identifiers=_identifier_summary(event.identifiers),
                evidence_ids=[deterministic_uuid(request.analysis_id, "T10", "event_evidence", event.event_id)],
                full_record_available=True,
                summary_attributes={
                    "protocol": event.protocol,
                    "message_type": event.message_type,
                },
                source_kind="event",
            )
        )

    for name, field in sorted(request.request_result.fields.items()):
        if field.value is None:
            continue
        items.append(
            TimelineItem(
                item_id=deterministic_uuid(request.analysis_id, "T10", "request", request.attempt.attempt_id, name),
                attempt_id=request.attempt.attempt_id,
                frame=request.attempt.start_frame,
                timestamp=request.attempt.start_timestamp,
                sort_ordinal=0,
                protocol="REQUEST",
                direction=request.attempt.initiator,
                stage_id=None,
                message=f"{name}={field.value}",
                label="expected",
                evidence_ids=list(field.evidence_ids),
                full_record_available=True,
                summary_attributes={"field": name, "value": field.value},
                source_kind="request",
            )
        )

    for transition in request.attempt.transitions:
        items.append(
            TimelineItem(
                item_id=deterministic_uuid(request.analysis_id, "T10", "transition", transition.transition_id),
                attempt_id=request.attempt.attempt_id,
                event_id=transition.event_id,
                frame=transition.frame,
                timestamp=transition.timestamp,
                sort_ordinal=0,
                protocol="STATE",
                direction="UNKNOWN",
                stage_id=transition.stage_id,
                message=transition.stage_name,
                label="terminal" if transition.transition_type in {"failed", "aborted"} else "expected",
                outcome=transition.transition_type,
                evidence_ids=[deterministic_uuid(request.analysis_id, "T10", "transition_evidence", transition.transition_id)],
                full_record_available=False,
                summary_attributes={"transition_type": transition.transition_type},
                source_kind="transition",
            )
        )

    for retry in request.attempt.retries:
        items.append(
            TimelineItem(
                item_id=deterministic_uuid(request.analysis_id, "T10", "retry", retry.retry_id),
                attempt_id=request.attempt.attempt_id,
                frame=request.attempt.start_frame,
                timestamp=request.attempt.start_timestamp,
                sort_ordinal=0,
                protocol="ATTEMPT",
                direction="UNKNOWN",
                stage_id=None,
                message="retry_of_previous_attempt",
                label="retry",
                evidence_ids=[deterministic_uuid(request.analysis_id, "T10", "retry_evidence", retry.retry_id)],
                full_record_available=False,
                summary_attributes={"prior_attempt_id": str(retry.prior_attempt_id)},
                source_kind="retry",
            )
        )

    for result, label in (
        (request.http_result.candidates, "failure"),
        (request.nas_ngap_result.candidates, "failure"),
        (request.pfcp_result.candidates, "failure"),
        (request.missing_result.candidates, "missing_transition"),
    ):
        for candidate in result:
            items.append(
                TimelineItem(
                    item_id=deterministic_uuid(request.analysis_id, "T10", "candidate", candidate.candidate_id),
                    attempt_id=request.attempt.attempt_id,
                    candidate_id=candidate.candidate_id,
                    frame=candidate.frame,
                    timestamp=None,
                    sort_ordinal=0,
                    protocol=candidate.protocol,
                    direction="UNKNOWN",
                    stage_id=candidate.component,
                    message=candidate.summary,
                    label=label,  # type: ignore[arg-type]
                    outcome=candidate.category,
                    evidence_ids=list(candidate.evidence_ids),
                    full_record_available=False,
                    summary_attributes={"severity": candidate.severity, "score": format(candidate.detector_score, "f")},
                    source_kind="candidate",
                    synthetic=(candidate.category == "missing_transition"),
                )
            )

    total_matching = len(items)
    items.sort(key=lambda item: (item.frame, str(item.event_id or item.candidate_id or item.item_id)))
    for ordinal, item in enumerate(items):
        item.sort_ordinal = ordinal
    parent_revisions = {
        "t05": request.request_result.revision,
        "t06": request.http_result.revision,
        "t07": request.nas_ngap_result.revision,
        "t08": request.pfcp_result.revision,
        "t09": request.missing_result.revision,
    }
    revision_payload = {
        "tool": "T10",
        "version": TIMELINE_VERSION,
        "analysis_id": str(request.analysis_id),
        "attempt_id": str(request.attempt.attempt_id),
        "mode": request.mode,
        "all_items": [str(item.item_id) for item in items],
        "parents": parent_revisions,
    }
    query_payload = {**revision_payload, "limit": limit}
    revision = "sha256:" + sha256_bytes(compact_json_bytes(revision_payload))
    query_digest = sha256_bytes(compact_json_bytes(query_payload))
    offset = _decode_timeline_offset(
        request.cursor,
        analysis_id=request.analysis_id,
        revision=revision,
        query_digest=query_digest,
    )
    returned_items = items[offset: offset + limit]
    next_offset = offset + len(returned_items)
    truncated = next_offset < len(items)
    query_id = deterministic_uuid(request.analysis_id, "T10", request.attempt.attempt_id, request.mode, limit, revision)
    page_id = deterministic_uuid(request.analysis_id, "T10", query_id, offset)
    relative_dir = f"normalized/diagnostics/{request.attempt.attempt_id}/T10/{page_id}"
    artifact_relative = f"{relative_dir}/timeline.json"
    manifest_relative = f"{relative_dir}/timeline_manifest.json"
    staging_root = request.run_dir / "staging" / f"T10-{request.attempt.attempt_id}-{page_id}"
    if staging_root.exists():
        for existing in sorted(staging_root.rglob("*"), reverse=True):
            if existing.is_file():
                existing.unlink()
            elif existing.is_dir():
                existing.rmdir()
    staging_root.mkdir(parents=True, exist_ok=True)
    issues = []
    if truncated:
        issues.append(Issue(code="T10_TIMELINE_TRUNCATED", stage="T10", message="timeline result exceeded requested limit"))
    artifact_payload = {
        "schema_version": SCHEMA_VERSION,
        "attempt_id": str(request.attempt.attempt_id),
        "mode": request.mode,
        "revision": revision,
        "items": [item.model_dump(mode="json", exclude_none=True) for item in returned_items],
        "total_matching": total_matching,
        "returned": len(returned_items),
        "truncated": truncated,
        "next_cursor": _encode_timeline_cursor(request.analysis_id, revision, query_digest, next_offset) if truncated else None,
        "issues": [item.model_dump(mode="json") for item in issues],
    }
    artifact_closed = JsonArtifactWriter(staging_root, request.run_dir, artifact_relative, "attempt_timeline").write(artifact_payload)
    manifest_closed = JsonArtifactWriter(
        staging_root,
        request.run_dir,
        manifest_relative,
        "attempt_timeline_manifest",
    ).write(
        {
            "schema_version": SCHEMA_VERSION,
            "tool": "T10",
            "analysis_id": str(request.analysis_id),
            "attempt_id": str(request.attempt.attempt_id),
            "mode": request.mode,
            "revision": revision,
            "artifact": artifact_closed.descriptor(creation_stage="T10", parent_source_sha256=request.missing_result.revision),
            "issues": [item.model_dump(mode="json") for item in issues],
        }
    )
    publish_closed_artifacts(request.run_dir, [artifact_closed, manifest_closed], manifest_relative_path=manifest_relative)
    artifact_path = request.run_dir / artifact_relative
    manifest_path = request.run_dir / manifest_relative
    return AttemptTimelineResult(
        attempt_id=request.attempt.attempt_id,
        mode=request.mode,
        items=returned_items,
        total_matching=total_matching,
        returned=len(returned_items),
        truncated=truncated,
        next_cursor=artifact_payload["next_cursor"],
        revision=revision,
        issues=issues,
        manifest=ArtifactDescriptor(
            artifact_id=str(deterministic_uuid(request.analysis_id, "T10", revision, "manifest")),
            relative_path=manifest_relative,
            artifact_type="attempt_timeline_manifest",
            media_type="application/json",
            format_schema_version=SCHEMA_VERSION,
            sha256=sha256_file(manifest_path),
            byte_size=manifest_path.stat().st_size,
            record_count=1,
            creation_stage="T10",
            parent_source_sha256=request.missing_result.revision,
            revision=revision,
        ),
        artifact=ArtifactDescriptor(
            artifact_id=str(deterministic_uuid(request.analysis_id, "T10", revision, "artifact")),
            relative_path=artifact_relative,
            artifact_type="attempt_timeline",
            media_type="application/json",
            format_schema_version=SCHEMA_VERSION,
            sha256=sha256_file(artifact_path),
            byte_size=artifact_path.stat().st_size,
            record_count=1,
            creation_stage="T10",
            parent_source_sha256=request.missing_result.revision,
            revision=revision,
        ),
        manifest_path=manifest_path,
    )


def _publish_http_result(
    request: FindHTTPFailuresRequest,
    started: datetime,
    candidates: list[FailureCandidate],
    retry_groups: list[HTTPRetryGroup],
    suspicions: list[DependencySuspicion],
    warning_counts: dict[str, int],
    issues: list[Issue],
) -> FindHTTPFailuresResult:
    return _publish_detector_result(
        request.analysis_id,
        request.attempt.attempt_id,
        request.attempts_revision,
        request.run_dir,
        request.diagnostics_dir,
        "T06",
        started,
        {
            "candidates": [item.model_dump(mode="json") for item in candidates],
            "retry_groups": [item.model_dump(mode="json") for item in retry_groups],
            "dependency_suspicions": [item.model_dump(mode="json") for item in suspicions],
        },
        candidate_count=len(candidates),
        warning_counts=warning_counts,
        issues=issues,
        result_factory=lambda revision, manifest, artifacts, elapsed_ms, manifest_path: FindHTTPFailuresResult(
            analysis_id=request.analysis_id,
            attempt_id=request.attempt.attempt_id,
            status="partial" if candidates else "success",
            revision=revision,
            manifest=manifest,
            artifacts=artifacts,
            candidates=candidates,
            retry_groups=retry_groups,
            dependency_suspicions=suspicions,
            inspected_event_count=len([event for event in _events_for_attempt(request.primary_reader, request.attempt) if event.protocol == "HTTP2"]),
            warning_counts=warning_counts,
            elapsed_ms=elapsed_ms,
            issues=issues,
            manifest_path=manifest_path,
        ),
    )


def _encode_timeline_cursor(analysis_id: UUID, revision: str, query_digest: str, offset: int) -> str:
    payload = {"query_digest": query_digest, "offset": offset}
    encoded_payload = compact_json_bytes(payload)
    secret = f"T10:{analysis_id}:{revision}".encode("utf-8")
    digest = hmac.new(secret, encoded_payload, hashlib.sha256).hexdigest()
    envelope = {"payload": payload, "digest": digest}
    return base64.urlsafe_b64encode(compact_json_bytes(envelope)).decode("ascii")


def _decode_timeline_offset(
    cursor: str | None,
    *,
    analysis_id: UUID,
    revision: str,
    query_digest: str,
) -> int:
    if cursor is None:
        return 0
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii"))
        envelope = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # pragma: no cover - malformed cursor path
        raise ValueError("invalid timeline cursor") from exc
    payload = envelope.get("payload")
    digest = envelope.get("digest")
    if not isinstance(payload, dict) or not isinstance(digest, str):
        raise ValueError("invalid timeline cursor")
    expected_digest = hmac.new(
        f"T10:{analysis_id}:{revision}".encode("utf-8"),
        compact_json_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(digest, expected_digest):
        raise ValueError("timeline cursor authentication failed")
    if payload.get("query_digest") != query_digest:
        raise ValueError("timeline cursor query mismatch")
    offset = int(payload.get("offset", 0))
    if offset < 0:
        raise ValueError("invalid timeline cursor offset")
    return offset


def _publish_nas_ngap_result(
    request: FindNASNGAPFailuresRequest,
    started: datetime,
    candidates: list[FailureCandidate],
    terminal_effects: list[TerminalEffect],
    request_only: list[RequestOnlyObservation],
) -> FindNASNGAPFailuresResult:
    issues = []
    warning_counts: dict[str, int] = {}
    return _publish_detector_result(
        request.analysis_id,
        request.attempt.attempt_id,
        request.attempts_revision,
        request.run_dir,
        request.diagnostics_dir,
        "T07",
        started,
        {
            "candidates": [item.model_dump(mode="json") for item in candidates],
            "terminal_effects": [item.model_dump(mode="json") for item in terminal_effects],
            "request_only_observations": [item.model_dump(mode="json") for item in request_only],
        },
        candidate_count=len(candidates),
        warning_counts=warning_counts,
        issues=issues,
        result_factory=lambda revision, manifest, artifacts, elapsed_ms, manifest_path: FindNASNGAPFailuresResult(
            analysis_id=request.analysis_id,
            attempt_id=request.attempt.attempt_id,
            status="partial" if (candidates or request_only) else "success",
            revision=revision,
            manifest=manifest,
            artifacts=artifacts,
            candidates=candidates,
            terminal_effects=terminal_effects,
            request_only_observations=request_only,
            inspected_event_count=len([event for event in _events_for_attempt(request.primary_reader, request.attempt) if event.protocol in {"NAS", "NGAP"}]),
            warning_counts=warning_counts,
            elapsed_ms=elapsed_ms,
            issues=issues,
            manifest_path=manifest_path,
        ),
    )


def _publish_pfcp_result(
    request: FindPFCPFailuresRequest,
    started: datetime,
    candidates: list[FailureCandidate],
    transactions: list[PFCPTransactionGroup],
    association_observations: list[PFCPAssociationObservation],
    association_links: list[PFCPAssociationAttemptLink],
    session_reports: list[PFCPSessionReportObservation],
    consistency_checks: list[PFCPConsistencyResult],
) -> FindPFCPFailuresResult:
    issues = []
    warning_counts: dict[str, int] = {}
    return _publish_detector_result(
        request.analysis_id,
        request.attempt.attempt_id,
        request.attempts_revision,
        request.run_dir,
        request.diagnostics_dir,
        "T08",
        started,
        {
            "candidates": [item.model_dump(mode="json") for item in candidates],
            "transactions": [item.model_dump(mode="json") for item in transactions],
            "association_observations": [item.model_dump(mode="json") for item in association_observations],
            "association_links": [item.model_dump(mode="json") for item in association_links],
            "session_reports": [item.model_dump(mode="json") for item in session_reports],
            "consistency_checks": [item.model_dump(mode="json") for item in consistency_checks],
        },
        candidate_count=len(candidates),
        warning_counts=warning_counts,
        issues=issues,
        result_factory=lambda revision, manifest, artifacts, elapsed_ms, manifest_path: FindPFCPFailuresResult(
            analysis_id=request.analysis_id,
            attempt_id=request.attempt.attempt_id,
            status="partial" if (candidates or consistency_checks) else "success",
            revision=revision,
            manifest=manifest,
            artifacts=artifacts,
            candidates=candidates,
            transactions=transactions,
            association_observations=association_observations,
            association_links=association_links,
            session_reports=session_reports,
            consistency_checks=consistency_checks,
            inspected_event_count=len([event for event in _events_for_attempt(request.primary_reader, request.attempt) if event.protocol == "PFCP"]),
            warning_counts=warning_counts,
            elapsed_ms=elapsed_ms,
            issues=issues,
            manifest_path=manifest_path,
        ),
    )


def _publish_missing_result(
    request: DetectMissingTransitionsRequest,
    started: datetime,
    stage_results: list[StageResult],
    candidates: list[FailureCandidate],
    suppressions: list[MissingStageSuppression],
    first_missing_stage_id: str | None,
    last_completed_stage_id: str | None,
) -> DetectMissingTransitionsResult:
    issues = []
    warning_counts: dict[str, int] = {}
    return _publish_detector_result(
        request.analysis_id,
        request.attempt.attempt_id,
        request.attempts_revision,
        request.run_dir,
        request.diagnostics_dir,
        "T09",
        started,
        {
            "stage_results": [item.model_dump(mode="json") for item in stage_results],
            "candidates": [item.model_dump(mode="json") for item in candidates],
            "suppressions": [item.model_dump(mode="json") for item in suppressions],
        },
        candidate_count=len(candidates),
        warning_counts=warning_counts,
        issues=issues,
        result_factory=lambda revision, manifest, artifacts, elapsed_ms, manifest_path: DetectMissingTransitionsResult(
            analysis_id=request.analysis_id,
            attempt_id=request.attempt.attempt_id,
            status="partial" if candidates else "success",
            revision=revision,
            manifest=manifest,
            artifacts=artifacts,
            stage_results=stage_results,
            candidates=candidates,
            linked_suppressions=suppressions,
            stage_timings=list(request.attempt.stage_timings),
            first_missing_stage_id=first_missing_stage_id,
            last_completed_stage_id=last_completed_stage_id,
            warning_counts=warning_counts,
            elapsed_ms=elapsed_ms,
            issues=issues,
            manifest_path=manifest_path,
        ),
    )


def _publish_detector_result(
    analysis_id: UUID,
    attempt_id: UUID,
    attempts_revision: str,
    run_dir: Path,
    diagnostics_dir: Path,
    tool: Literal["T06", "T07", "T08", "T09"],
    started: datetime,
    payload: dict[str, Any],
    *,
    candidate_count: int,
    warning_counts: dict[str, int],
    issues: list[Issue],
    result_factory,
):
    relative_dir = f"normalized/diagnostics/{attempt_id}/{tool}"
    artifact_relative = f"{relative_dir}/result.json"
    manifest_relative = f"{relative_dir}/manifest.json"
    staging_root = run_dir / "staging" / f"{tool}-{attempt_id}"
    if staging_root.exists():
        for existing in sorted(staging_root.rglob("*"), reverse=True):
            if existing.is_file():
                existing.unlink()
            elif existing.is_dir():
                existing.rmdir()
    staging_root.mkdir(parents=True, exist_ok=True)
    revision = "sha256:" + sha256_bytes(
        compact_json_bytes(
            {
                "tool": tool,
                "version": DETECTOR_VERSION,
                "analysis_id": str(analysis_id),
                "attempt_id": str(attempt_id),
                "attempts_revision": attempts_revision,
                "payload": payload,
            }
        )
    )
    result_closed = JsonArtifactWriter(staging_root, run_dir, artifact_relative, f"{tool.lower()}_result").write(
        {
            "schema_version": SCHEMA_VERSION,
            "analysis_id": str(analysis_id),
            "attempt_id": str(attempt_id),
            "revision": revision,
            **payload,
        }
    )
    ended = datetime.now(tz=timezone.utc)
    elapsed_ms = int((ended - started).total_seconds() * 1000)
    manifest_closed = JsonArtifactWriter(staging_root, run_dir, manifest_relative, f"{tool.lower()}_manifest").write(
        {
            "schema_version": SCHEMA_VERSION,
            "tool": tool,
            "analysis_id": str(analysis_id),
            "attempt_id": str(attempt_id),
            "revision": revision,
            "attempts_revision": attempts_revision,
            "candidate_count": candidate_count,
            "warning_counts": warning_counts,
            "issues": [item.model_dump(mode="json") for item in issues],
            "artifact": result_closed.descriptor(creation_stage=tool, parent_source_sha256=attempts_revision),
            "elapsed_ms": elapsed_ms,
        }
    )
    publish_closed_artifacts(run_dir, [result_closed, manifest_closed], manifest_relative_path=manifest_relative)
    manifest_path = run_dir / manifest_relative
    artifact_path = run_dir / artifact_relative
    artifact_descriptor = ArtifactDescriptor(
        artifact_id=str(deterministic_uuid(analysis_id, tool, revision, "artifact")),
        relative_path=artifact_relative,
        artifact_type=f"{tool.lower()}_result",
        media_type="application/json",
        format_schema_version=SCHEMA_VERSION,
        sha256=sha256_file(artifact_path),
        byte_size=artifact_path.stat().st_size,
        record_count=1,
        creation_stage=tool,
        parent_source_sha256=attempts_revision,
        revision=revision,
    )
    manifest_descriptor = ArtifactDescriptor(
        artifact_id=str(deterministic_uuid(analysis_id, tool, revision, "manifest")),
        relative_path=manifest_relative,
        artifact_type=f"{tool.lower()}_manifest",
        media_type="application/json",
        format_schema_version=SCHEMA_VERSION,
        sha256=sha256_file(manifest_path),
        byte_size=manifest_path.stat().st_size,
        record_count=1,
        creation_stage=tool,
        parent_source_sha256=attempts_revision,
        revision=revision,
    )
    return result_factory(revision, manifest_descriptor, [artifact_descriptor], elapsed_ms, manifest_path)


def _candidate_from_event(
    analysis_id: UUID,
    attempt_id: UUID,
    *,
    detector: str,
    category: str,
    severity: Literal["info", "warning", "error", "critical"],
    event: CanonicalEvent,
    summary: str,
    observed: dict[str, Any],
    score_terms: list[ScoreTerm],
    explicit: bool,
    related_events: list[CanonicalEvent] | None = None,
) -> FailureCandidate:
    detector_score = sum((term.value for term in score_terms), start=Decimal("0"))
    detector_score = max(Decimal("0"), min(Decimal("1.0"), detector_score))
    related = sorted(related_events or [event], key=lambda item: (item.frame, str(item.event_id)))
    return FailureCandidate(
        candidate_id=deterministic_uuid(analysis_id, detector, attempt_id, category, *(item.event_id for item in related)),
        attempt_id=attempt_id,
        source_event_ids=[item.event_id for item in related],
        protocol=event.protocol,
        category=category,
        severity=severity,
        frame=event.frame,
        related_frames=[item.frame for item in related],
        component=None,
        summary=summary,
        observed=observed,
        explicit=explicit,
        evidence_ids=[deterministic_uuid(analysis_id, detector, "evidence", event.event_id, category)],
        detector=detector,
        detector_score=detector_score,
        score_terms=score_terms,
        capture_phase="unknown",
        relevance="attempt_related",
        call_impact="inconclusive",
    )


def _events_for_attempt(reader: JsonlPrimaryEventReader, attempt: ProcedureAttempt) -> list[CanonicalEvent]:
    events = [reader.get(event_id) for event_id in attempt.event_ids]
    return sorted(events, key=lambda item: (item.frame, str(item.event_id)))


def _http_transaction_groups(events: list[CanonicalEvent]) -> list[tuple[str, list[CanonicalEvent]]]:
    grouped: DefaultDict[str, list[CanonicalEvent]] = defaultdict(list)
    for event in events:
        key = (
            event.identifiers.http2_key
            or event.identifiers.correlation_id
            or event.identifiers.sm_context_ref
            or str(event.attributes.get("http.transaction_id") or "")
        )
        if not key:
            key = f"{event.attributes.get('http.method')}:{event.attributes.get('http.path')}:{event.frame}:{event.event_id}"
        grouped[str(key)].append(event)
    return [
        (key, sorted(group, key=lambda item: (item.frame, str(item.event_id))))
        for key, group in sorted(grouped.items(), key=lambda item: (item[1][0].frame, item[0]))
    ]


def _http_representative_event(grouped: list[CanonicalEvent]) -> CanonicalEvent:
    response = [event for event in grouped if _http_status([event]) is not None]
    if response:
        return sorted(response, key=lambda item: (item.frame, str(item.event_id)))[-1]
    return sorted(grouped, key=lambda item: (item.frame, str(item.event_id)))[-1]


def _http_status(grouped: list[CanonicalEvent]) -> int | None:
    for event in sorted(grouped, key=lambda item: (item.frame, str(item.event_id)), reverse=True):
        status = event.attributes.get("http.status")
        if isinstance(status, int):
            return status
        if isinstance(status, str) and status.isdigit():
            return int(status)
    return None


def _http_completion_state(grouped: list[CanonicalEvent]) -> str:
    states = {str(event.attributes.get("http.completion_state") or "").lower() for event in grouped}
    states.discard("")
    if any(state in {"reset", "rst_stream"} for state in states) or any(event.attributes.get("http.reset") for event in grouped):
        return "reset"
    if any(state in {"truncated", "partial", "incomplete_capture"} for state in states):
        return "incomplete_capture"
    if _http_status(grouped) is not None and any(event.attributes.get("http.method") for event in grouped):
        return "complete"
    if any(state in {"request_only", "timeout", "no_response"} for state in states):
        return "request_only"
    return next(iter(sorted(states)), "unknown")


def _http_incomplete_category(completion_state: str, attempt_completion_reason: str) -> Literal["http_timeout", "http_reset", "http_incomplete_capture"]:
    normalized = completion_state.lower()
    if normalized in {"reset", "rst_stream"}:
        return "http_reset"
    if normalized in {"truncated", "partial", "incomplete_capture", "response_only"}:
        return "http_incomplete_capture"
    if attempt_completion_reason in {"response_timeout", "idle_timeout"} or normalized in {"timeout", "request_only", "no_response"}:
        return "http_timeout"
    return "http_incomplete_capture"


def _first_http_attr(grouped: list[CanonicalEvent], key: str) -> Any:
    for event in sorted(grouped, key=lambda item: (item.frame, str(item.event_id))):
        value = event.attributes.get(key)
        if value not in {None, "", "None"}:
            return value
    return None


def _http_problem_details(grouped: list[CanonicalEvent]) -> dict[str, Any] | None:
    for event in sorted(grouped, key=lambda item: (item.frame, str(item.event_id)), reverse=True):
        for key in ("http.problem_details", "problem_details"):
            value = event.attributes.get(key)
            if isinstance(value, dict):
                return value
        body = event.attributes.get("http.response_body")
        if isinstance(body, dict):
            for key in ("problem_details", "selected_fields", "json"):
                value = body.get(key)
                if isinstance(value, dict):
                    return value
    return None


def _http_group_failed_or_incomplete(grouped: list[CanonicalEvent]) -> bool:
    status = _http_status(grouped)
    return (status is not None and status >= 400) or _http_completion_state(grouped) != "complete"


def _dependency_suspicion_reason(grouped: list[CanonicalEvent]) -> str | None:
    apis = {str(event.attributes.get("http.sbi_api") or "").lower() for event in grouped}
    nf_types = {
        str(event.attributes.get(key) or "").upper()
        for event in grouped
        for key in ("http.target_nf_type", "http.producer_nf_type", "http.consumer_nf_type")
    }
    if apis.intersection({"nnrf-nfm", "nnrf-disc"}) or "NRF" in nf_types:
        return "nrf_policy_backed"
    if "nudr-dr" in apis or "UDR" in nf_types:
        return "udr_policy_backed"
    return None


def _nas_ngap_cause_class(event: CanonicalEvent, cause: Any) -> Literal["success", "failure", "unknown"]:
    message = event.message_type.upper()
    normalized = str(cause or "").strip().lower()
    success_causes = {"", "none", "normal", "normal_release", "request_accepted", "success", "successful", "0", "1"}
    if event.outcome == "success" or "ACCEPT" in message or "COMPLETE" in message:
        if "REJECT" not in message and "FAIL" not in message and "UNSUCCESSFUL" not in message:
            return "success"
    if normalized in success_causes:
        return "success" if normalized not in {"", "none"} else "unknown"
    failure_tokens = ("reject", "fail", "unsuccessful", "error", "not_reachable", "unreachable", "denied", "invalid", "missing")
    if event.outcome == "failure" or any(token in message.lower() for token in failure_tokens) or any(token in normalized for token in failure_tokens):
        return "failure"
    if cause not in {None, "", "None"}:
        return "failure"
    return "unknown"


def _is_reachability_failure(event: CanonicalEvent, cause: Any) -> bool:
    text = f"{event.message_type} {cause or ''}".lower()
    return any(token in text for token in ("paging", "not_reachable", "unreachable", "mobile_terminated", "mt_delivery"))


def _is_terminal_profile_event(profile: ResolvedProcedureProfile, event: CanonicalEvent) -> bool:
    terminal_matchers = [*profile.success_terminals, *profile.failure_terminals, *profile.abort_terminals]
    return any(_diagnostic_event_matches(event, matcher) for matcher in terminal_matchers)


def _diagnostic_event_matches(event: CanonicalEvent, matcher: Any) -> bool:
    protocol = getattr(matcher, "protocol", None)
    if protocol is not None and event.protocol != protocol:
        return False
    message_types = getattr(matcher, "message_types", []) or []
    if message_types and event.message_type not in message_types:
        return False
    outcomes = getattr(matcher, "outcomes", []) or []
    if outcomes and event.outcome not in outcomes:
        return False
    attribute_equals = getattr(matcher, "attribute_equals", {}) or {}
    for key, value in attribute_equals.items():
        if event.attributes.get(key) != value:
            return False
    identifier_present = getattr(matcher, "identifier_present", []) or []
    for key in identifier_present:
        if getattr(event.identifiers, key, None) is None:
            return False
    return True


def _collect_field(
    fields: dict[str, RequestedField],
    conflicts: list[RequestFieldConflict],
    name: str,
    value: Any,
    *,
    events: list[CanonicalEvent] | None = None,
    path: str | None = None,
) -> None:
    if isinstance(value, tuple) and len(value) == 3:
        value, events, path = value
    if value is None:
        return
    source_events = events or []
    field = RequestedField(
        name=name,
        value=value,
        status="explicit",
        source_event_ids=[event.event_id for event in source_events],
        source_frames=[event.frame for event in source_events],
        raw_refs=[ref for event in source_events for ref in event.raw_refs],
        field_paths=[] if path is None else [path],
        evidence_ids=[
            deterministic_uuid(
                source_events[0].analysis_id if source_events else UUID("00000000-0000-0000-0000-000000000000"),
                "T05",
                "request_field",
                name,
                *(str(event.event_id) for event in source_events),
            )
        ] if source_events else [],
    )
    existing = fields.get(name)
    if existing is None:
        fields[name] = field
        return
    if existing.value != value:
        conflicts.append(
            RequestFieldConflict(
                name=name,
                values=[existing.value, value],
                source_event_ids=existing.source_event_ids + field.source_event_ids,
                source_frames=existing.source_frames + field.source_frames,
            )
        )
        fields[name] = existing.model_copy(update={"status": "conflicting", "confidence": "low"})


def _registration_type(attempt: ProcedureAttempt, events: list[CanonicalEvent]) -> tuple[Any, list[CanonicalEvent], str] | None:
    for event in events:
        if "REGISTRATION" in event.message_type.upper():
            return "initial", [event], "message_type"
    if "REGISTRATION" in attempt.procedure_type:
        return "initial", events[:1], "attempt.procedure_type"
    return None


def _service_request_type(attempt: ProcedureAttempt, events: list[CanonicalEvent]) -> tuple[Any, list[CanonicalEvent], str] | None:
    for event in events:
        if "SERVICE_REQUEST" in event.message_type.upper():
            return "service_request", [event], "message_type"
    if "SERVICE" in attempt.procedure_type:
        return "service_request", events[:1], "attempt.procedure_type"
    return None


def _first_attr(events: list[CanonicalEvent], key: str) -> tuple[Any, list[CanonicalEvent], str] | None:
    for event in events:
        value = event.attributes.get(key)
        if value not in {None, "", "None"}:
            return value, [event], key
    return None


def _release_origin(attempt: ProcedureAttempt) -> tuple[Any, list[CanonicalEvent], str] | None:
    if attempt.initiator == "UE":
        return "ue", [], "attempt.initiator"
    if attempt.initiator == "NETWORK":
        return "network", [], "attempt.initiator"
    return None


def _masked_ue_identity(request: GetUERequestRequest, events: list[CanonicalEvent]) -> MaskedUEIdentity | None:
    salt = str(request.masking_policy.get("salt") or "")
    if not salt:
        return None
    kinds: dict[str, str] = {}
    for event in events:
        for kind in ("supi", "suci", "gpsi", "guti", "pei"):
            value = getattr(event.identifiers, kind, None)
            if value is None or kind in kinds:
                continue
            kinds[kind] = mask_identifier(kind, str(value), salt)
    if not kinds:
        return None
    display_kind = sorted(kinds.keys())[0]
    return MaskedUEIdentity(display=kinds[display_kind], kinds=kinds)


def _identifier_summary(identifiers: EventIdentifiers) -> dict[str, str]:
    return {key: str(value) for key, value in identifiers.model_dump(exclude_none=True).items()}


def _stage_visibility_results(attempt: ProcedureAttempt, stage: StageDefinition) -> list[StageVisibilityResult]:
    results: list[StageVisibilityResult] = []
    for requirement in stage.visibility_requirements:
        if requirement.domain == "reference_point":
            state = attempt.visibility.reference_points.get(requirement.key, "unknown")
        elif requirement.domain == "sbi_service":
            state = attempt.visibility.services.get(requirement.key, "unknown")
        else:
            state = attempt.visibility.apis.get(requirement.key, "unknown")
        satisfied = state == "visible" or (requirement.minimum_state == "partial" and state == "partial")
        results.append(
            StageVisibilityResult(
                domain=requirement.domain,
                key=requirement.key,
                state=state,
                minimum_state=requirement.minimum_state,
                satisfied=satisfied,
            )
        )
    return results


def _stage_applicability_result(attempt: ProcedureAttempt, stage: StageDefinition) -> bool | None:
    if stage.applicability != "conditional" and stage.applicability_condition is None:
        return True
    condition = stage.applicability_condition
    if condition is None:
        return True
    return _evaluate_stage_condition(condition, _stage_condition_facts(attempt))


def _stage_condition_facts(attempt: ProcedureAttempt) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "access_family": attempt.access_family,
        "access_anchor_type": attempt.access_anchor_type,
        "completion_reason": attempt.completion_reason,
        "initiator": attempt.initiator,
        "outcome": attempt.outcome,
        "procedure": attempt.procedure_type,
        "procedure_type": attempt.procedure_type,
        "procedure_subtype": attempt.subtype,
        "profile_id": attempt.profile_id,
    }
    facts.update({f"request_signature.{key}": value for key, value in attempt.request_signature.items()})
    facts.update({f"identifier.{key}": value for key, value in attempt.correlation_identifiers.model_dump(exclude_none=True).items()})
    if attempt.roaming_topology is not None:
        facts["roaming_topology"] = attempt.roaming_topology.selected_topology
    return facts


def _evaluate_stage_condition(condition: dict[str, Any], facts: dict[str, Any]) -> bool | None:
    if not isinstance(condition, dict):
        return None
    if "all" in condition:
        results = [_evaluate_stage_condition(item, facts) for item in condition.get("all") or []]
        if any(result is False for result in results):
            return False
        return True if results and all(result is True for result in results) else None
    if "any" in condition:
        results = [_evaluate_stage_condition(item, facts) for item in condition.get("any") or []]
        if any(result is True for result in results):
            return True
        return False if results and all(result is False for result in results) else None
    if "fact" in condition:
        fact = str(condition.get("fact"))
        operator = str(condition.get("operator") or "eq")
        expected = condition.get("value")
    elif len(condition) == 1:
        fact, expected = next(iter(condition.items()))
        operator = "eq"
    else:
        return None
    present = fact in facts and facts[fact] is not None
    actual = facts.get(fact)
    if operator == "present":
        return present
    if operator == "absent":
        return not present
    if not present:
        return None
    if operator == "eq":
        return actual == expected
    if operator == "ne":
        return actual != expected
    if operator == "in":
        return isinstance(expected, (list, tuple, set)) and actual in expected
    return None


def _candidate_relates_to_stage(candidate: FailureCandidate, stage: StageDefinition) -> bool:
    hints = [
        candidate.component,
        candidate.observed.get("stage_id"),
        candidate.observed.get("component"),
        candidate.observed.get("stage"),
        candidate.observed.get("message_type"),
        candidate.category,
    ]
    return any(_diagnostic_semantic_match(hint, stage.stage_id) or _diagnostic_semantic_match(hint, stage.name) for hint in hints)


def _diagnostic_semantic_match(observed: Any, expected: Any) -> bool:
    if observed == expected:
        return True
    if not isinstance(observed, str) or not isinstance(expected, str):
        return False
    observed_parts = {part for part in _diagnostic_semantic_parts(observed) if part}
    expected_parts = {part for part in _diagnostic_semantic_parts(expected) if part}
    return bool(expected_parts) and expected_parts.issubset(observed_parts)


def _diagnostic_semantic_parts(value: str) -> list[str]:
    normalized = "".join(character.lower() if character.isalnum() else " " for character in value)
    return normalized.split()


def _stage_deadline_frame(
    attempt: ProcedureAttempt,
    stage: StageDefinition,
    transitions_by_stage: DefaultDict[str, list[Any]],
) -> int | None:
    if stage.timeout_seconds is None:
        return None
    anchor_frame = attempt.start_frame
    anchor_timestamp = attempt.start_timestamp
    predecessor_transitions = [
        transition
        for predecessor_id in stage.predecessor_ids
        for transition in transitions_by_stage.get(predecessor_id, [])
    ]
    if predecessor_transitions:
        anchor = sorted(predecessor_transitions, key=lambda item: (item.frame, str(item.transition_id)))[-1]
        anchor_frame = anchor.frame
        anchor_timestamp = anchor.timestamp
    if anchor_timestamp is None or attempt.end_timestamp is None:
        return anchor_frame
    if attempt.end_timestamp - anchor_timestamp <= stage.timeout_seconds:
        return attempt.end_frame
    return anchor_frame


def _frame_for_event_id(attempt: ProcedureAttempt, event_id: UUID, *, default: int) -> int:
    if event_id in attempt.event_ids:
        return attempt.start_frame
    return default


def _pfcp_transaction_key(event: CanonicalEvent) -> str:
    response_to = event.attributes.get("pfcp.response_to")
    if response_to not in {None, "", "None"}:
        return f"response_to:{response_to}"
    node_pair = _pfcp_node_pair_key(event) or "unknown_pair"
    sequence = event.identifiers.pfcp_sequence if event.identifiers.pfcp_sequence is not None else event.attributes.get("pfcp.sequence", "unknown_seq")
    seid = event.identifiers.cp_seid or event.identifiers.up_seid or event.attributes.get("pfcp.seid") or event.identifiers.pdu_session_id or "no_seid"
    return f"{node_pair}:seq={sequence}:seid={seid}"


def _pfcp_node_pair_key(event: CanonicalEvent) -> str | None:
    if event.src is None or event.dst is None or event.src.ip is None or event.dst.ip is None:
        return None
    ordered = sorted((event.src.ip, event.dst.ip))
    return f"{ordered[0]}->{ordered[1]}"


def _pfcp_cause_class(cause: Any) -> Literal["success", "failure", "unknown"]:
    normalized = str(cause or "").strip().lower()
    if normalized in {"", "none"}:
        return "unknown"
    if normalized in {"1", "request_accepted", "accepted", "success", "successful"}:
        return "success"
    if normalized in {"64", "request_rejected", "rejected", "failure", "failed"}:
        return "failure"
    failure_tokens = ("reject", "fail", "denied", "error", "invalid", "mandatory_ie_missing", "no_resources")
    if any(token in normalized for token in failure_tokens):
        return "failure"
    return "unknown"


def _pfcp_transaction_outcome(grouped: list[CanonicalEvent]) -> Literal["success", "failure", "unknown"]:
    response_seen = any("RESPONSE" in event.message_type.upper() for event in grouped)
    cause_classes = [_pfcp_cause_class(event.attributes.get("pfcp.cause")) for event in grouped]
    if "failure" in cause_classes:
        return "failure"
    if response_seen and "success" in cause_classes:
        return "success"
    return "unknown"


def _pfcp_failure_event(grouped: list[CanonicalEvent]) -> CanonicalEvent:
    for event in sorted(grouped, key=lambda item: (item.frame, str(item.event_id)), reverse=True):
        if _pfcp_cause_class(event.attributes.get("pfcp.cause")) == "failure":
            return event
    return grouped[-1]


def _pfcp_session_report(event: CanonicalEvent) -> PFCPSessionReportObservation | None:
    report_type = event.attributes.get("pfcp.report_type")
    if "SESSION_REPORT" not in event.message_type.upper() and report_type in {None, "", "None"}:
        return None
    summary = f"PFCP session report {report_type or event.message_type}"
    return PFCPSessionReportObservation(
        observation_id=deterministic_uuid(event.analysis_id, "T08", "session_report", event.event_id),
        event_id=event.event_id,
        frame=event.frame,
        summary=summary,
    )


def _report_indicates_failure(event: CanonicalEvent) -> bool:
    text = f"{event.message_type} {event.attributes.get('pfcp.report_type') or ''} {event.attributes.get('pfcp.report_reason') or ''}".lower()
    return any(token in text for token in ("error", "failure", "failed", "downlink_data_failure", "no_resources"))


def _pfcp_tunnel_consistency(analysis_id: UUID, event: CanonicalEvent) -> PFCPConsistencyResult | None:
    expected = event.attributes.get("pfcp.expected_tunnel_role")
    observed = event.attributes.get("pfcp.f_teid_direction") or event.attributes.get("pfcp.tunnel_direction")
    if expected in {None, "", "None"} and observed in {None, "", "None"}:
        return None
    if expected in {None, "", "None"} or observed in {None, "", "None"}:
        outcome: Literal["pass", "warning", "failure", "inconclusive"] = "inconclusive"
        summary = "PFCP tunnel role could not be fully validated"
    elif str(expected).lower() == str(observed).lower():
        outcome = "pass"
        summary = "PFCP tunnel role matched expected direction"
    else:
        outcome = "failure"
        summary = f"PFCP tunnel role {observed} did not match expected {expected}"
    return PFCPConsistencyResult(
        check_id=deterministic_uuid(analysis_id, "T08", "tunnel_consistency", event.event_id),
        event_id=event.event_id,
        frame=event.frame,
        outcome=outcome,
        summary=summary,
    )
