from __future__ import annotations

import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from decimal import Decimal
from pathlib import Path
from uuid import UUID, uuid4
from unittest.mock import patch

from harness.attempts import (
    EventMatcher,
    InterfaceVisibility,
    ProcedureAttempt,
    ProfileSelectionAlternative,
    ResolvedProcedureProfile,
    ResolvedProfileRegistry,
    SegmentAttemptsRequest,
    StageTimingObservation,
    StateTransition,
    StageDefinition,
    open_attempts_reader,
    segment_attempts,
)
from harness.diagnostics import (
    AttemptTimelineResult,
    BuildPFCPNodeStateCatalogRequest,
    DetectMissingTransitionsRequest,
    FindHTTPFailuresRequest,
    FindNASNGAPFailuresRequest,
    FindPFCPFailuresRequest,
    GetAttemptTimelineRequest,
    GetUERequestRequest,
    FailureCandidate,
    MaskedUEIdentity,
    RequestFieldConflict,
    RequestedField,
    ScoreTerm,
    TimelineItem,
    UERequestResult,
    build_pfcp_node_state_catalog,
    detect_missing_transitions,
    find_http_failures,
    find_nas_ngap_failures,
    find_pfcp_failures,
    get_attempt_timeline,
    get_ue_request,
    open_pfcp_node_state_catalog_reader,
)
from harness.decoder.manifest import ArtifactDescriptor
from harness.identity import BuildIdentityGraphRequest, build_identity_graph, open_identity_graph_reader
from harness.normalize import NormalizeEventsRequest, normalize_events, open_primary_event_reader
from harness.post_analysis import (
    AnalysisState,
    BuildExpandedEvidenceRequest,
    BuildInitialEvidenceRequest,
    ClassifyCapturePhasesRequest,
    CompareAttemptsRequest,
    ContextAnchor,
    ContextWindow,
    EvidenceCapability,
    GenerateDiagnosisRequest,
    GetPacketContextRequest,
    InspectNRFFlowRequest,
    InspectUDRFlowRequest,
    LookupFullEvidenceRequest,
    ParseScenarioRequest,
    ProviderConfig,
    RankRootCausesRequest,
    RedecodeSelection,
    RenderReportRequest,
    RootCauseResult,
    ScenarioCheckpoint,
    ScenarioCondition,
    ScenarioMatcher,
    ScenarioSelectors,
    ScenarioSpec,
    ScenarioTimeScope,
    CheckpointOrdering,
    ExpectedRequest,
    TargetedRedecodeRequest,
    ValidateScenarioRequest,
    build_expanded_evidence_packet,
    build_initial_evidence_packet,
    classify_capture_phases,
    compare_attempts,
    generate_diagnosis,
    get_packet_context,
    inspect_nrf_flow,
    inspect_udr_flow,
    lookup_full_evidence,
    parse_scenario,
    rank_root_causes,
    render_report,
    targeted_redecode,
    validate_scenario,
)
from harness.shared import CanonicalEvent, CaptureMetadata, EventIdentifiers, ProtocolCodepointRegistry, ResolvedPolicy, deterministic_uuid, iter_jsonl
from harness.tests.test_t02_t03 import NormalizeAndIdentityGraphTests


class PostAnalysisPipelineTests(unittest.TestCase):
    def test_t11_to_t25_pipeline(self) -> None:
        fixture = NormalizeAndIdentityGraphTests()
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            decode_result = fixture._build_decoder_run(run_dir)

            normalized = normalize_events(
                NormalizeEventsRequest(
                    analysis_id=decode_result.analysis_id,
                    decoder_result=decode_result,
                    run_dir=run_dir,
                    normalized_dir=run_dir / "normalized",
                    indexes_dir=run_dir / "indexes",
                    protocol_registry=ProtocolCodepointRegistry(
                        registry_name="5g_nas_ngap_pfcp",
                        registry_version="2026-06-10",
                        schema_version="2.0",
                        sha256="registry-sha",
                        nas_message_types={"65": "REGISTRATION_REQUEST"},
                        ngap_procedures={"14": "INITIAL_UE_MESSAGE"},
                        pfcp_message_types={"50": "SESSION_ESTABLISHMENT_REQUEST"},
                    ),
                    partition_policy=ResolvedPolicy(
                        name="dependency-partitions",
                        version="2026-06-10",
                        sha256="partition-sha",
                        payload={"udr_apis": ["nudr-dr"]},
                    ),
                    policy_versions={
                        "protocol_registry": "2026-06-10",
                        "partition_policy": "2026-06-10",
                    },
                )
            )
            primary_reader = open_primary_event_reader(normalized)
            graph = build_identity_graph(
                BuildIdentityGraphRequest(
                    analysis_id=decode_result.analysis_id,
                    normalization=normalized,
                    primary_reader=primary_reader,
                    capture=CaptureMetadata(
                        first_frame=1,
                        last_frame=100,
                        first_timestamp=None,
                        last_timestamp=None,
                        packet_count=30,
                        source_sha256=decode_result.source.sha256,
                    ),
                    run_dir=run_dir,
                    identity_dir=run_dir / "normalized" / "identity",
                    indexes_dir=run_dir / "indexes",
                    identity_rules=ResolvedPolicy(
                        name="identity-rules",
                        version="2026-06-10",
                        sha256="identity-sha",
                        payload={"sensitive_identifier_kinds": ["suci"]},
                    ),
                    topology_rules=ResolvedPolicy(
                        name="topology-rules",
                        version="2026-06-10",
                        sha256="topology-sha",
                        payload={},
                    ),
                    masking_policy=ResolvedPolicy(
                        name="masking-policy",
                        version="2026-06-10",
                        sha256="masking-sha",
                        payload={},
                    ),
                    masking_key="unit-test-key",
                    policy_versions={
                        "identity_rules": "2026-06-10",
                        "topology_rules": "2026-06-10",
                        "masking_policy": "2026-06-10",
                    },
                )
            )
            identity_graph = open_identity_graph_reader(graph)

            profile = ResolvedProcedureProfile(
                profile_id="registration.initial",
                version="1",
                release="R17",
                deployment_profile="default",
                procedure_type="INITIAL_REGISTRATION",
                trigger_matchers=[EventMatcher(protocol="NAS", message_types=["REGISTRATION_REQUEST"])],
                stages=[
                    StageDefinition(
                        stage_id="registration.request",
                        name="Registration Request",
                        order=1,
                        event_matchers=[EventMatcher(protocol="NAS", message_types=["REGISTRATION_REQUEST"])],
                    ),
                    StageDefinition(
                        stage_id="registration.accept",
                        name="Registration Accept",
                        order=2,
                        event_matchers=[EventMatcher(protocol="NAS", message_types=["REGISTRATION_ACCEPT"])],
                        terminal_success=True,
                    ),
                ],
                success_terminals=[EventMatcher(protocol="NAS", message_types=["REGISTRATION_ACCEPT"])],
                failure_terminals=[EventMatcher(protocol="NAS", message_types=["REGISTRATION_REJECT"])],
                abort_terminals=[],
                source_checksum="profile-sha",
                resolved_revision="profile-rev",
            )
            registry = ResolvedProfileRegistry(
                schema_version="2.0",
                registry_version="2026-06-10",
                sha256="profiles-sha",
                release="R17",
                deployment_profile="default",
                profiles=[profile],
            )
            attempts = segment_attempts(
                SegmentAttemptsRequest(
                    analysis_id=decode_result.analysis_id,
                    normalization=normalized,
                    identity_result=graph,
                    primary_reader=primary_reader,
                    identity_graph=identity_graph,
                    capture=CaptureMetadata(
                        first_frame=1,
                        last_frame=100,
                        first_timestamp=None,
                        last_timestamp=None,
                        packet_count=30,
                        source_sha256=decode_result.source.sha256,
                    ),
                    profile_registry=registry,
                    run_dir=run_dir,
                    attempts_dir=run_dir / "normalized" / "attempts",
                    indexes_dir=run_dir / "indexes",
                    policy_versions={"profile_registry": "2026-06-10"},
                )
            )
            attempts_reader = open_attempts_reader(attempts)
            attempt = attempts_reader.attempts[0]

            request_result = get_ue_request(
                GetUERequestRequest(
                    analysis_id=decode_result.analysis_id,
                    attempt=attempt,
                    attempts_revision=attempts.revision,
                    primary_reader=primary_reader,
                    identity_graph=identity_graph,
                    masking_policy={"salt": "unit-test-salt"},
                    run_dir=run_dir,
                    requests_dir=run_dir / "normalized" / "requests",
                )
            )
            http_result = find_http_failures(
                FindHTTPFailuresRequest(
                    analysis_id=decode_result.analysis_id,
                    attempt=attempt,
                    attempts_revision=attempts.revision,
                    primary_reader=primary_reader,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized" / "diagnostics" / str(attempt.attempt_id) / "T06",
                )
            )
            nas_ngap_result = find_nas_ngap_failures(
                FindNASNGAPFailuresRequest(
                    analysis_id=decode_result.analysis_id,
                    attempt=attempt,
                    attempts_revision=attempts.revision,
                    primary_reader=primary_reader,
                    profile=profile,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized" / "diagnostics" / str(attempt.attempt_id) / "T07",
                )
            )
            catalog = build_pfcp_node_state_catalog(
                BuildPFCPNodeStateCatalogRequest(
                    analysis_id=decode_result.analysis_id,
                    normalization=normalized,
                    primary_reader=primary_reader,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized" / "diagnostics",
                )
            )
            catalog_reader = open_pfcp_node_state_catalog_reader(catalog, run_dir)
            pfcp_result = find_pfcp_failures(
                FindPFCPFailuresRequest(
                    analysis_id=decode_result.analysis_id,
                    attempt=attempt,
                    attempts_revision=attempts.revision,
                    primary_reader=primary_reader,
                    identity_graph=identity_graph,
                    node_state_catalog=catalog_reader,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized" / "diagnostics" / str(attempt.attempt_id) / "T08",
                )
            )
            missing_result = detect_missing_transitions(
                DetectMissingTransitionsRequest(
                    analysis_id=decode_result.analysis_id,
                    attempt=attempt,
                    attempts_revision=attempts.revision,
                    profile=profile,
                    http_result=http_result,
                    nas_ngap_result=nas_ngap_result,
                    pfcp_result=pfcp_result,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized" / "diagnostics" / str(attempt.attempt_id) / "T09",
                )
            )
            timeline = get_attempt_timeline(
                GetAttemptTimelineRequest(
                    analysis_id=decode_result.analysis_id,
                    attempt=attempt,
                    request_result=request_result,
                    primary_reader=primary_reader,
                    http_result=http_result,
                    nas_ngap_result=nas_ngap_result,
                    pfcp_result=pfcp_result,
                    missing_result=missing_result,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized" / "diagnostics" / str(attempt.attempt_id) / "T10",
                )
            )

            baseline_attempt = attempt.model_copy(
                deep=True,
                update={
                    "attempt_id": uuid4(),
                    "outcome": "succeeded",
                    "completion_reason": "baseline_success",
                    "start_frame": max(1, attempt.start_frame - 10),
                    "end_frame": max(1, attempt.end_frame - 10),
                },
            )
            baseline_request = request_result.model_copy(
                deep=True,
                update={"attempt_id": baseline_attempt.attempt_id, "revision": "baseline-request-rev"},
            )

            comparison = compare_attempts(
                CompareAttemptsRequest(
                    analysis_id=decode_result.analysis_id,
                    failed_attempt=attempt,
                    candidate_baselines=[baseline_attempt],
                    failed_request=request_result,
                    baseline_requests=[baseline_request],
                )
            )
            self.assertEqual(comparison.selected_baseline_id, baseline_attempt.attempt_id)
            self.assertEqual(len(comparison.comparisons), 1)

            root_cause = rank_root_causes(
                RankRootCausesRequest(
                    analysis_id=decode_result.analysis_id,
                    attempt=attempt,
                    candidates=missing_result.candidates,
                    terminal_effects=nas_ngap_result.terminal_effects,
                    comparison=comparison.comparisons[0],
                    pass_stage="primary",
                )
            )
            self.assertIsNotNone(root_cause.primary_candidate_id)

            scenario = parse_scenario(
                ParseScenarioRequest(
                    analysis_id=decode_result.analysis_id,
                    scenario_text="registration should succeed on 3gpp access",
                    explicit_selectors=ScenarioSelectors(attempt_id=attempt.attempt_id),
                    provider_mode="none",
                )
            )
            self.assertEqual(scenario.status, "parsed")

            validation = validate_scenario(
                ValidateScenarioRequest(
                    analysis_id=decode_result.analysis_id,
                    scenario=scenario.spec,
                    explicit_attempt_id=attempt.attempt_id,
                    attempts=[attempt],
                    requests=[request_result],
                    root_causes=[root_cause],
                    pass_stage="primary",
                )
            )
            self.assertIn(validation.overall_status, {"failed", "inconclusive", "verified"})

            initial_packet = build_initial_evidence_packet(
                BuildInitialEvidenceRequest(
                    analysis_id=decode_result.analysis_id,
                    attempt=attempt,
                    request_result=request_result,
                    root_cause=root_cause,
                    timeline=timeline,
                    comparison=comparison,
                    scenario_validation=validation,
                    provider_mode="none",
                    run_dir=run_dir,
                    evidence_dir=run_dir / "evidence" / "packets",
                )
            )
            self.assertEqual(initial_packet.packet.pass_stage, "primary")
            self.assertIsNotNone(initial_packet.packet.primary_failure)
            self.assertEqual(initial_packet.packet.primary_failure.candidate_id, root_cause.primary_candidate_id)

            diagnosis = generate_diagnosis(
                GenerateDiagnosisRequest(
                    analysis_id=decode_result.analysis_id,
                    attempt_id=attempt.attempt_id,
                    packet=initial_packet.packet,
                    pass_stage="initial",
                    provider_config=ProviderConfig(mode="local", model="test-model"),
                )
            )
            self.assertEqual(diagnosis.status, "success")
            self.assertGreaterEqual(len(diagnosis.diagnosis.dependency_evidence_requests), 1)

            evidence = lookup_full_evidence(
                LookupFullEvidenceRequest(
                    analysis_id=decode_result.analysis_id,
                    caller_capability=EvidenceCapability(holder="test", analysis_id=decode_result.analysis_id, attempt_ids=[attempt.attempt_id]),
                    selectors={"event_ids": [attempt.event_ids[-1]]},
                    normalization=normalized,
                    attempts=[attempt],
                    candidates=missing_result.candidates,
                    request_results=[request_result],
                    field_paths=["message_type", "observed.stage_id"],
                )
            )
            self.assertGreaterEqual(evidence.returned_records, 1)
            self.assertTrue(any(record.field_path_results[0].found for record in evidence.records))

            context = get_packet_context(
                GetPacketContextRequest(
                    analysis_id=decode_result.analysis_id,
                    caller_capability=EvidenceCapability(holder="test", analysis_id=decode_result.analysis_id, attempt_ids=[attempt.attempt_id]),
                    anchor=ContextAnchor(candidate_id=root_cause.primary_candidate_id),
                    window=ContextWindow(frames_before=5, frames_after=5),
                    normalization=normalized,
                    attempts=[attempt],
                    candidates=missing_result.candidates,
                    run_dir=run_dir,
                    context_dir=run_dir / "evidence" / "context",
                )
            )
            self.assertGreaterEqual(len(context.packets), 1)
            self.assertEqual(context.effective_anchor.frame, attempt.end_frame)

            tshark_script = _write_fake_tshark(
                run_dir,
                [
                    {"_source": {"layers": {"frame": {"frame.number": "10"}, "http2": {"http2.streamid": "1"}}}},
                    {"_source": {"layers": {"frame": {"frame.number": "11"}, "http2": {"http2.streamid": "1"}}}},
                ],
            )
            with patch.dict(os.environ, {"ANALYSER_TSHARK_BIN": str(tshark_script)}):
                redecode = targeted_redecode(
                    TargetedRedecodeRequest(
                        analysis_id=decode_result.analysis_id,
                        caller_capability=EvidenceCapability(holder="test", analysis_id=decode_result.analysis_id, attempt_ids=[attempt.attempt_id]),
                        selection=RedecodeSelection(frame_start=10, frame_end=30),
                        normalization=normalized,
                        run_dir=run_dir,
                        redecode_dir=run_dir / "evidence" / "redecode",
                    )
                )
            self.assertEqual(redecode.status, "success")

            phases = classify_capture_phases(
                ClassifyCapturePhasesRequest(
                    analysis_id=decode_result.analysis_id,
                    attempts_revision=attempts.revision,
                    attempts=[attempt],
                    primary_reader=primary_reader,
                    capture=CaptureMetadata(
                        first_frame=1,
                        last_frame=100,
                        first_timestamp=None,
                        last_timestamp=None,
                        packet_count=30,
                        source_sha256=decode_result.source.sha256,
                    ),
                    run_dir=run_dir,
                    phases_dir=run_dir / "normalized" / "phases",
                )
            )
            self.assertGreaterEqual(len(phases.intervals), 1)

            nrf = inspect_nrf_flow(
                InspectNRFFlowRequest(
                    request_id=uuid4(),
                    analysis_id=decode_result.analysis_id,
                    initial_packet_id=initial_packet.packet.packet_id,
                    attempt_id=attempt.attempt_id,
                    reason_code="DISCOVERY_FAILURE_SUSPECTED",
                    rationale="test",
                    initial_evidence_ids=[],
                    frame_start=1,
                    frame_end=50,
                    nf_type="NRF",
                    service_name="nnrf-disc",
                    normalization=normalized,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized" / "diagnostics" / "nrf",
                )
            )
            self.assertIn(nrf.status, {"empty", "completed"})

            udr = inspect_udr_flow(
                InspectUDRFlowRequest(
                    request_id=uuid4(),
                    analysis_id=decode_result.analysis_id,
                    initial_packet_id=initial_packet.packet.packet_id,
                    attempt_id=attempt.attempt_id,
                    reason_code="SUBSCRIBER_DATA_FAILURE_SUSPECTED",
                    rationale="test",
                    initial_evidence_ids=[],
                    frame_start=1,
                    frame_end=20,
                    consumer_nf="UDM",
                    normalization=normalized,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized" / "diagnostics" / "udr",
                )
            )
            self.assertEqual(udr.status, "completed")

            expanded_root_cause = rank_root_causes(
                RankRootCausesRequest(
                    analysis_id=decode_result.analysis_id,
                    attempt=attempt,
                    candidates=missing_result.candidates + udr.failure_candidates,
                    terminal_effects=nas_ngap_result.terminal_effects,
                    comparison=comparison.comparisons[0],
                    dependency_results=[udr],
                    pass_stage="dependency_expanded",
                    primary_ranking_revision=root_cause.ranking_revision,
                )
            )
            expanded_packet = build_expanded_evidence_packet(
                BuildExpandedEvidenceRequest(
                    initial_packet=initial_packet.packet,
                    dependency_results=[udr],
                    expanded_root_cause=expanded_root_cause,
                    scenario_validation=validation,
                    run_dir=run_dir,
                    evidence_dir=run_dir / "evidence" / "packets",
                )
            )
            self.assertEqual(expanded_packet.packet.pass_stage, "dependency_expanded")

            analysis_state = AnalysisState(
                analysis_id=decode_result.analysis_id,
                attempts=[attempt],
                request_results=[request_result],
                root_cause_results=[root_cause, expanded_root_cause],
                timelines=[timeline],
                comparisons=[comparison],
                scenario_validation=validation,
                diagnoses=[diagnosis],
                dependency_results=[udr],
                capture={"source_sha256": decode_result.source.sha256, "packet_count": 30},
                run_dir=run_dir,
                report_dir=run_dir / "report",
            )
            report = render_report(
                RenderReportRequest(
                    analysis_id=decode_result.analysis_id,
                    analysis_state=analysis_state,
                )
            )
            self.assertTrue((run_dir / report.report_json.relative_path).exists())
            self.assertTrue((run_dir / report.report_markdown.relative_path).exists())


class ScenarioValidationTests(unittest.TestCase):
    def test_parse_scenario_extracts_selectors_scope_forbidden_and_ordering(self) -> None:
        analysis_id = UUID("20000000-0000-0000-0000-000000000101")
        parsed = parse_scenario(
            ParseScenarioRequest(
                analysis_id=analysis_id,
                scenario_text=(
                    "UE initiated registration should fail at SMF for PDU session 7 "
                    "with DNN internet on 3GPP frames 10-50, no registration reject, "
                    "registration request before smf"
                ),
            )
        )

        self.assertEqual(parsed.status, "parsed")
        self.assertEqual(parsed.confidence, "high")
        self.assertIsNotNone(parsed.spec)
        spec = parsed.spec
        self.assertEqual(spec.procedure, "INITIAL_REGISTRATION")
        self.assertEqual(spec.initiator, "UE")
        self.assertEqual(spec.expected_outcome, "failure")
        self.assertEqual(spec.expected_failure_stage, "smf")
        self.assertEqual(spec.selectors.pdu_session_id, 7)
        self.assertEqual(spec.expected_request.dnn, "internet")
        self.assertEqual(spec.expected_request.access_type, "3gpp")
        self.assertIsNotNone(spec.time_scope)
        self.assertEqual((spec.time_scope.frame_start, spec.time_scope.frame_end), (10, 50))
        self.assertEqual([item.checkpoint_id for item in spec.forbidden_events], ["no_registration_reject"])
        self.assertEqual(len(spec.ordering_constraints), 1)
        self.assertEqual(spec.ordering_constraints[0].constraint, "before")

    def test_expected_failure_stage_uses_primary_candidate_component(self) -> None:
        attempt, request_result, root = _scenario_validation_fixture()

        matching = validate_scenario(
            _validation_request(
                attempt,
                request_result,
                root,
                ScenarioSpec(
                    scenario_id=uuid4(),
                    original_text_hash="match",
                    selectors=ScenarioSelectors(attempt_id=attempt.attempt_id),
                    expected_failure_stage="smf",
                ),
            )
        )
        self.assertEqual(matching.overall_status, "verified")
        self.assertEqual(matching.checkpoints[0].status, "verified")
        self.assertEqual(matching.checkpoints[0].observed, "smf.create")

        mismatching = validate_scenario(
            _validation_request(
                attempt,
                request_result,
                root,
                ScenarioSpec(
                    scenario_id=uuid4(),
                    original_text_hash="mismatch",
                    selectors=ScenarioSelectors(attempt_id=attempt.attempt_id),
                    expected_failure_stage="amf",
                ),
            )
        )
        self.assertEqual(mismatching.overall_status, "failed")
        self.assertEqual(mismatching.checkpoints[0].status, "failed")
        self.assertEqual(mismatching.checkpoints[0].observed, "smf.create")
        self.assertIn("primary_candidate_stage_mismatch", mismatching.checkpoints[0].reason_codes)

    def test_selectors_and_all_request_expectations_are_deterministic(self) -> None:
        attempt, request_result, root = _scenario_validation_fixture()
        scenario = ScenarioSpec(
            scenario_id=uuid4(),
            original_text_hash="request-fields",
            procedure=attempt.procedure_type,
            selectors=ScenarioSelectors(
                ue_id=attempt.ue_id,
                masked_subscriber_alias="ue:test",
                amf_ue_ngap_id="amf-1",
                ran_ue_ngap_id="ran-1",
                pdu_session_id=7,
                frame_start=5,
                frame_end=30,
                time_start=Decimal("0.5"),
                time_end=Decimal("2.5"),
            ),
            expected_request=ExpectedRequest(
                dnn="internet",
                snssai="1-010203",
                pdu_type="ipv4",
                ssc_mode="1",
                registration_type="initial",
                service_type="data",
                access_type="3gpp",
                emergency=False,
            ),
        )
        validation = validate_scenario(_validation_request(attempt, request_result, root, scenario))

        self.assertEqual(validation.selected_attempt_ids, [attempt.attempt_id])
        self.assertEqual(validation.overall_status, "verified")
        self.assertEqual(len(validation.checkpoints), 8)
        self.assertTrue(all(item.status == "verified" for item in validation.checkpoints))

    def test_checkpoints_forbidden_ordering_applicability_and_time_scope(self) -> None:
        attempt, request_result, root = _scenario_validation_fixture()
        scenario = ScenarioSpec(
            scenario_id=uuid4(),
            original_text_hash="checkpoint-order",
            selectors=ScenarioSelectors(attempt_id=attempt.attempt_id),
            time_scope=ScenarioTimeScope(frame_start=5, frame_end=25),
            checkpoints=[
                ScenarioCheckpoint(
                    checkpoint_id="request_stage",
                    description="registration request stage",
                    protocol=None,
                    stage_id="registration.request",
                    matcher=ScenarioMatcher(stage_id="registration.request"),
                ),
                ScenarioCheckpoint(
                    checkpoint_id="smf_stage",
                    description="SMF stage",
                    protocol=None,
                    stage_id="smf.create",
                    matcher=ScenarioMatcher(stage_id="smf.create"),
                ),
                ScenarioCheckpoint(
                    checkpoint_id="emergency_only",
                    description="not applicable for non-emergency",
                    protocol=None,
                    stage_id=None,
                    matcher=ScenarioMatcher(field="outcome", operator="eq", value="failed"),
                    applicability_condition=ScenarioCondition(
                        fact="request.emergency",
                        operator="eq",
                        value=True,
                    ),
                ),
            ],
            forbidden_events=[
                ScenarioCheckpoint(
                    checkpoint_id="no_registration_reject",
                    description="registration reject must be absent",
                    protocol="NAS",
                    stage_id=None,
                    matcher=ScenarioMatcher(protocol="NAS", message_type="REGISTRATION_REJECT"),
                )
            ],
            ordering_constraints=[
                CheckpointOrdering(
                    first_checkpoint_id="request_stage",
                    second_checkpoint_id="smf_stage",
                    constraint="before",
                ),
                CheckpointOrdering(
                    first_checkpoint_id="request_stage",
                    second_checkpoint_id="smf_stage",
                    constraint="no_forbidden_between",
                ),
            ],
        )
        validation = validate_scenario(_validation_request(attempt, request_result, root, scenario))
        results = {item.checkpoint_id: item for item in validation.checkpoints}

        self.assertEqual(validation.overall_status, "verified")
        self.assertEqual(results["request_stage"].status, "verified")
        self.assertEqual(results["smf_stage"].status, "verified")
        self.assertEqual(results["emergency_only"].status, "not_applicable")
        self.assertEqual(results["no_registration_reject"].status, "verified")
        self.assertTrue(
            all(
                result.status == "verified"
                for checkpoint_id, result in results.items()
                if checkpoint_id.startswith("ordering.")
            )
        )

    def test_request_conflict_is_inconclusive_and_audited(self) -> None:
        attempt, request_result, root = _scenario_validation_fixture()
        request_result.fields["dnn"] = request_result.fields["dnn"].model_copy(
            update={"status": "conflicting", "value": None}
        )
        request_result.conflicts = [
            RequestFieldConflict(
                name="dnn",
                values=["internet", "ims"],
                source_event_ids=attempt.event_ids,
                source_frames=[10, 20],
            )
        ]
        scenario = ScenarioSpec(
            scenario_id=uuid4(),
            original_text_hash="conflict",
            selectors=ScenarioSelectors(attempt_id=attempt.attempt_id),
            expected_request=ExpectedRequest(dnn="internet"),
        )
        validation = validate_scenario(_validation_request(attempt, request_result, root, scenario))

        self.assertEqual(validation.overall_status, "inconclusive")
        self.assertEqual(validation.checkpoints[0].status, "inconclusive")
        self.assertTrue(validation.checkpoints[0].conflict)
        self.assertEqual(len(validation.conflicts), 1)

    def test_observed_forbidden_event_fails_and_invalid_matcher_is_rejected(self) -> None:
        attempt, request_result, root = _scenario_validation_fixture()
        scenario = ScenarioSpec(
            scenario_id=uuid4(),
            original_text_hash="forbidden-observed",
            selectors=ScenarioSelectors(attempt_id=attempt.attempt_id),
            forbidden_events=[
                ScenarioCheckpoint(
                    checkpoint_id="no_smf_failure",
                    description="SMF failure must be absent",
                    protocol="HTTP2",
                    stage_id="smf.create",
                    matcher=ScenarioMatcher(
                        protocol="HTTP2",
                        message_type="SM_CONTEXT_CREATE_FAILURE",
                    ),
                )
            ],
        )
        validation = validate_scenario(_validation_request(attempt, request_result, root, scenario))
        self.assertEqual(validation.overall_status, "failed")
        self.assertEqual(validation.checkpoints[0].status, "failed")
        self.assertIn("forbidden_event_observed", validation.checkpoints[0].reason_codes)

        invalid = scenario.model_copy(
            deep=True,
            update={
                "scenario_id": uuid4(),
                "forbidden_events": [
                    ScenarioCheckpoint(
                        checkpoint_id="invalid",
                        description="invalid field",
                        protocol=None,
                        stage_id=None,
                        matcher=ScenarioMatcher(field="arbitrary.json.path", operator="present"),
                    )
                ],
            },
        )
        with self.assertRaisesRegex(ValueError, "not allowlisted"):
            validate_scenario(_validation_request(attempt, request_result, root, invalid))

    def test_ambiguous_selection_is_inconclusive_and_time_scope_disambiguates(self) -> None:
        attempt, request_result, root = _scenario_validation_fixture()
        second = attempt.model_copy(
            deep=True,
            update={
                "attempt_id": uuid4(),
                "start_frame": 100,
                "end_frame": 120,
                "start_timestamp": Decimal("10"),
                "end_timestamp": Decimal("12"),
            },
        )
        second_request = request_result.model_copy(deep=True, update={"attempt_id": second.attempt_id})
        second_root = root.model_copy(deep=True, update={"attempt_id": second.attempt_id})

        ambiguous_scenario = ScenarioSpec(
            scenario_id=uuid4(),
            original_text_hash="ambiguous",
            procedure=attempt.procedure_type,
        )
        ambiguous = validate_scenario(
            ValidateScenarioRequest(
                analysis_id=attempt.analysis_id,
                scenario=ambiguous_scenario,
                attempts=[attempt, second],
                requests=[request_result, second_request],
                root_causes=[root, second_root],
                pass_stage="primary",
            )
        )
        self.assertEqual(ambiguous.overall_status, "inconclusive")
        self.assertEqual(ambiguous.selected_attempt_ids, [])
        self.assertTrue(all(item.ambiguous for item in ambiguous.selection_candidates))
        self.assertEqual(ambiguous.conflicts[0].checkpoint_id, "attempt_selection")

        scoped_scenario = ambiguous_scenario.model_copy(
            deep=True,
            update={
                "scenario_id": uuid4(),
                "time_scope": ScenarioTimeScope(frame_start=5, frame_end=30),
            },
        )
        scoped = validate_scenario(
            ValidateScenarioRequest(
                analysis_id=attempt.analysis_id,
                scenario=scoped_scenario,
                attempts=[attempt, second],
                requests=[request_result, second_request],
                root_causes=[root, second_root],
                pass_stage="primary",
            )
        )
        self.assertEqual(scoped.selected_attempt_ids, [attempt.attempt_id])
        self.assertEqual(scoped.overall_status, "not_applicable")

        missing_explicit = validate_scenario(
            ValidateScenarioRequest(
                analysis_id=attempt.analysis_id,
                scenario=scoped_scenario,
                explicit_attempt_id=uuid4(),
                attempts=[attempt, second],
                requests=[request_result, second_request],
                root_causes=[root, second_root],
                pass_stage="primary",
            )
        )
        self.assertEqual(missing_explicit.selected_attempt_ids, [])
        self.assertEqual(missing_explicit.overall_status, "inconclusive")


class EvidenceAuthorizationTests(unittest.TestCase):
    def test_lookup_context_and_redecode_enforce_capability_and_cursors(self) -> None:
        fixture = NormalizeAndIdentityGraphTests()
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            decode_result, normalized, events = _build_normalized_fixture(fixture, run_dir)
            primary_events = [event for event in events if event.partition == "primary"]
            udr_events = [event for event in events if event.partition == "udr"]
            self.assertGreaterEqual(len(primary_events), 2)
            self.assertEqual(len(udr_events), 1)

            denied = LookupFullEvidenceRequest(
                analysis_id=decode_result.analysis_id,
                caller_capability=EvidenceCapability(holder="test", analysis_id=decode_result.analysis_id),
                selectors={"event_ids": [udr_events[0].event_id]},
                normalization=normalized,
            )
            with self.assertRaisesRegex(ValueError, "outside capability scope"):
                lookup_full_evidence(denied)

            page_one = lookup_full_evidence(
                LookupFullEvidenceRequest(
                    analysis_id=decode_result.analysis_id,
                    caller_capability=EvidenceCapability(holder="test", analysis_id=decode_result.analysis_id),
                    selectors={"event_ids": [primary_events[0].event_id, primary_events[1].event_id]},
                    normalization=normalized,
                    page_size_bytes=2000,
                    max_records=1,
                )
            )
            self.assertTrue(page_one.truncated)
            self.assertIsNotNone(page_one.next_cursor)

            page_two = lookup_full_evidence(
                LookupFullEvidenceRequest(
                    analysis_id=decode_result.analysis_id,
                    caller_capability=EvidenceCapability(holder="test", analysis_id=decode_result.analysis_id),
                    selectors={"event_ids": [primary_events[0].event_id, primary_events[1].event_id]},
                    normalization=normalized,
                    page_size_bytes=2000,
                    max_records=1,
                    cursor=page_one.next_cursor,
                )
            )
            self.assertEqual(page_two.returned_records, 1)
            self.assertNotEqual(page_one.records[0].record_id, page_two.records[0].record_id)

            candidate = FailureCandidate(
                candidate_id=deterministic_uuid(decode_result.analysis_id, "registry-candidate"),
                attempt_id=uuid4(),
                source_event_ids=[primary_events[0].event_id],
                protocol=primary_events[0].protocol,
                category="registry_test_failure",
                severity="error",
                frame=primary_events[0].frame,
                component="registry.test",
                summary="registry-backed evidence",
                observed={"stage_id": "registry.test"},
                explicit=True,
                evidence_ids=[deterministic_uuid(decode_result.analysis_id, "registry-evidence")],
                detector="T06",
                detector_score=Decimal("0.80"),
                score_terms=[ScoreTerm(kind="base", rationale_code="registry_test", value=Decimal("0.80"))],
            )
            by_evidence = lookup_full_evidence(
                LookupFullEvidenceRequest(
                    analysis_id=decode_result.analysis_id,
                    caller_capability=EvidenceCapability(holder="test", analysis_id=decode_result.analysis_id),
                    selectors={"evidence_ids": [candidate.evidence_ids[0]]},
                    normalization=normalized,
                    candidates=[candidate],
                )
            )
            self.assertEqual(by_evidence.returned_records, 1)
            self.assertIn(str(candidate.evidence_ids[0]), by_evidence.records[0].metadata["evidence_registry_ids"])
            record_id = deterministic_uuid(decode_result.analysis_id, "T18", primary_events[0].event_id)
            by_record = lookup_full_evidence(
                LookupFullEvidenceRequest(
                    analysis_id=decode_result.analysis_id,
                    caller_capability=EvidenceCapability(holder="test", analysis_id=decode_result.analysis_id),
                    selectors={"record_ids": [record_id]},
                    normalization=normalized,
                )
            )
            self.assertEqual(by_record.records[0].record_id, record_id)
            with self.assertRaisesRegex(ValueError, "unknown evidence_id"):
                lookup_full_evidence(
                    LookupFullEvidenceRequest(
                        analysis_id=decode_result.analysis_id,
                        caller_capability=EvidenceCapability(holder="test", analysis_id=decode_result.analysis_id),
                        selectors={"evidence_ids": [uuid4()]},
                        normalization=normalized,
                        candidates=[candidate],
                    )
                )

            with self.assertRaisesRegex(ValueError, "query mismatch"):
                lookup_full_evidence(
                    LookupFullEvidenceRequest(
                        analysis_id=decode_result.analysis_id,
                        caller_capability=EvidenceCapability(holder="test", analysis_id=decode_result.analysis_id),
                        selectors={"event_ids": [primary_events[0].event_id]},
                        normalization=normalized,
                        page_size_bytes=2000,
                        max_records=1,
                        cursor=page_one.next_cursor,
                    )
                )

            with self.assertRaisesRegex(ValueError, "not authorized"):
                get_packet_context(
                    GetPacketContextRequest(
                        analysis_id=decode_result.analysis_id,
                        caller_capability=EvidenceCapability(holder="test", analysis_id=decode_result.analysis_id),
                        anchor=ContextAnchor(event_id=primary_events[0].event_id),
                        window=ContextWindow(frames_before=1, frames_after=1),
                        normalization=normalized,
                        detail="raw_packet",
                        run_dir=run_dir,
                        context_dir=run_dir / "evidence" / "context",
                    )
                )

            with self.assertRaisesRegex(ValueError, "not authorized"):
                targeted_redecode(
                    TargetedRedecodeRequest(
                        analysis_id=decode_result.analysis_id,
                        caller_capability=EvidenceCapability(holder="test", analysis_id=decode_result.analysis_id),
                        selection=RedecodeSelection(frame_start=10, frame_end=11),
                        normalization=normalized,
                        output_mode="raw_packet_json",
                        run_dir=run_dir,
                        redecode_dir=run_dir / "evidence" / "redecode",
                    )
                )


class EvidencePacketBudgetTests(unittest.TestCase):
    def test_packet_trims_optional_sections_and_fails_when_mandatory_exceeds_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            packet_request = _packet_fixture_from_scenario(run_dir)
            packet_request.timeline.items = [
                item.model_copy(update={"item_id": uuid4(), "message": "x" * 500})
                for item in packet_request.timeline.items
                for _ in range(4)
            ]
            packet_request.token_budget = packet_request.token_budget.model_copy(
                update={"effective_input_tokens": 2000, "hard_input_cap": 2000}
            )
            result = build_initial_evidence_packet(packet_request)
            self.assertLessEqual(result.token_count, 2000)
            self.assertTrue(result.truncations)

            oversized = _packet_fixture_from_scenario(run_dir)
            oversized.request_result.fields["dnn"] = oversized.request_result.fields["dnn"].model_copy(
                update={"value": "x" * 6000}
            )
            oversized.token_budget = oversized.token_budget.model_copy(
                update={"effective_input_tokens": 200, "hard_input_cap": 200}
            )
            with self.assertRaisesRegex(ValueError, "mandatory evidence exceeds"):
                build_initial_evidence_packet(oversized)


class DiagnosisProviderTests(unittest.TestCase):
    def test_local_provider_succeeds_and_final_pass_requests_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            packet_request = _packet_fixture_from_scenario(run_dir)
            packet = build_initial_evidence_packet(packet_request).packet

            success = generate_diagnosis(
                GenerateDiagnosisRequest(
                    analysis_id=packet.analysis_id,
                    attempt_id=packet.attempt.attempt_id,
                    packet=packet,
                    pass_stage="initial",
                    provider_config=ProviderConfig(mode="local", model="test-model"),
                )
            )
            self.assertEqual(success.status, "success")
            self.assertIsNotNone(success.provider)

            payload = {
                "schema_version": "2.0",
                "ue_request_summary": "test",
                "outcome_summary": "test",
                "root_cause_summary": "test",
                "primary_candidate_id": str(packet.primary_failure.candidate_id),
                "alternative_candidate_ids": [],
                "reasoning_steps": [],
                "evidence_ids": [str(packet.primary_failure.evidence_ids[0])],
                "confidence": "medium",
                "limitations": [],
                "deterministic_conflicts": [],
                "dependency_evidence_requests": [],
            }
            payload["dependency_evidence_requests"] = [
                {
                    "tool": "inspect_udr_flow",
                    "attempt_id": str(packet.attempt.attempt_id),
                    "reason_code": "SUBSCRIBER_DATA_FAILURE_SUSPECTED",
                    "rationale": "provider suggested extra evidence",
                    "frame_start": 1,
                    "frame_end": 2,
                }
            ]
            with patch("harness.post_analysis._invoke_provider_transport", return_value=(payload, None)):
                final = generate_diagnosis(
                    GenerateDiagnosisRequest(
                        analysis_id=packet.analysis_id,
                        attempt_id=packet.attempt.attempt_id,
                        packet=packet,
                        pass_stage="final",
                        provider_config=ProviderConfig(mode="local", model="test-model"),
                    )
                )
            self.assertEqual(final.status, "success")
            self.assertEqual(final.diagnosis.dependency_evidence_requests, [])
            self.assertIn("final_pass_tool_requests_rejected", final.warnings)

    def test_malformed_provider_payload_fails_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            packet_request = _packet_fixture_from_scenario(run_dir)
            packet = build_initial_evidence_packet(packet_request).packet
            with patch("harness.post_analysis._invoke_provider_transport", return_value=({"bad": "payload"}, None)):
                result = generate_diagnosis(
                    GenerateDiagnosisRequest(
                        analysis_id=packet.analysis_id,
                        attempt_id=packet.attempt.attempt_id,
                        packet=packet,
                        pass_stage="initial",
                        provider_config=ProviderConfig(mode="local", model="test-model"),
                    )
                )
            self.assertEqual(result.status, "failed")


class TargetedRedecodeTests(unittest.TestCase):
    def test_targeted_redecode_uses_fake_tshark_output(self) -> None:
        fixture = NormalizeAndIdentityGraphTests()
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            decode_result, normalized, _ = _build_normalized_fixture(fixture, run_dir)
            tshark_script = _write_fake_tshark(
                run_dir,
                [{"_source": {"layers": {"frame": {"frame.number": "10"}, "http2": {"http2.streamid": "1"}}}}],
            )
            with patch.dict(os.environ, {"ANALYSER_TSHARK_BIN": str(tshark_script)}):
                result = targeted_redecode(
                    TargetedRedecodeRequest(
                        analysis_id=decode_result.analysis_id,
                        caller_capability=EvidenceCapability(holder="test", analysis_id=decode_result.analysis_id),
                        selection=RedecodeSelection(frame_start=10, frame_end=10),
                        normalization=normalized,
                        run_dir=run_dir,
                        redecode_dir=run_dir / "evidence" / "redecode",
                    )
                )
            self.assertEqual(result.status, "success")
            self.assertEqual(result.access_plan.mode, "scan_preslice")
            self.assertTrue((run_dir / result.artifact.relative_path).exists())


class DependencyInspectionTests(unittest.TestCase):
    def test_success_only_udr_flow_does_not_emit_failure_candidate(self) -> None:
        fixture = NormalizeAndIdentityGraphTests()
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            decode_result, normalized, _ = _build_normalized_fixture(fixture, run_dir)
            result = inspect_udr_flow(
                InspectUDRFlowRequest(
                    request_id=uuid4(),
                    analysis_id=decode_result.analysis_id,
                    initial_packet_id=uuid4(),
                    attempt_id=uuid4(),
                    reason_code="SUBSCRIBER_DATA_FAILURE_SUSPECTED",
                    rationale="test",
                    frame_start=1,
                    frame_end=20,
                    normalization=normalized,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized" / "diagnostics" / "udr",
                )
            )
            self.assertEqual(result.impact.call_impact, "unrelated")
            self.assertEqual(result.failure_candidates, [])


class CapturePhasePublicationTests(unittest.TestCase):
    def test_no_attempts_publish_truthful_empty_artifacts(self) -> None:
        fixture = NormalizeAndIdentityGraphTests()
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            decode_result, normalized, _ = _build_normalized_fixture(fixture, run_dir)
            primary_reader = open_primary_event_reader(normalized)
            result = classify_capture_phases(
                ClassifyCapturePhasesRequest(
                    analysis_id=decode_result.analysis_id,
                    attempts_revision="sha256:none",
                    attempts=[],
                    primary_reader=primary_reader,
                    capture=CaptureMetadata(
                        first_frame=1,
                        last_frame=100,
                        packet_count=30,
                        source_sha256=decode_result.source.sha256,
                    ),
                    run_dir=run_dir,
                    phases_dir=run_dir / "normalized" / "phases",
                )
            )
            self.assertEqual(result.status, "unknown")
            self.assertTrue((run_dir / result.primary_event_labels_artifact.relative_path).exists())
            self.assertTrue(result.manifest_path.exists())


class PublicationDeterminismTests(unittest.TestCase):
    def test_evidence_packet_publication_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            request_one = _packet_fixture_from_scenario(run_dir)
            first = build_initial_evidence_packet(request_one)
            request_two = _packet_fixture_from_scenario(run_dir)
            second = build_initial_evidence_packet(request_two)
            self.assertEqual(first.artifact.artifact_id, second.artifact.artifact_id)
            self.assertEqual(first.manifest.artifact_id, second.manifest.artifact_id)
            self.assertEqual(first.token_count, second.token_count)


class ReportTruthfulnessTests(unittest.TestCase):
    def test_report_uses_stage_provider_integrity_and_evidence_state(self) -> None:
        attempt, request_result, root = _scenario_validation_fixture()
        attempt = attempt.model_copy(
            update={
                "profile_alternatives": [
                    ProfileSelectionAlternative(
                        profile_id="registration.periodic",
                        score=Decimal("0.80"),
                        reason_codes=["same_trigger"],
                    )
                ]
            }
        )
        root.candidate_records[0].source_event_ids = []
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            state = AnalysisState(
                analysis_id=attempt.analysis_id,
                attempts=[attempt],
                request_results=[request_result],
                root_cause_results=[root],
                capture={"source_sha256": "source-sha", "packet_count": 2, "completed_at": "2026-06-11T00:00:00Z"},
                stage_statuses={"T01": "success", "T02": "partial", "T16": "failed"},
                stage_revisions={"T01": "sha256:t01", "T02": "sha256:t02"},
                timings_ms={"T01": 10, "T02": 20},
                publication_warnings=["report source was partially available"],
                run_dir=run_dir,
                report_dir=run_dir / "report",
            )
            state.diagnoses = [
                generate_diagnosis(
                    GenerateDiagnosisRequest(
                        analysis_id=attempt.analysis_id,
                        attempt_id=attempt.attempt_id,
                        packet=build_initial_evidence_packet(_packet_fixture_from_scenario(run_dir)).packet,
                        pass_stage="initial",
                        provider_config=ProviderConfig(mode="none"),
                    )
                ).model_copy(update={"status": "failed", "warnings": ["provider_failed"]})
            ]
            result = render_report(RenderReportRequest(analysis_id=attempt.analysis_id, analysis_state=state))
            payload = json.loads((run_dir / result.report_json.relative_path).read_text(encoding="utf-8"))

            self.assertEqual(result.status, "partial")
            self.assertEqual(payload["pipeline"]["stage_statuses"]["T02"], "partial")
            self.assertEqual(payload["provider"]["status"], "failed")
            self.assertEqual(payload["evidence_integrity"]["status"], "degraded")
            self.assertEqual(payload["timings"], {"T01": 10, "T02": 20})
            self.assertEqual(payload["generated_at"], "2026-06-11T00:00:00Z")
            self.assertEqual(payload["ue_results"][0]["profile_alternatives"][0]["profile_id"], "registration.periodic")
            self.assertEqual(payload["ue_results"][0]["root_cause"]["primary_summary"], root.candidate_records[0].summary)
            self.assertTrue(payload["ue_results"][0]["root_cause"]["candidate_summaries"])
            self.assertTrue(payload["ue_results"][0]["evidence"])

    def test_critical_stage_failure_marks_report_failed_and_no_attempt_is_partial(self) -> None:
        analysis_id = UUID("30000000-0000-0000-0000-000000000001")
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            failed = render_report(
                RenderReportRequest(
                    analysis_id=analysis_id,
                    analysis_state=AnalysisState(
                        analysis_id=analysis_id,
                        stage_statuses={"T01": "failed"},
                        capture={"source_sha256": "unknown"},
                        run_dir=run_dir,
                        report_dir=run_dir / "report",
                    ),
                )
            )
            self.assertEqual(failed.status, "failed")

    def test_disabled_provider_and_empty_dependency_are_truthful(self) -> None:
        attempt, request_result, root = _scenario_validation_fixture()
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            diagnosis = generate_diagnosis(
                GenerateDiagnosisRequest(
                    analysis_id=attempt.analysis_id,
                    attempt_id=attempt.attempt_id,
                    packet=build_initial_evidence_packet(_packet_fixture_from_scenario(run_dir)).packet,
                    pass_stage="initial",
                    provider_config=ProviderConfig(mode="none"),
                )
            )
            state = AnalysisState(
                analysis_id=attempt.analysis_id,
                attempts=[attempt],
                request_results=[request_result],
                root_cause_results=[root],
                diagnoses=[diagnosis],
                dependency_results=[SimpleNamespace(request_id=uuid4(), attempt_id=attempt.attempt_id, status="empty")],
                capture={"source_sha256": "source-sha"},
                stage_statuses={"T01": "success", "T02": "success", "T03": "success"},
                publication_warnings=["secondary report surface unavailable"],
                run_dir=run_dir,
                report_dir=run_dir / "report",
            )
            result = render_report(RenderReportRequest(analysis_id=attempt.analysis_id, analysis_state=state))
            payload = json.loads((run_dir / result.report_json.relative_path).read_text(encoding="utf-8"))

        self.assertEqual(result.status, "partial")
        self.assertEqual(payload["provider"], {"mode": "none", "status": "disabled"})
        self.assertEqual(payload["pipeline"]["stage_statuses"]["T24/T25"], "empty")
        self.assertNotIn("T10", payload["pipeline"]["invoked_tools"])
        self.assertIn("publication_warning", result.warnings)

    def test_report_publication_failure_is_not_reported_successfully(self) -> None:
        analysis_id = UUID("30000000-0000-0000-0000-000000000002")
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            with patch("harness.post_analysis.publish_closed_artifacts", side_effect=OSError("disk full")):
                with self.assertRaisesRegex(OSError, "disk full"):
                    render_report(
                        RenderReportRequest(
                            analysis_id=analysis_id,
                            analysis_state=AnalysisState(
                                analysis_id=analysis_id,
                                stage_statuses={"T01": "success"},
                                capture={"source_sha256": "source-sha"},
                                run_dir=run_dir,
                                report_dir=run_dir / "report",
                            ),
                        )
                    )
            self.assertFalse((run_dir / "report/report_manifest.json").exists())


class RankingAndDivergenceTests(unittest.TestCase):
    def test_excluded_high_score_does_not_control_rank_or_confidence(self) -> None:
        attempt, _, _ = _scenario_validation_fixture()
        excluded = FailureCandidate(
            candidate_id=uuid4(),
            attempt_id=attempt.attempt_id,
            protocol="HTTP2",
            category="dependency",
            severity="error",
            frame=5,
            summary="excluded",
            observed={},
            explicit=True,
            detector="T24",
            detector_score=Decimal("1.20"),
            call_impact="unrelated",
        )
        eligible = excluded.model_copy(
            deep=True,
            update={
                "candidate_id": uuid4(),
                "category": "primary",
                "summary": "eligible",
                "frame": 10,
                "detector_score": Decimal("0.80"),
                "call_impact": None,
            },
        )
        result = rank_root_causes(
            RankRootCausesRequest(
                analysis_id=attempt.analysis_id,
                attempt=attempt,
                candidates=[excluded, eligible],
                pass_stage="primary",
            )
        )
        ranked = {item.candidate_id: item for item in result.ranked_candidates}
        self.assertEqual(result.primary_candidate_id, eligible.candidate_id)
        self.assertEqual(ranked[eligible.candidate_id].rank, 1)
        self.assertIsNone(ranked[excluded.candidate_id].rank)
        self.assertEqual(result.confidence, "high")
        self.assertEqual(ranked[eligible.candidate_id].final_score, Decimal("0.8800"))
        self.assertEqual(
            [term.rationale_code for term in ranked[eligible.candidate_id].score_terms],
            ["detector_base", "explicit_failure_bonus"],
        )

    def test_stage_alignment_uses_frame_order_and_preserves_occurrences(self) -> None:
        attempt, request_result, _ = _scenario_validation_fixture()
        failed = attempt.model_copy(
            deep=True,
            update={
                "stage_timings": [
                    _stage_timing(attempt.analysis_id, "z.stage", 10, "observed", 1),
                    _stage_timing(attempt.analysis_id, "a.stage", 20, "observed", 1),
                    _stage_timing(attempt.analysis_id, "a.stage", 30, "missing", 2),
                ]
            },
        )
        baseline = failed.model_copy(
            deep=True,
            update={
                "attempt_id": uuid4(),
                "outcome": "succeeded",
                "start_frame": 1,
                "stage_timings": [
                    _stage_timing(attempt.analysis_id, "a.stage", 20, "observed", 1),
                    _stage_timing(attempt.analysis_id, "a.stage", 30, "observed", 2),
                ],
            },
        )
        comparison = compare_attempts(
            CompareAttemptsRequest(
                analysis_id=attempt.analysis_id,
                failed_attempt=failed,
                candidate_baselines=[baseline],
                failed_request=request_result,
                baseline_requests=[request_result.model_copy(update={"attempt_id": baseline.attempt_id})],
            )
        ).comparisons[0]
        self.assertEqual(comparison.first_divergence.stage_id, "z.stage")
        repeated = [item for item in comparison.stage_alignment if item.stage_id == "a.stage"]
        self.assertEqual([item.occurrence for item in repeated], [1, 2])
        self.assertEqual(repeated[1].relation, "changed")


def _scenario_validation_fixture() -> tuple[ProcedureAttempt, UERequestResult, RootCauseResult]:
    analysis_id = UUID("20000000-0000-0000-0000-000000000001")
    attempt_id = UUID("20000000-0000-0000-0000-000000000002")
    ue_id = UUID("20000000-0000-0000-0000-000000000003")
    request_event_id = deterministic_uuid(analysis_id, "scenario", "registration-request")
    smf_event_id = deterministic_uuid(analysis_id, "scenario", "smf-create")
    attempt = ProcedureAttempt(
        attempt_id=attempt_id,
        analysis_id=analysis_id,
        ue_id=ue_id,
        session_node_id=UUID("20000000-0000-0000-0000-000000000004"),
        access_context_id=UUID("20000000-0000-0000-0000-000000000005"),
        access_family="3gpp",
        access_anchor_type="GNB",
        profile_id="registration.initial",
        procedure_type="INITIAL_REGISTRATION",
        sequence_number=1,
        initiator="UE",
        start_frame=10,
        end_frame=20,
        start_timestamp=Decimal("1.0"),
        end_timestamp=Decimal("2.0"),
        trigger_event_ids=[request_event_id],
        event_ids=[request_event_id, smf_event_id],
        correlation_identifiers=EventIdentifiers(
            amf_ue_ngap_id="amf-1",
            ran_ue_ngap_id="ran-1",
            pdu_session_id=7,
        ),
        transitions=[
            StateTransition(
                transition_id=deterministic_uuid(analysis_id, "transition", "registration.request"),
                stage_id="registration.request",
                stage_name="Registration Request",
                event_id=request_event_id,
                frame=10,
                timestamp=Decimal("1.0"),
            ),
            StateTransition(
                transition_id=deterministic_uuid(analysis_id, "transition", "smf.create"),
                stage_id="smf.create",
                stage_name="SMF Create Context",
                event_id=smf_event_id,
                frame=20,
                timestamp=Decimal("2.0"),
                transition_type="failed",
            ),
        ],
        outcome="failed",
        completion_reason="stage:smf.create",
        visibility=InterfaceVisibility(
            reference_points={"N1": "visible", "N2": "visible", "N4": "visible"},
            services={"nsmf-pdusession": "visible"},
        ),
    )
    artifact = _scenario_artifact(analysis_id, "request.json", "ue_request")
    field_values = {
        "dnn": "internet",
        "snssai": "1-010203",
        "pdu_type": "ipv4",
        "ssc_mode": "1",
        "registration_type": "initial",
        "service_type": "data",
        "access_type": "3gpp",
        "emergency": False,
    }
    request_result = UERequestResult(
        analysis_id=analysis_id,
        attempt_id=attempt_id,
        revision="sha256:scenario-request",
        status="decoded",
        procedure=attempt.procedure_type,
        initiator="UE",
        fields={
            name: RequestedField(
                name=name,
                value=value,
                status="explicit",
                source_event_ids=[request_event_id],
                source_frames=[10],
                evidence_ids=[deterministic_uuid(analysis_id, "request-field", name)],
            )
            for name, value in field_values.items()
        },
        ue=MaskedUEIdentity(display="ue:test", kinds={"suci": "suci:test"}),
        trigger_event_ids=[request_event_id],
        trigger_frames=[10],
        artifact=artifact,
        manifest=_scenario_artifact(analysis_id, "request_manifest.json", "ue_request_manifest"),
        manifest_path=Path("/tmp/scenario/request_manifest.json"),
    )
    candidate = FailureCandidate(
        candidate_id=deterministic_uuid(analysis_id, "candidate", "smf.create"),
        attempt_id=attempt_id,
        source_event_ids=[smf_event_id],
        protocol="HTTP2",
        category="http_status_failure",
        severity="error",
        frame=20,
        component="smf.create",
        summary="SMF create context failed",
        observed={"stage_id": "smf.create", "status": 500, "message_type": "SM_CONTEXT_CREATE_FAILURE"},
        explicit=True,
        evidence_ids=[deterministic_uuid(analysis_id, "candidate-evidence", "smf.create")],
        detector="T06",
        detector_score=Decimal("0.90"),
        score_terms=[ScoreTerm(kind="base", rationale_code="test", value=Decimal("0.90"))],
    )
    root = RootCauseResult(
        attempt_id=attempt_id,
        pass_stage="primary",
        primary_candidate_id=candidate.candidate_id,
        candidate_records=[candidate],
        confidence="high",
        ranking_revision="sha256:scenario-ranking",
    )
    return attempt, request_result, root


def _validation_request(
    attempt: ProcedureAttempt,
    request_result: UERequestResult,
    root: RootCauseResult,
    scenario: ScenarioSpec,
) -> ValidateScenarioRequest:
    return ValidateScenarioRequest(
        analysis_id=attempt.analysis_id,
        scenario=scenario,
        attempts=[attempt],
        requests=[request_result],
        root_causes=[root],
        pass_stage="primary",
    )


def _scenario_artifact(
    analysis_id: UUID,
    relative_path: str,
    artifact_type: str,
) -> ArtifactDescriptor:
    return ArtifactDescriptor(
        artifact_id=str(deterministic_uuid(analysis_id, "scenario-artifact", relative_path)),
        relative_path=relative_path,
        artifact_type=artifact_type,
        media_type="application/json",
        format_schema_version="2.0",
        sha256=f"sha256:{artifact_type}",
        byte_size=0,
        record_count=1,
        creation_stage="test",
        revision=f"sha256:{artifact_type}",
    )


def _write_fake_tshark(run_dir: Path, payload: list[dict[str, object]]) -> Path:
    script_path = run_dir / "fake_tshark.py"
    script_path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import json",
                f"print(json.dumps({json.dumps(payload)}))",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    script_path.chmod(0o755)
    return script_path


def _stage_timing(
    analysis_id: UUID,
    stage_id: str,
    frame: int,
    status: str,
    occurrence: int,
) -> StageTimingObservation:
    event_id = deterministic_uuid(analysis_id, "stage-event", stage_id, occurrence)
    return StageTimingObservation(
        stage_timing_id=deterministic_uuid(analysis_id, "stage-timing", stage_id, occurrence),
        stage_id=stage_id,
        stage_name=stage_id,
        first_event_id=event_id,
        first_frame=frame,
        last_event_id=event_id,
        last_frame=frame,
        status=status,
    )


def _build_normalized_fixture(
    fixture: NormalizeAndIdentityGraphTests,
    run_dir: Path,
) -> tuple[object, object, list[CanonicalEvent]]:
    decode_result = fixture._build_decoder_run(run_dir)
    normalized = normalize_events(
        NormalizeEventsRequest(
            analysis_id=decode_result.analysis_id,
            decoder_result=decode_result,
            run_dir=run_dir,
            normalized_dir=run_dir / "normalized",
            indexes_dir=run_dir / "indexes",
            protocol_registry=ProtocolCodepointRegistry(
                registry_name="5g_nas_ngap_pfcp",
                registry_version="2026-06-10",
                schema_version="2.0",
                sha256="registry-sha",
                nas_message_types={"65": "REGISTRATION_REQUEST"},
                ngap_procedures={"14": "INITIAL_UE_MESSAGE"},
                pfcp_message_types={"50": "SESSION_ESTABLISHMENT_REQUEST"},
            ),
            partition_policy=ResolvedPolicy(
                name="dependency-partitions",
                version="2026-06-10",
                sha256="partition-sha",
                payload={"udr_apis": ["nudr-dr"], "nrf_apis": ["nnrf-disc"]},
            ),
            policy_versions={
                "protocol_registry": "2026-06-10",
                "partition_policy": "2026-06-10",
            },
        )
    )
    return decode_result, normalized, [
        CanonicalEvent.model_validate(record)
        for record in iter_jsonl(run_dir / "normalized/events/events.jsonl")
    ]


def _packet_fixture_from_scenario(run_dir: Path) -> BuildInitialEvidenceRequest:
    attempt, request_result, root = _scenario_validation_fixture()
    timeline = AttemptTimelineResult(
        attempt_id=attempt.attempt_id,
        mode="internal",
        items=[
            TimelineItem(
                item_id=deterministic_uuid(attempt.analysis_id, "timeline", "start"),
                attempt_id=attempt.attempt_id,
                event_id=attempt.trigger_event_ids[0],
                source_kind="request",
                frame=attempt.start_frame,
                timestamp=attempt.start_timestamp,
                sort_ordinal=1,
                protocol="NAS",
                direction="UE_TO_NETWORK",
                stage_id="registration.request",
                message="Registration Request",
                label="expected",
                evidence_ids=[attempt.trigger_event_ids[0]],
            ),
            TimelineItem(
                item_id=deterministic_uuid(attempt.analysis_id, "timeline", "failure"),
                attempt_id=attempt.attempt_id,
                candidate_id=root.primary_candidate_id,
                source_kind="candidate",
                frame=attempt.end_frame,
                timestamp=attempt.end_timestamp,
                sort_ordinal=2,
                protocol="HTTP2",
                direction="NF_TO_NF",
                stage_id="smf.create",
                message="SMF create failed",
                label="failure",
                evidence_ids=[root.candidate_records[0].evidence_ids[0]],
            ),
        ],
        total_matching=2,
        returned=2,
        truncated=False,
        revision="sha256:timeline",
        manifest=_scenario_artifact(attempt.analysis_id, "timeline_manifest.json", "attempt_timeline_manifest"),
        artifact=_scenario_artifact(attempt.analysis_id, "timeline.jsonl", "attempt_timeline"),
        manifest_path=run_dir / "timeline_manifest.json",
    )
    return BuildInitialEvidenceRequest(
        analysis_id=attempt.analysis_id,
        attempt=attempt,
        request_result=request_result,
        root_cause=root,
        timeline=timeline,
        provider_mode="local",
        run_dir=run_dir,
        evidence_dir=run_dir / "evidence" / "packets",
    )


if __name__ == "__main__":
    unittest.main()
