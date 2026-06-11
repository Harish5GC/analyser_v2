from __future__ import annotations

import json
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from uuid import UUID

from harness.attempts import (
    AttemptSegmentationConfig,
    EventMatcher,
    InterfaceVisibility,
    ProcedureAttempt,
    ResolvedProcedureProfile,
    ResolvedProfileRegistry,
    SegmentAttemptsRequest,
    StageDefinition,
    StateTransition,
    VisibilityRequirement,
    load_resolved_profile_registry,
    open_attempts_reader,
    segment_attempts,
)
from harness.decoder.manifest import ArtifactDescriptor
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
from harness.identity import (
    BuildIdentityGraphRequest,
    BuildIdentityGraphResult,
    IdentifierObservation,
    IdentityGraphReader,
    IdentityNode,
    build_identity_graph,
    open_identity_graph_reader,
)
from harness.normalize import (
    JsonlPrimaryEventReader,
    NormalizeEventsRequest,
    NormalizeEventsResult,
    normalize_events,
    open_primary_event_reader,
)
from harness.shared import (
    CanonicalEvent,
    CaptureMetadata,
    Endpoint,
    EventIdentifiers,
    ProtocolCodepointRegistry,
    ResolvedPolicy,
    compact_json_bytes,
    deterministic_uuid,
    iter_jsonl,
    sha256_file,
)
from harness.tests.test_t02_t03 import NormalizeAndIdentityGraphTests


class AttemptAndDetectorPipelineTests(unittest.TestCase):
    def test_t04_to_t10_pipeline(self) -> None:
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
                trigger_matchers=[
                    EventMatcher(protocol="NAS", message_types=["REGISTRATION_REQUEST"]),
                ],
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
            self.assertEqual(attempts.attempt_count, 1)
            self.assertEqual(attempts.outcome_counts["incomplete_capture"], 1)
            self.assertEqual(attempts.ambiguous_assignment_count, 0)

            attempts_reader = open_attempts_reader(attempts)
            attempt = attempts_reader.attempts[0]
            self.assertEqual(attempt.profile_id, "registration.initial")
            self.assertIn("registration.request", {item.stage_id for item in attempt.stage_timings})

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
            self.assertEqual(request_result.status, "decoded")
            self.assertEqual(request_result.fields["registration_type"].value, "initial")
            self.assertEqual(request_result.fields["access_type"].value, "3gpp")
            self.assertIsNotNone(request_result.ue)

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
            self.assertEqual(len(http_result.candidates), 0)

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
            self.assertEqual(len(nas_ngap_result.candidates), 0)
            self.assertGreaterEqual(len(nas_ngap_result.request_only_observations), 1)

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
            self.assertEqual(len(pfcp_result.candidates), 0)
            self.assertGreaterEqual(len(pfcp_result.association_observations), 0)

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
            self.assertEqual(len(missing_result.candidates), 1)
            self.assertEqual(missing_result.first_missing_stage_id, "registration.accept")

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
            self.assertGreater(timeline.returned, 0)
            self.assertIn("missing_transition", {item.label for item in timeline.items})
            self.assertTrue((run_dir / timeline.artifact.relative_path).exists())

            first_page = get_attempt_timeline(
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
                    limit=2,
                )
            )
            self.assertTrue(first_page.truncated)
            self.assertIsNotNone(first_page.next_cursor)
            second_page = get_attempt_timeline(
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
                    limit=2,
                    cursor=first_page.next_cursor,
                )
            )
            self.assertEqual(first_page.revision, second_page.revision)
            self.assertGreater(second_page.items[0].sort_ordinal, first_page.items[-1].sort_ordinal)
            with self.assertRaisesRegex(ValueError, "query mismatch"):
                get_attempt_timeline(
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
                        limit=3,
                        cursor=first_page.next_cursor,
                    )
                )

    def test_t06_http2_transactions_retries_and_dependency_suspicions(self) -> None:
        analysis_id = UUID("10000000-0000-0000-0000-000000000101")
        request_event = _event(analysis_id, 10, "POST /nnrf-disc/v1/nf-instances", "ue-a", protocol="HTTP2").model_copy(
            update={
                "identifiers": EventIdentifiers(http2_key="stream-1", correlation_id="corr-1"),
                "attributes": {
                    "http.method": "POST",
                    "http.path": "/nnrf-disc/v1/nf-instances",
                    "http.sbi_api": "nnrf-disc",
                    "http.completion_state": "request_only",
                    "test.ue": "ue-a",
                },
            }
        )
        response_event = _event(analysis_id, 11, "POST /nnrf-disc/v1/nf-instances", "ue-a", protocol="HTTP2").model_copy(
            update={
                "outcome": "failure",
                "identifiers": EventIdentifiers(http2_key="stream-1", correlation_id="corr-1"),
                "attributes": {
                    "http.method": "POST",
                    "http.path": "/nnrf-disc/v1/nf-instances",
                    "http.status": 503,
                    "http.sbi_api": "nnrf-disc",
                    "http.completion_state": "complete",
                    "http.problem_details": {"cause": "NRF_UNAVAILABLE"},
                    "test.ue": "ue-a",
                },
            }
        )
        reset_retry = _event(analysis_id, 12, "POST /nnrf-disc/v1/nf-instances", "ue-a", protocol="HTTP2").model_copy(
            update={
                "identifiers": EventIdentifiers(http2_key="stream-2", correlation_id="corr-2"),
                "attributes": {
                    "http.method": "POST",
                    "http.path": "/nnrf-disc/v1/nf-instances",
                    "http.sbi_api": "nnrf-disc",
                    "http.completion_state": "reset",
                    "http.reset": True,
                    "test.ue": "ue-a",
                },
            }
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            attempt, reader = _detector_attempt_fixture(
                run_dir,
                analysis_id,
                [request_event, response_event, reset_retry],
                outcome="timed_out",
                completion_reason="response_timeout",
            )
            result = find_http_failures(
                FindHTTPFailuresRequest(
                    analysis_id=analysis_id,
                    attempt=attempt,
                    attempts_revision="sha256:test-attempts",
                    primary_reader=reader,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized/diagnostics/http",
                )
            )

        categories = {candidate.category for candidate in result.candidates}
        self.assertIn("http_status_failure", categories)
        self.assertIn("http_reset", categories)
        status_candidate = next(candidate for candidate in result.candidates if candidate.category == "http_status_failure")
        self.assertEqual(status_candidate.source_event_ids, [request_event.event_id, response_event.event_id])
        self.assertEqual(status_candidate.observed["problem_details"], {"cause": "NRF_UNAVAILABLE"})
        self.assertEqual(len(result.retry_groups), 1)
        self.assertEqual(result.retry_groups[0].frames, [10, 11, 12])
        self.assertEqual(result.dependency_suspicions[0].reason_code, "nrf_policy_backed_http_status_failure")

    def test_t07_distinguishes_successful_causes_and_reachability_failures(self) -> None:
        analysis_id = UUID("10000000-0000-0000-0000-000000000102")
        request_event = _event(analysis_id, 20, "REGISTRATION_REQUEST", "ue-a")
        successful_cause = _event(analysis_id, 21, "PDU_SESSION_RESOURCE_SETUP_RESPONSE", "ue-a", protocol="NGAP").model_copy(
            update={"outcome": "success", "attributes": {"ngap.cause": "successful", "test.ue": "ue-a"}}
        )
        reachability_failure = _event(analysis_id, 22, "PAGING_FAILURE", "ue-a", protocol="NGAP").model_copy(
            update={"outcome": "failure", "attributes": {"ngap.cause": "UE_NOT_REACHABLE", "test.ue": "ue-a"}}
        )
        profile = _profile(terminal_on_trigger=False).model_copy(
            update={
                "failure_terminals": [EventMatcher(protocol="NGAP", message_types=["PAGING_FAILURE"])],
                "stages": [
                    StageDefinition(
                        stage_id="paging",
                        name="Paging",
                        order=1,
                        event_matchers=[EventMatcher(protocol="NGAP", message_types=["PAGING_FAILURE"])],
                        terminal_failure=True,
                    )
                ],
            }
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            attempt, reader = _detector_attempt_fixture(run_dir, analysis_id, [request_event, successful_cause, reachability_failure])
            result = find_nas_ngap_failures(
                FindNASNGAPFailuresRequest(
                    analysis_id=analysis_id,
                    attempt=attempt,
                    attempts_revision="sha256:test-attempts",
                    primary_reader=reader,
                    profile=profile,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized/diagnostics/nas",
                )
            )

        self.assertEqual([candidate.category for candidate in result.candidates], ["reachability_failure"])
        self.assertEqual(result.candidates[0].observed["profile_release"], "R17")
        self.assertEqual(len(result.request_only_observations), 1)
        self.assertEqual(result.terminal_effects[0].event_id, reachability_failure.event_id)

    def test_t08_pfcp_pairing_session_reports_and_tunnel_direction(self) -> None:
        analysis_id = UUID("10000000-0000-0000-0000-000000000103")
        success_request = _pfcp_event(analysis_id, 30, "SESSION_ESTABLISHMENT_REQUEST", 10, "seid-1")
        success_response = _pfcp_event(
            analysis_id,
            31,
            "SESSION_ESTABLISHMENT_RESPONSE",
            10,
            "seid-1",
            outcome="success",
            attrs={"pfcp.cause": "REQUEST_ACCEPTED"},
        )
        failed_response = _pfcp_event(
            analysis_id,
            32,
            "SESSION_MODIFICATION_RESPONSE",
            11,
            "seid-2",
            outcome="failure",
            attrs={"pfcp.cause": "REQUEST_REJECTED"},
        )
        session_report = _pfcp_event(
            analysis_id,
            33,
            "SESSION_REPORT_REQUEST",
            12,
            "seid-2",
            outcome="failure",
            attrs={"pfcp.report_type": "DOWNLINK_DATA_FAILURE", "pfcp.cause": "NO_RESOURCES"},
        )
        tunnel_mismatch = _pfcp_event(
            analysis_id,
            34,
            "SESSION_ESTABLISHMENT_REQUEST",
            13,
            "seid-3",
            attrs={"pfcp.expected_tunnel_role": "uplink", "pfcp.f_teid_direction": "downlink"},
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            attempt, reader = _detector_attempt_fixture(
                run_dir,
                analysis_id,
                [success_request, success_response, failed_response, session_report, tunnel_mismatch],
            )
            result = find_pfcp_failures(
                FindPFCPFailuresRequest(
                    analysis_id=analysis_id,
                    attempt=attempt,
                    attempts_revision="sha256:test-attempts",
                    primary_reader=reader,
                    identity_graph=IdentityGraphReader("sha256:test-identity", [], [], [], [], [], []),
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized/diagnostics/pfcp",
                )
            )

        outcomes = {transaction.key: transaction.outcome for transaction in result.transactions}
        self.assertIn("success", outcomes.values())
        self.assertIn("failure", outcomes.values())
        categories = {candidate.category for candidate in result.candidates}
        self.assertIn("pfcp_failure", categories)
        self.assertIn("pfcp_session_report_failure", categories)
        self.assertIn("pfcp_tunnel_direction_mismatch", categories)
        self.assertEqual(len(result.session_reports), 1)
        self.assertIn("failure", {check.outcome for check in result.consistency_checks})
        self.assertGreaterEqual(len(result.association_observations), 5)

    def test_t09_profile_dag_visibility_and_candidate_linkage(self) -> None:
        analysis_id = UUID("10000000-0000-0000-0000-000000000104")
        request_event = _event(analysis_id, 10, "REGISTRATION_REQUEST", "ue-a")
        smf_failure = _event(analysis_id, 20, "POST /nsmf-pdusession/v1/sm-contexts", "ue-a", protocol="HTTP2").model_copy(
            update={
                "outcome": "failure",
                "identifiers": EventIdentifiers(http2_key="stream-1"),
                "attributes": {
                    "http.method": "POST",
                    "http.path": "/nsmf-pdusession/v1/sm-contexts",
                    "http.sbi_api": "nsmf-pdusession",
                    "http.status": 500,
                    "http.completion_state": "complete",
                    "test.ue": "ue-a",
                    "test.access": "ue-a",
                },
            }
        )
        profile = ResolvedProcedureProfile(
            profile_id="test.registration",
            version="1",
            release="R17",
            deployment_profile="test",
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
                    stage_id="smf.create",
                    name="SMF Create Context",
                    order=2,
                    predecessor_ids=["registration.request"],
                    timeout_seconds=Decimal("1.0"),
                    visibility_requirements=[
                        VisibilityRequirement(domain="sbi_api", key="nsmf-pdusession"),
                    ],
                ),
                StageDefinition(
                    stage_id="registration.accept",
                    name="Registration Accept",
                    order=3,
                    predecessor_ids=["smf.create"],
                    terminal_success=True,
                ),
                StageDefinition(
                    stage_id="nudm.lookup",
                    name="UDM Lookup",
                    order=4,
                    visibility_requirements=[
                        VisibilityRequirement(domain="sbi_api", key="nudm-uecm"),
                    ],
                ),
            ],
            source_checksum="test-profile-sha",
            resolved_revision="test-profile-revision",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            attempt, reader = _detector_attempt_fixture(run_dir, analysis_id, [request_event, smf_failure])
            attempt = attempt.model_copy(
                update={
                    "transitions": [
                        StateTransition(
                            transition_id=deterministic_uuid(analysis_id, "transition", "registration.request"),
                            stage_id="registration.request",
                            stage_name="Registration Request",
                            event_id=request_event.event_id,
                            frame=request_event.frame,
                            timestamp=request_event.timestamp,
                        )
                    ],
                    "visibility": InterfaceVisibility(
                        reference_points={"N1": "visible"},
                        apis={"nsmf-pdusession": "visible", "nudm-uecm": "not_observed"},
                    ),
                }
            )
            http_result = find_http_failures(
                FindHTTPFailuresRequest(
                    analysis_id=analysis_id,
                    attempt=attempt,
                    attempts_revision="sha256:test-attempts",
                    primary_reader=reader,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized/diagnostics/http",
                )
            )
            smf_candidate = http_result.candidates[0].model_copy(
                update={
                    "component": "smf.create",
                    "observed": {**http_result.candidates[0].observed, "stage_id": "smf.create"},
                }
            )
            http_result = http_result.model_copy(update={"candidates": [smf_candidate]})
            nas_result = find_nas_ngap_failures(
                FindNASNGAPFailuresRequest(
                    analysis_id=analysis_id,
                    attempt=attempt,
                    attempts_revision="sha256:test-attempts",
                    primary_reader=reader,
                    profile=profile,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized/diagnostics/nas",
                )
            )
            pfcp_result = find_pfcp_failures(
                FindPFCPFailuresRequest(
                    analysis_id=analysis_id,
                    attempt=attempt,
                    attempts_revision="sha256:test-attempts",
                    primary_reader=reader,
                    identity_graph=IdentityGraphReader("sha256:test-identity", [], [], [], [], [], []),
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized/diagnostics/pfcp",
                )
            )
            result = detect_missing_transitions(
                DetectMissingTransitionsRequest(
                    analysis_id=analysis_id,
                    attempt=attempt,
                    attempts_revision="sha256:test-attempts",
                    profile=profile,
                    http_result=http_result,
                    nas_ngap_result=nas_result,
                    pfcp_result=pfcp_result,
                    run_dir=run_dir,
                    diagnostics_dir=run_dir / "normalized/diagnostics/missing",
                )
            )

        stages = {stage.stage_id: stage for stage in result.stage_results}
        self.assertEqual(stages["registration.request"].state, "completed")
        self.assertEqual(stages["smf.create"].state, "suppressed")
        self.assertEqual(result.linked_suppressions[0].explicit_candidate_ids, [smf_candidate.candidate_id])
        self.assertEqual(stages["registration.accept"].state, "skipped")
        self.assertIn("predecessor_not_reached", stages["registration.accept"].reason_codes)
        self.assertEqual(stages["nudm.lookup"].state, "skipped")
        self.assertIn("visibility_not_satisfied", stages["nudm.lookup"].reason_codes)
        self.assertEqual(result.candidates, [])

    def test_t04_unique_trigger_assignment_and_overlapping_ues_round_trip(self) -> None:
        analysis_id = UUID("10000000-0000-0000-0000-000000000001")
        events = [
            _event(analysis_id, 10, "REGISTRATION_REQUEST", "ue-a"),
            _event(analysis_id, 11, "REGISTRATION_REQUEST", "ue-b"),
            _event(analysis_id, 12, "AUTHENTICATION_RESPONSE", "ue-a"),
            _event(analysis_id, 13, "AUTHENTICATION_RESPONSE", "ue-b"),
        ]
        profile = _profile(terminal_on_trigger=False)

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            result = _segment_fixture(run_dir, analysis_id, events, profile, max_open_attempts_per_ue=1)
            reader = open_attempts_reader(result)

            self.assertEqual(result.attempt_count, 2)
            self.assertEqual(result.ambiguous_assignment_count, 0)
            self.assertEqual(result.unassigned_event_count, 0)
            self.assertEqual(len(reader.assignments), len(events))
            self.assertEqual(len({item.assignment_id for item in reader.assignments}), len(events))

            attempts_by_ue = {str(attempt.ue_id): attempt for attempt in reader.attempts}
            self.assertEqual(len(attempts_by_ue), 2)
            for attempt in reader.attempts:
                self.assertEqual(attempt.sequence_number, 1)
                self.assertEqual(len(attempt.event_ids), 2)
                self.assertEqual(
                    attempt.event_ids,
                    [assignment.event_id for assignment in reader.assignments_for_attempt(attempt.attempt_id)],
                )

            persisted = [
                ProcedureAttempt.model_validate(record)
                for record in iter_jsonl(run_dir / "normalized/attempts/attempts.jsonl")
            ]
            self.assertEqual(reader.attempts, persisted)

    def test_t04_retry_and_sequence_metadata_are_persisted_deterministically(self) -> None:
        analysis_id = UUID("10000000-0000-0000-0000-000000000002")
        events = [
            _event(analysis_id, 20, "REGISTRATION_REQUEST", "ue-a"),
            _event(analysis_id, 30, "REGISTRATION_REQUEST", "ue-a"),
        ]
        profile = _profile(terminal_on_trigger=True)

        with tempfile.TemporaryDirectory() as first_tmpdir, tempfile.TemporaryDirectory() as second_tmpdir:
            first_dir = Path(first_tmpdir)
            second_dir = Path(second_tmpdir)
            first_result = _segment_fixture(first_dir, analysis_id, events, profile)
            second_result = _segment_fixture(second_dir, analysis_id, events, profile)
            first_reader = open_attempts_reader(first_result)

            self.assertEqual(first_result.retry_count, 1)
            self.assertEqual([attempt.sequence_number for attempt in first_reader.attempts], [1, 2])
            self.assertEqual(first_reader.attempts[0].retries, [])
            self.assertEqual(len(first_reader.attempts[1].retries), 1)
            retry = first_reader.attempts[1].retries[0]
            self.assertEqual(retry.prior_attempt_id, first_reader.attempts[0].attempt_id)
            self.assertEqual(retry.next_attempt_id, first_reader.attempts[1].attempt_id)
            self.assertIsNone(first_reader.attempts[1].parent_attempt_id)
            self.assertEqual(first_reader.attempts[0].child_attempt_ids, [])
            self.assertEqual(len(first_reader.relationships), 1)
            self.assertEqual(first_reader.relationships[0].relation, "retry_of")

            first_bytes = (first_dir / "normalized/attempts/attempts.jsonl").read_bytes()
            second_bytes = (second_dir / "normalized/attempts/attempts.jsonl").read_bytes()
            self.assertEqual(first_bytes, second_bytes)
            self.assertEqual(first_result.revision, second_result.revision)

    def test_t04_low_confidence_trigger_does_not_open_attempt(self) -> None:
        analysis_id = UUID("10000000-0000-0000-0000-000000000003")
        event = _event(
            analysis_id,
            40,
            "Nsmf_PDUSession_CreateSMContext",
            "ue-a",
            protocol="HTTP2",
        )
        profile = _profile(
            terminal_on_trigger=False,
            protocol="HTTP2",
            message_type="Nsmf_PDUSession_CreateSMContext",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            result = _segment_fixture(
                Path(tmpdir),
                analysis_id,
                [event],
                profile,
                minimum_assignment_confidence=Decimal("0.90"),
            )
            reader = open_attempts_reader(result)

            self.assertEqual(result.attempt_count, 0)
            self.assertEqual(result.unassigned_event_count, 1)
            self.assertEqual(reader.attempts, [])
            self.assertEqual(reader.assignments, [])

    def test_t04_response_timeout_and_capture_boundary_are_distinct(self) -> None:
        analysis_id = UUID("10000000-0000-0000-0000-000000000004")
        profile = _profile(terminal_on_trigger=False)
        events = [
            _event(analysis_id, 1, "REGISTRATION_REQUEST", "ue-a"),
            _event(analysis_id, 200, "REGISTRATION_REQUEST", "ue-b"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            reader = open_attempts_reader(
                _segment_fixture(
                    Path(tmpdir),
                    analysis_id,
                    events,
                    profile,
                    default_response_timeout_seconds=Decimal("5"),
                )
            )

        attempts = {str(attempt.ue_id): attempt for attempt in reader.attempts}
        self.assertEqual(len(attempts), 2)
        first = min(reader.attempts, key=lambda item: item.start_frame)
        second = max(reader.attempts, key=lambda item: item.start_frame)
        self.assertEqual((first.outcome, first.completion_reason), ("timed_out", "response_timeout"))
        self.assertEqual((second.outcome, second.completion_reason), ("incomplete_capture", "capture_ended_before_terminal"))

    def test_t04_conditional_stage_status_and_profile_alternatives(self) -> None:
        analysis_id = UUID("10000000-0000-0000-0000-000000000005")
        primary = _profile(terminal_on_trigger=True)
        primary.stages.extend(
            [
                StageDefinition(
                    stage_id="periodic_only",
                    name="Periodic Only",
                    order=2,
                    applicability="conditional",
                    applicability_condition={"op": "eq", "fact": "request.registration_type", "value": "periodic_update"},
                ),
                StageDefinition(
                    stage_id="history_dependent",
                    name="History Dependent",
                    order=3,
                    applicability="conditional",
                    applicability_condition={"op": "eq", "fact": "attempt.has_prior_registration", "value": True},
                ),
            ]
        )
        alternative = primary.model_copy(
            deep=True,
            update={"profile_id": "test.alternative", "resolved_revision": "alternative-revision"},
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            result = _segment_fixture(
                Path(tmpdir),
                analysis_id,
                [_event(analysis_id, 10, "REGISTRATION_REQUEST", "ue-a")],
                [primary, alternative],
            )
            attempt = open_attempts_reader(result).attempts[0]

        statuses = {item.stage_id: item.status for item in attempt.stage_timings}
        self.assertEqual(statuses["periodic_only"], "skipped")
        self.assertEqual(statuses["history_dependent"], "inconclusive")
        self.assertEqual(attempt.profile_selection_status, "ambiguous")
        self.assertEqual(len(attempt.profile_alternatives), 1)
        self.assertIn("T04_STAGE_APPLICABILITY_UNKNOWN", attempt.issue_codes)

    def test_t04_resolved_registry_loader_verifies_files_and_dimensions(self) -> None:
        profile = _profile(terminal_on_trigger=False)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            profile_path = root / "registration.json"
            profile_path.write_text(json.dumps(profile.model_dump(mode="json")), encoding="utf-8")
            registry_path = root / "registry.json"
            registry_path.write_text(
                json.dumps(
                    {
                        "schema_version": "2.0",
                        "registry_version": "fixture-1",
                        "release": "R17",
                        "deployment_profile": "test",
                        "profile_files": [
                            {"relative_path": profile_path.name, "sha256": sha256_file(profile_path)},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            registry = load_resolved_profile_registry(
                registry_path,
                expected_release="R17",
                expected_deployment_profile="test",
            )
            self.assertEqual([item.profile_id for item in registry.profiles], [profile.profile_id])

            profile_path.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                load_resolved_profile_registry(registry_path)

    def test_t04_profile_relationship_rules_cover_nesting_transfer_and_deregistration(self) -> None:
        analysis_id = UUID("10000000-0000-0000-0000-000000000006")
        events = [
            _event(analysis_id, 10, "REGISTRATION_REQUEST", "ue-a", access_key="access-a"),
            _event(analysis_id, 11, "PDU_SESSION_ESTABLISHMENT", "ue-a", access_key="access-a"),
            _event(analysis_id, 12, "HANDOVER_REQUIRED", "ue-a", access_key="access-b", protocol="NGAP"),
            _event(analysis_id, 13, "DEREGISTRATION_REQUEST", "ue-a", access_key="access-b"),
        ]
        registration = _profile(terminal_on_trigger=False)
        pdu = _profile(terminal_on_trigger=True, message_type="PDU_SESSION_ESTABLISHMENT").model_copy(
            update={
                "profile_id": "test.pdu",
                "procedure_type": "PDU_SESSION_ESTABLISHMENT",
                "parent_profile_ids": [registration.profile_id],
            }
        )
        transfer = _profile(terminal_on_trigger=True, protocol="NGAP", message_type="HANDOVER_REQUIRED").model_copy(
            update={
                "profile_id": "test.handover",
                "procedure_type": "HANDOVER",
                "transfer_from_profile_ids": [registration.profile_id],
            }
        )
        deregistration = _profile(terminal_on_trigger=True, message_type="DEREGISTRATION_REQUEST").model_copy(
            update={
                "profile_id": "test.deregistration",
                "procedure_type": "DEREGISTRATION",
                "closes_profile_ids": [transfer.profile_id, registration.profile_id],
            }
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            reader = open_attempts_reader(
                _segment_fixture(
                    Path(tmpdir),
                    analysis_id,
                    events,
                    [registration, pdu, transfer, deregistration],
                )
            )

        attempts_by_profile = {attempt.profile_id: attempt for attempt in reader.attempts}
        self.assertEqual(attempts_by_profile[pdu.profile_id].parent_attempt_id, attempts_by_profile[registration.profile_id].attempt_id)
        self.assertIn(attempts_by_profile[pdu.profile_id].attempt_id, attempts_by_profile[registration.profile_id].child_attempt_ids)

        relationships = {(item.relation, item.left_attempt_id, item.right_attempt_id) for item in reader.relationships}
        self.assertIn(
            (
                "parent_child",
                attempts_by_profile[registration.profile_id].attempt_id,
                attempts_by_profile[pdu.profile_id].attempt_id,
            ),
            relationships,
        )
        self.assertIn(
            (
                "access_transfer",
                attempts_by_profile[transfer.profile_id].attempt_id,
                attempts_by_profile[registration.profile_id].attempt_id,
            ),
            relationships,
        )
        self.assertIn(
            (
                "supersedes",
                attempts_by_profile[deregistration.profile_id].attempt_id,
                attempts_by_profile[transfer.profile_id].attempt_id,
            ),
            relationships,
        )
        self.assertNotIn(
            (
                "supersedes",
                attempts_by_profile[deregistration.profile_id].attempt_id,
                attempts_by_profile[registration.profile_id].attempt_id,
            ),
            relationships,
        )

def _event(
    analysis_id: UUID,
    frame: int,
    message_type: str,
    ue_key: str,
    *,
    protocol: str = "NAS",
    access_key: str | None = None,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=deterministic_uuid(analysis_id, "test-event", frame, message_type, ue_key),
        analysis_id=analysis_id,
        protocol=protocol,
        frame=frame,
        timestamp=Decimal(frame) / Decimal("10"),
        timestamp_precision="milliseconds",
        direction="UE_TO_NETWORK",
        message_type=message_type,
        procedure="test",
        outcome="request",
        identifiers=EventIdentifiers(),
        attributes={"test.ue": ue_key, "test.access": access_key or ue_key},
    )


def _profile(
    *,
    terminal_on_trigger: bool,
    protocol: str = "NAS",
    message_type: str = "REGISTRATION_REQUEST",
) -> ResolvedProcedureProfile:
    matcher = EventMatcher(protocol=protocol, message_types=[message_type])
    return ResolvedProcedureProfile(
        profile_id=f"test.{protocol.lower()}.{message_type.lower()}",
        version="1",
        release="R17",
        deployment_profile="test",
        procedure_type="INITIAL_REGISTRATION" if protocol == "NAS" else "PDU_SESSION_ESTABLISHMENT",
        trigger_matchers=[matcher],
        stages=[
            StageDefinition(
                stage_id="trigger",
                name="Trigger",
                order=1,
                event_matchers=[matcher],
                terminal_failure=terminal_on_trigger,
            )
        ],
        failure_terminals=[matcher] if terminal_on_trigger else [],
        source_checksum="test-profile-sha",
        resolved_revision="test-profile-revision",
    )


def _detector_attempt_fixture(
    run_dir: Path,
    analysis_id: UUID,
    events: list[CanonicalEvent],
    *,
    outcome: str = "failed",
    completion_reason: str = "failure_terminal",
) -> tuple[ProcedureAttempt, JsonlPrimaryEventReader]:
    events_path = run_dir / "fixture-detector-events.jsonl"
    events_path.write_bytes(b"".join(compact_json_bytes(event) + b"\n" for event in events))
    timestamped_events = [event for event in events if event.timestamp is not None]
    attempt = ProcedureAttempt(
        attempt_id=deterministic_uuid(analysis_id, "detector-attempt", *(event.event_id for event in events)),
        analysis_id=analysis_id,
        profile_id="test.detector",
        procedure_type="TEST_PROCEDURE",
        sequence_number=1,
        start_frame=min(event.frame for event in events),
        end_frame=max(event.frame for event in events),
        start_timestamp=min((event.timestamp for event in timestamped_events), default=None),
        end_timestamp=max((event.timestamp for event in timestamped_events), default=None),
        trigger_event_ids=[events[0].event_id],
        event_ids=[event.event_id for event in events],
        outcome=outcome,
        completion_reason=completion_reason,
        assignment_confidence="high",
    )
    return attempt, JsonlPrimaryEventReader("sha256:test-normalization", events_path)


def _pfcp_event(
    analysis_id: UUID,
    frame: int,
    message_type: str,
    sequence: int,
    seid: str,
    *,
    outcome: str = "request",
    attrs: dict[str, object] | None = None,
) -> CanonicalEvent:
    attributes = {"test.ue": "ue-a", "test.access": "ue-a"}
    attributes.update(attrs or {})
    return _event(analysis_id, frame, message_type, "ue-a", protocol="PFCP").model_copy(
        update={
            "outcome": outcome,
            "src": Endpoint(ip="10.0.0.1", port=8805),
            "dst": Endpoint(ip="10.0.0.2", port=8805),
            "identifiers": EventIdentifiers(pfcp_sequence=sequence, cp_seid=seid),
            "attributes": attributes,
        }
    )


def _segment_fixture(
    run_dir: Path,
    analysis_id: UUID,
    events: list[CanonicalEvent],
    profile: ResolvedProcedureProfile | list[ResolvedProcedureProfile],
    *,
    minimum_assignment_confidence: Decimal = Decimal("0.70"),
    max_open_attempts_per_ue: int = 100,
    default_response_timeout_seconds: Decimal = Decimal("10"),
):
    events_path = run_dir / "fixture-primary-events.jsonl"
    events_path.write_bytes(b"".join(compact_json_bytes(event) + b"\n" for event in events))
    normalization_revision = "sha256:test-normalization"
    identity_revision = "sha256:test-identity"
    source_sha256 = "test-source-sha256"
    normalization_manifest = _descriptor(
        "normalized/diagnostics/normalization_manifest.json",
        "normalization_manifest",
        "T02",
        parent_source_sha256=source_sha256,
        revision=normalization_revision,
    )
    normalization = NormalizeEventsResult(
        analysis_id=analysis_id,
        status="success",
        revision=normalization_revision,
        manifest=normalization_manifest,
        artifacts=[],
        event_count=len(events),
        partition_counts={"primary": len(events), "nrf": 0, "udr": 0},
        protocol_counts={protocol: sum(event.protocol == protocol for event in events) for protocol in {event.protocol for event in events}},
        source_record_counts={},
        unknown_field_counts={},
        warning_counts={},
        elapsed_ms=0,
        issues=[],
        manifest_path=run_dir / normalization_manifest.relative_path,
    )
    primary_reader = JsonlPrimaryEventReader(normalization_revision, events_path)
    identity_graph, identity_result = _identity_fixture(
        run_dir,
        analysis_id,
        identity_revision,
        normalization_manifest.sha256,
        events,
    )
    profiles = profile if isinstance(profile, list) else [profile]
    registry = ResolvedProfileRegistry(
        registry_version="test-registry",
        sha256="test-registry-sha",
        release="R17",
        deployment_profile="test",
        profiles=profiles,
    )
    capture = CaptureMetadata(
        first_frame=min(event.frame for event in events),
        last_frame=max(event.frame for event in events),
        first_timestamp=min(event.timestamp for event in events if event.timestamp is not None),
        last_timestamp=max(event.timestamp for event in events if event.timestamp is not None),
        packet_count=len(events),
        source_sha256=source_sha256,
    )
    return segment_attempts(
        SegmentAttemptsRequest(
            analysis_id=analysis_id,
            normalization=normalization,
            identity_result=identity_result,
            primary_reader=primary_reader,
            identity_graph=identity_graph,
            capture=capture,
            profile_registry=registry,
            run_dir=run_dir,
            attempts_dir=run_dir / "normalized/attempts",
            indexes_dir=run_dir / "indexes",
            policy_versions={"profile_registry": registry.registry_version},
            config=AttemptSegmentationConfig(
                minimum_assignment_confidence=minimum_assignment_confidence,
                max_open_attempts_per_ue=max_open_attempts_per_ue,
                default_response_timeout_seconds=default_response_timeout_seconds,
            ),
        )
    )


def _identity_fixture(
    run_dir: Path,
    analysis_id: UUID,
    revision: str,
    parent_source_sha256: str,
    events: list[CanonicalEvent],
) -> tuple[IdentityGraphReader, BuildIdentityGraphResult]:
    observations: list[IdentifierObservation] = []
    nodes: list[IdentityNode] = []
    for ue_key in sorted({str(event.attributes["test.ue"]) for event in events}):
        ue_events = [event for event in events if event.attributes["test.ue"] == ue_key]
        for node_type, role, group_key in (
            ("UE", "UE", ue_key),
            ("PDU_SESSION", "SESSION", ue_key),
        ):
            observation_ids = []
            for event in ue_events:
                observation_id = deterministic_uuid(
                    analysis_id,
                    "test-observation",
                    group_key,
                    node_type,
                    event.event_id,
                )
                observation_ids.append(observation_id)
                observations.append(
                    IdentifierObservation(
                        observation_id=observation_id,
                        event_id=event.event_id,
                        frame=event.frame,
                        timestamp=event.timestamp,
                        timestamp_precision=event.timestamp_precision,
                        kind=f"test_{node_type.lower()}",
                        node_type=node_type,
                        lookup_value=group_key,
                        sensitive=False,
                        scope_key=group_key,
                        field_path="$.attributes.test.ue",
                        role=role,
                        confidence=Decimal("1.0"),
                        valid_from_frame=min(item.frame for item in ue_events),
                        valid_to_frame=max(item.frame for item in ue_events),
                    )
                )
            nodes.append(
                IdentityNode(
                    node_id=deterministic_uuid(analysis_id, "test-node", group_key, node_type),
                    node_type=node_type,
                    first_frame=min(item.frame for item in ue_events),
                    last_frame=max(item.frame for item in ue_events),
                    observation_ids=observation_ids,
                )
            )
        for access_key in sorted({str(event.attributes.get("test.access", ue_key)) for event in ue_events}):
            access_events = [event for event in ue_events if str(event.attributes.get("test.access", ue_key)) == access_key]
            observation_ids = []
            for event in access_events:
                observation_id = deterministic_uuid(
                    analysis_id,
                    "test-observation",
                    access_key,
                    "ACCESS_CONTEXT",
                    event.event_id,
                )
                observation_ids.append(observation_id)
                observations.append(
                    IdentifierObservation(
                        observation_id=observation_id,
                        event_id=event.event_id,
                        frame=event.frame,
                        timestamp=event.timestamp,
                        timestamp_precision=event.timestamp_precision,
                        kind="test_access_context",
                        node_type="ACCESS_CONTEXT",
                        lookup_value=access_key,
                        sensitive=False,
                        scope_key=access_key,
                        field_path="$.attributes.test.access",
                        role="ACCESS_CONTEXT",
                        confidence=Decimal("1.0"),
                        valid_from_frame=min(item.frame for item in access_events),
                        valid_to_frame=max(item.frame for item in access_events),
                    )
                )
            nodes.append(
                IdentityNode(
                    node_id=deterministic_uuid(analysis_id, "test-node", access_key, "ACCESS_CONTEXT"),
                    node_type="ACCESS_CONTEXT",
                    first_frame=min(item.frame for item in access_events),
                    last_frame=max(item.frame for item in access_events),
                    observation_ids=observation_ids,
                )
            )

    manifest = _descriptor(
        "normalized/identity/identity_manifest.json",
        "identity_manifest",
        "T03",
        parent_source_sha256=parent_source_sha256,
        revision=revision,
    )
    result = BuildIdentityGraphResult(
        analysis_id=analysis_id,
        status="success",
        revision=revision,
        manifest=manifest,
        artifacts=[],
        observation_count=len(observations),
        ue_nodes=sum(node.node_type == "UE" for node in nodes),
        pdu_session_nodes=sum(node.node_type == "PDU_SESSION" for node in nodes),
        access_context_nodes=sum(node.node_type == "ACCESS_CONTEXT" for node in nodes),
        sm_context_nodes=0,
        pfcp_session_nodes=0,
        accepted_edges=0,
        ambiguous_edges=0,
        conflicts=0,
        registration_state_intervals=0,
        topology_intervals=0,
        fault_domain_maps=0,
        warning_counts={},
        elapsed_ms=0,
        issues=[],
        manifest_path=run_dir / manifest.relative_path,
    )
    return IdentityGraphReader(revision, nodes, [], observations, [], [], []), result


def _descriptor(
    relative_path: str,
    artifact_type: str,
    creation_stage: str,
    *,
    parent_source_sha256: str | None,
    revision: str,
) -> ArtifactDescriptor:
    return ArtifactDescriptor(
        artifact_id=str(deterministic_uuid(UUID("10000000-0000-0000-0000-000000000000"), relative_path)),
        relative_path=relative_path,
        artifact_type=artifact_type,
        media_type="application/json",
        format_schema_version="2.0",
        sha256=f"sha256:{artifact_type}",
        byte_size=0,
        record_count=1,
        creation_stage=creation_stage,
        parent_source_sha256=parent_source_sha256,
        revision=revision,
    )


if __name__ == "__main__":
    unittest.main()
