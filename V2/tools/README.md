# Tool Implementation Specifications

This directory contains one implementation-ready specification per harness tool. The detailed files are normative for implementation; `../requirement.md` remains the authoritative system-level tool list and scope.

| Tool | Specification | Status |
|---|---|---|
| T01 `decode_capture` | `T01_decode_capture.md` | Reviewed implementation specification |
| T02 `normalize_events` | `T02_normalize_events.md` | Reviewed implementation specification |
| T03 `build_identity_graph` | `T03_build_identity_graph.md` | Reviewed implementation specification |
| T04 `segment_attempts` | `T04_segment_attempts.md` | Reviewed implementation specification |
| T05 `get_ue_request` | `T05_get_ue_request.md` | Reviewed implementation specification |
| T06 `find_http_failures` | `T06_find_http_failures.md` | Reviewed implementation specification |
| T07 `find_nas_ngap_failures` | `T07_find_nas_ngap_failures.md` | Reviewed implementation specification |
| T08 `find_pfcp_failures` | `T08_find_pfcp_failures.md` | Reviewed implementation specification |
| T09 `detect_missing_transitions` | `T09_detect_missing_transitions.md` | Reviewed implementation specification |
| T10 `get_attempt_timeline` | `T10_get_attempt_timeline.md` | Reviewed implementation specification |
| T11 `compare_attempts` | `T11_compare_attempts.md` | Reviewed implementation specification |
| T12 `rank_root_causes` | `T12_rank_root_causes.md` | Reviewed implementation specification |
| T13 `parse_scenario` | `T13_parse_scenario.md` | Reviewed implementation specification |
| T14 `validate_scenario` | `T14_validate_scenario.md` | Reviewed implementation specification |
| T15 `build_evidence_packet` | `T15_build_evidence_packet.md` | Reviewed implementation specification |
| T16 `generate_diagnosis` | `T16_generate_diagnosis.md` | Reviewed implementation specification |
| T17 `render_report` | `T17_render_report.md` | Reviewed implementation specification |
| T18 `lookup_full_evidence` | `T18_lookup_full_evidence.md` | Reviewed implementation specification |
| T19 `get_packet_context` | `T19_get_packet_context.md` | Reviewed implementation specification |
| T20 `targeted_redecode` | `T20_targeted_redecode.md` | Reviewed implementation specification |
| T21 `classify_capture_phases` | `T21_classify_capture_phases.md` | Reviewed implementation specification |
| T22 `build_nf_lifecycle` | `T22_build_nf_lifecycle.md` | Reviewed implementation specification |
| T23 `assess_background_impact` | `T23_assess_background_impact.md` | Reviewed implementation specification |
| T24 `inspect_nrf_flow` | `T24_inspect_nrf_flow.md` | Reviewed implementation specification |
| T25 `inspect_udr_flow` | `T25_inspect_udr_flow.md` | Reviewed implementation specification |

Each specification defines the tool-specific subset of:

- Purpose, non-goals, and access boundaries.
- Typed input and output contracts.
- Algorithms and deterministic decision rules.
- Artifact and index behavior.
- Error and partial-result semantics.
- Security, privacy, and resource constraints.
- Proposed source files.
- Unit/integration tests and acceptance criteria.

Cross-tool invariants remain defined in `../architecture.md` and `../LLD.md`, especially primary versus NRF/UDR reader isolation and the single bounded dependency-evidence round.

## Review Quality Bar

Each reviewed specification must include, where applicable:

- Explicit purpose, non-goals, ownership, and caller capability boundary.
- Typed request/result and important persisted/internal models.
- Deterministic algorithms, precedence, scoring, state, or correlation rules.
- Output artifacts, indexes, manifests, checksums, revisions, and atomic publication.
- Idempotency, pagination, bounded-window, or caching behavior.
- Detailed failure/partial/inconclusive semantics.
- Performance/resource targets and observability fields/metrics.
- Security/privacy controls and untrusted-input handling.
- Proposed implementation files and implementation sequence.
- Unit, integration, negative/security, and acceptance tests.
- Concrete acceptance criteria suitable for implementation review.

T01-T25 were reviewed against this quality bar. Tool-specific sections may differ because a pure detector does not need the same process/artifact contract as the Go decoder, but omitted concerns must be intentionally not applicable rather than unspecified.
