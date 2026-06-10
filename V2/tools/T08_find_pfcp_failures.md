# T08 `find_pfcp_failures` Implementation Specification

## 1. Purpose

`find_pfcp_failures` detects N4/PFCP session-programming failures correlated to one UE procedure attempt. It covers explicit response rejection, timeout/retry exhaustion, session identity inconsistency, rule-programming defects, and tunnel mismatch with NGAP/session expectations.

T08 emits candidates. It does not rank them against NAS/NGAP/HTTP candidates.

## 2. Non-Goals

T08 must not:

- Treat routine PFCP heartbeat traffic as a session failure.
- Assume a changed SEID or TEID is invalid without scope and procedure context.
- Associate PFCP solely by timestamp.
- Read NRF/UDR partitions.
- Infer a missing response when capture visibility is insufficient.
- Validate full UPF packet forwarding/data-plane traffic in V2.1.

## 3. Inputs and Boundary

- One T04 attempt and related session/context identities.
- Attempt-assigned PFCP events from `PrimaryEventReader`.
- Relevant NGAP/NAS/primary SBI event summaries for consistency checks.
- The shared attempt-scoped `DetectionContext` (`LLD.md` section 11), carrying
  capture bounds (required for `request_only_capture_boundary` and timeout
  decisions), the T21 phase reader, reference-point/SBI visibility and the resolved
  PFCP message/cause/timeout policy handles.

T08 may use T18 for exact PFCP IEs referenced by assigned events. It cannot request broad packet context itself.

## 4. Python Tool Contract

```python
class FindPFCPFailuresRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt: ProcedureAttempt
    pfcp_event_ids: list[UUID]
    correlated_event_ids: list[UUID]
    context: DetectionContext


class FindPFCPFailuresResult(BaseModel):
    schema_version: Literal["2.0"]
    attempt_id: UUID
    candidates: list[FailureCandidate]
    transactions: list[PFCPTransactionGroup]
    association_observations: list[PFCPAssociationObservation]
    session_reports: list[PFCPSessionReportObservation]
    consistency_checks: list[PFCPConsistencyResult]
    warnings: list[DetectorWarning]
```

## 5. PFCP Transaction Model

```python
class PFCPTransactionGroup(BaseModel):
    transaction_id: UUID
    message_family: str
    request_event_id: UUID | None
    response_event_id: UUID | None
    retransmission_event_ids: list[UUID]
    sequence_number: int | None
    request_frame: int | None
    response_frame: int | None
    local_node: str | None
    remote_node: str | None
    cp_seid: str | None
    up_seid: str | None
    outcome: Literal[
        "accepted", "rejected", "timed_out", "reset_or_transport_error",
        "request_only_capture_boundary", "unpaired", "unknown"
    ]
    pairing_confidence: Literal["high", "medium", "low"]
    pairing_reasons: list[str]

class PFCPAssociationObservation(BaseModel):
    observation_id: UUID
    node_pair_id: UUID
    local_node: str | None
    remote_node: str | None
    message_family: Literal[
        "association_setup", "association_update", "association_release",
        "heartbeat"
    ]
    request_event_id: UUID | None
    response_event_id: UUID | None
    outcome: Literal[
        "accepted", "rejected", "timed_out", "released",
        "restart_detected", "recovered", "unknown"
    ]
    recovery_timestamp_before: str | None
    recovery_timestamp_after: str | None
    availability: Literal["available", "unavailable", "degraded", "unknown"]
    affected_session_ids: list[UUID]
    attempt_link: Literal["selected_node_pair", "used_session", "supporting_only", "unrelated", "unknown"]
    evidence_ids: list[UUID]

class PFCPSessionReportObservation(BaseModel):
    report_id: UUID
    request_event_id: UUID
    response_event_id: UUID | None
    report_type: Literal[
        "error_indication", "user_plane_path_failure", "downlink_data",
        "usage", "session_report", "unknown"
    ]
    seid: str | None
    f_teids: list[str]
    mapped_attempt_id: UUID | None
    relevance: Literal["attempt_failure_evidence", "observation", "unrelated", "inconclusive"]
    evidence_ids: list[UUID]
```

## 6. Transaction Pairing Algorithm

Pair in descending evidence strength:

1. T01/T02 explicit `response_to` frame/reference.
2. Same endpoint pair, PFCP sequence, and request/response message family.
3. Same scoped SEID/session plus sequence and bounded time.
4. Endpoint/message family/time fallback with low confidence.

Pairing rules must account for:

- Sequence reuse after validity window.
- Requests before a UP SEID exists.
- Responses carrying newly allocated UP SEID.
- Retransmissions with same sequence.
- Direction reversal.
- Node restart/recovery timestamp changing validity.

Ambiguous pairing remains explicit; T08 must not force the nearest response.

## 7. Association and Node-State Observations

Association Setup, Update, Release and heartbeat/recovery evidence is indexed
by PFCP node pair independently of UE attempts. T08 records rejection,
timeout, explicit release, restart/recovery timestamp discontinuity and
availability as `PFCPAssociationObservation`.

An association observation emits an attempt-scoped candidate only when the
attempt selected or used that node pair through a strong T03/T04/T08 link and
the node observation is causally reachable before the failed PFCP/session
stage. Otherwise it remains a node observation or supporting evidence. T08
must not create one node-level candidate shared directly by multiple attempts;
each affected attempt gets its own candidate only after association evidence
passes that attempt's association rules.

Association candidate scoring uses `relevance="unresolved_infrastructure"` and
records whether availability was unavailable, degraded or unknown at the
attempt stage. Recovery before the attempt suppresses a failure candidate and
is retained as recovery evidence.

## 8. Explicit Rejection Detection

Emit a candidate when response Cause is not accepted for the message family. Preserve:

- Numeric cause and standardized label.
- Offending IE when present.
- Request/response frames.
- Session/node identity.
- Failed rule IDs and relevant IE paths.

Unknown cause values remain usable and produce a dictionary warning.

## 9. Timeout and Retransmission Detection

- Group retransmissions into one transaction.
- Use message-family timeout policy and capture timestamps.
- `timed_out` requires visible interval beyond timeout and no accepted/rejected response.
- Capture end before timeout yields `request_only_capture_boundary`, not failure.
- Repeated request followed by accepted response is recovered retry evidence.
- Retry exhaustion emits one candidate with all retry frames.

## 10. Session and SEID Validation

Detect:

- Unknown session response/cause.
- Response SEID incompatible with request/session state.
- Modification/deletion before establishment without capture-boundary explanation.
- Same active SEID mapped to incompatible session identities.
- Old SEID used after explicit deletion/recovery restart.

SEID value changes during new establishment, relocation, or node restart may be valid and require profile/state context.

## 11. Rule Programming Validation

For establishment/modification, check semantic presence/consistency when applicable:

- PDR and FAR references resolve.
- QER/URR references resolve when required.
- Apply Action is compatible with forwarding/buffering intent.
- Outer Header Creation/Removal has required endpoint/tunnel fields.
- UE IP and network instance/DNN are present when required.
- QFI and QoS rule mapping is internally consistent.
- Created/updated/removed rule IDs do not contradict session state.

These are targeted semantic checks, not complete PFCP specification validation.

## 12. PFCP Session Report Handling

Session Report Request/Response is UPF-initiated evidence. T08 classifies
reports by report type and mapped session:

- Error Indication and user-plane path failure become potential
  attempt-scoped candidates only when reported SEID, F-TEID, UE IP/session
  identity or linked PFCP session maps to the attempt.
- Downlink Data, Usage and other routine reports are observations unless a
  profile/cause policy explicitly declares them failure-relevant for the
  stage.
- Request without response follows report-specific timeout policy; capture
  boundary yields an inconclusive observation, not an inferred failure.
- Report acceptance/rejection is recorded separately from whether the report
  proves user-plane failure.

Reports may support reachability-loss and mobile-terminated delivery findings
when profile timing shows paging/service response or user-plane activation was
causally reachable.

## 13. NGAP/PFCP Tunnel Consistency

```python
class TunnelRoleExpectation(BaseModel):
    role: Literal[
        "ngap_downlink_transport", "pfcp_far_outer_header_creation",
        "pfcp_uplink_pdr_f_teid", "n9_intermediate_tunnel",
        "source_path", "target_path", "cleanup_path"
    ]
    stage_id: str
    activation: Literal["source_active", "target_prepared", "target_active", "cleanup"]
    address: str | None
    teid: str | None
    qfi: str | None
    evidence_ids: list[UUID]

class PFCPConsistencyResult(BaseModel):
    check_id: UUID
    check_type: str
    expected: list[TunnelRoleExpectation]
    observed: list[TunnelRoleExpectation]
    status: Literal["consistent", "inconsistent", "inconclusive", "not_applicable"]
    evidence_ids: list[UUID]
    rationale: str
```

Checks include:

- NGAP downlink N3 transport address/TEID versus PFCP FAR Outer Header
  Creation for the downlink path.
- PFCP-created uplink PDR/F-TEID versus NGAP/session expectation for uplink
  user-plane path.
- QFI/resource mapping.
- UE IP/DNN/session mapping.
- Handover target tunnel versus PFCP path update.
- N9/inter-UPF intermediate tunnel roles when the selected profile declares
  them applicable.

During handover, compare against target/path-switch values only after the
profile's target-activation stage. Do not compare a new target tunnel to
obsolete source tunnel values, and do not flag source/target coexistence
during a legal transition window. Old-path deletion after target activation is
cleanup; target path programming failure before activation can still be
primary when it causes handover failure.

## 14. Mobility and Handover Handling

- Expected source/target tunnels may coexist during transition.
- Old-path deletion after successful switch is cleanup.
- Target path programming failure before Handover Failure may be primary.
- PFCP failure after radio success/path switch may explain post-handover traffic failure.
- Inter-UPF/N9 complexity is checked only when visible and profile-applicable,
  using profile-declared intermediate tunnel roles.

## 15. Heartbeat and Node Recovery

Heartbeats are routine and produce no session candidate by default. They may support a node-unavailable candidate only when:

- Heartbeat/recovery timestamp establishes restart/unavailability.
- Same PFCP node/session is used by the attempt.
- A session operation fails or times out consistently.

T08 must not diagnose node failure from a single missing heartbeat without
policy and correlation evidence. Heartbeat/recovery evidence should update the
node-pair association observation and only become an attempt candidate through
the association rules in section 7.

## 16. Candidate Categories and Scoring Inputs

Suggested bases:

- Explicit non-accepted response: `0.95`.
- Association rejection or unrecovered association timeout for a selected
  node pair: `0.90`.
- Session Report Error Indication or user-plane path failure mapped to the
  attempt: `0.85`.
- Request timeout after visible window: `0.80`.
- Strong SEID/session inconsistency: `0.75`.
- Directional tunnel/rule inconsistency: `0.75-0.90` based on explicitness,
  profile stage and source/target/N9 role.
- Recovered retry: penalty/no terminal candidate.
- Downlink Data, Usage or other non-failure Session Reports: observation only
  unless profile/cause policy promotes them.
- Low pairing confidence or capture boundary: penalty.
- Cleanup operation after terminal attempt: cleanup penalty in T12.

Store all score terms and rule IDs. Per `LLD.md` section 4.6, T08 assigns
`severity` from its rule table, resolves `capture_phase` through
`context.phase_reader`, publishes `call_impact="inconclusive"`, and mints
cited evidence through the evidence registry (`LLD.md` section 24). Published
candidates are immutable.

## 17. Attempt Association

Association requires at least one strong session signal:

- T03 PFCP session node linked to attempt session.
- CP/UP SEID within validity interval.
- SBI SM context to PFCP correlation.
- UE IP/DNN/slice plus stage-compatible transaction and endpoint.
- NGAP tunnel match plus session identity.
- Selected/used PFCP association node pair for node-state candidates.
- Session Report SEID/F-TEID/UE-IP mapping for report candidates.

Timestamp proximity alone is insufficient.

## 18. Persistence and Deterministic IDs

Candidate ID:

```text
UUIDv5(attempt_id + detector_rule + transaction_id + failed_rule/item)
```

Persist transaction groups and consistency results in common diagnostics artifacts:

```text
normalized/diagnostics/pfcp_transactions.jsonl
normalized/diagnostics/pfcp_association_observations.jsonl
normalized/diagnostics/pfcp_session_reports.jsonl
normalized/diagnostics/pfcp_consistency.jsonl
normalized/diagnostics/failure_candidates.jsonl
```

## 19. Failure Semantics

- Unknown attempt/event: validation error.
- Ambiguous pairing: retain unpaired/ambiguous group, warn, lower confidence.
- Missing IE tree: explicit outer cause remains usable; semantic checks become inconclusive.
- Association observation cannot be linked to the attempt: retain as node
  observation, no candidate.
- Session Report cannot be mapped to attempt SEID/F-TEID: retain as
  observation/inconclusive, no candidate.
- Unknown cause/message: preserve raw value and continue.
- Capture boundary before timeout: no timeout candidate.
- Full evidence checksum mismatch: evidence-integrity failure for affected check.
- Rule exception: quarantine affected transaction and mark partial.

## 20. Performance and Resource Requirements

- O(PFCP events + scoped consistency checks).
- Index by endpoint pair, node pair, sequence, SEID, F-TEID and session node.
- Keep only active/unpaired transactions in memory.
- Avoid all-pairs tunnel comparisons.
- Record events/sec, active transactions, pairing ambiguity, retries, consistency checks, full lookups, and latency.

## 21. Security and Privacy

- Primary capability only.
- Do not log UE IP, DNN, SEID, TEID, or raw IEs; log hashed/scoped IDs.
- Full PFCP records remain local.
- Treat IE text/values as untrusted.
- Bound nested IE materialization.

## 22. Observability

Logs include attempt, transaction, association observation, session report,
message family, pairing rule/confidence, outcome, candidate/check ID, cause
category, tunnel role and warning code.

Metrics include rejected/timed-out transactions, association failures,
restart discontinuities, session reports by relevance, retry
recovery/exhaustion, pairing ambiguity, directional tunnel inconsistencies,
heartbeat-supported node failures, and detector latency.

## 23. Proposed Python Code Structure

```text
V2/harness/analysis/
  pfcp.py
  pfcp_pairing.py
  pfcp_timeouts.py
  pfcp_session_state.py
  pfcp_association.py
  pfcp_session_reports.py
  pfcp_rules.py
  pfcp_consistency.py
  pfcp_mobility.py
V2/harness/config/
  pfcp_messages.yaml
  pfcp_causes.yaml
  pfcp_timeouts.yaml
V2/harness/models/
  pfcp.py
  failures.py
```

## 24. Implementation Sequence

1. Define transaction/consistency schemas and cause tables.
2. Implement explicit response pairing and rejection detection.
3. Add retransmission/timeout handling.
4. Add association/node-state observation indexing.
5. Add Session Report classification and attempt mapping.
6. Add SEID/session-state validation.
7. Add rule programming checks.
8. Add directional NGAP/PFCP tunnel consistency and mobility branches.
9. Add heartbeat/recovery support and performance tests.

## 25. Tests

### 25.1 Unit tests

- Explicit, sequence-based, and ambiguous pairing.
- Sequence/SEID reuse and validity intervals.
- Accepted/rejected/unknown causes.
- Association Setup/Update/Release accepted/rejected/timed-out/recovered and
  recovery timestamp discontinuity.
- Session Report Error Indication/user-plane path failure mapping and
  non-failure report preservation.
- Timeout, capture boundary, retry recovery/exhaustion.
- PDR/FAR/QER/URR reference checks.
- Directional tunnel/QFI/UE-IP consistency, including uplink/downlink roles.
- Deterministic IDs and score terms.

### 25.2 Integration tests

- PDU establishment rejected by PFCP then NAS reject.
- PFCP timeout with and without sufficient capture.
- Association failure before an attempt and during an attempt.
- Modification unknown session.
- Session Report path failure after establishment.
- Downlink Data/Usage report without failure promotion.
- Handover target PFCP path update failure.
- Successful path switch followed by old-path cleanup.
- N9/inter-UPF directional tunnel variant.
- Node restart/recovery timestamp and session failure.
- Multiple concurrent PFCP sessions with reused sequence values.

### 25.3 Negative tests

- Heartbeat traffic alone does not create call failure.
- Node association observation does not create a shared multi-attempt candidate.
- Expected handover TEID change is not inconsistency.
- Source/target handover coexistence before cleanup is not inconsistency.
- Timestamp proximity alone does not associate PFCP.
- Session Report with unmapped SEID/F-TEID is not attempt evidence.
- T08 cannot access NRF/UDR partitions.

## 26. Acceptance Criteria

T08 is complete when:

1. PFCP requests/responses/retries are paired with explicit confidence.
2. Explicit rejection and timeout semantics respect capture visibility.
3. Association/node-state observations are indexed independently and derive
   attempt candidates only through selected/used node-pair evidence.
4. Session Reports are classified and only failure-relevant mapped reports
   become candidates.
5. SEID and rule-programming checks are scoped to valid session state.
6. NGAP/PFCP consistency uses the correct directional role, procedure stage
   and target/source/N9 path.
7. Heartbeat/recovery evidence is supporting, not automatically causal.
8. Every candidate/check cites exact PFCP and correlated evidence.
9. Candidate score terms are available to T12.
10. Primary-only access is enforced.
