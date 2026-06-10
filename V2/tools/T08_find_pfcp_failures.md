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
  decisions), the T21 phase reader, interface visibility and the resolved
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

## 7. Explicit Rejection Detection

Emit a candidate when response Cause is not accepted for the message family. Preserve:

- Numeric cause and standardized label.
- Offending IE when present.
- Request/response frames.
- Session/node identity.
- Failed rule IDs and relevant IE paths.

Unknown cause values remain usable and produce a dictionary warning.

## 8. Timeout and Retransmission Detection

- Group retransmissions into one transaction.
- Use message-family timeout policy and capture timestamps.
- `timed_out` requires visible interval beyond timeout and no accepted/rejected response.
- Capture end before timeout yields `request_only_capture_boundary`, not failure.
- Repeated request followed by accepted response is recovered retry evidence.
- Retry exhaustion emits one candidate with all retry frames.

## 9. Session and SEID Validation

Detect:

- Unknown session response/cause.
- Response SEID incompatible with request/session state.
- Modification/deletion before establishment without capture-boundary explanation.
- Same active SEID mapped to incompatible session identities.
- Old SEID used after explicit deletion/recovery restart.

SEID value changes during new establishment, relocation, or node restart may be valid and require profile/state context.

## 10. Rule Programming Validation

For establishment/modification, check semantic presence/consistency when applicable:

- PDR and FAR references resolve.
- QER/URR references resolve when required.
- Apply Action is compatible with forwarding/buffering intent.
- Outer Header Creation/Removal has required endpoint/tunnel fields.
- UE IP and network instance/DNN are present when required.
- QFI and QoS rule mapping is internally consistent.
- Created/updated/removed rule IDs do not contradict session state.

These are targeted semantic checks, not complete PFCP specification validation.

## 11. NGAP/PFCP Tunnel Consistency

```python
class PFCPConsistencyResult(BaseModel):
    check_id: UUID
    check_type: str
    expected: dict[str, JsonValue]
    observed: dict[str, JsonValue]
    status: Literal["consistent", "inconsistent", "inconclusive", "not_applicable"]
    evidence_ids: list[UUID]
    rationale: str
```

Checks include:

- NGAP N3 transport address/TEID versus PFCP FAR/PDR tunnel.
- QFI/resource mapping.
- UE IP/DNN/session mapping.
- Handover target tunnel versus PFCP path update.

During handover, compare against target/path-switch values after the relevant stage. Do not compare a new target tunnel to obsolete source tunnel values.

## 12. Mobility and Handover Handling

- Expected source/target tunnels may coexist during transition.
- Old-path deletion after successful switch is cleanup.
- Target path programming failure before Handover Failure may be primary.
- PFCP failure after radio success/path switch may explain post-handover traffic failure.
- Inter-UPF/N9 complexity is checked only when visible and profile-applicable.

## 13. Heartbeat and Node Recovery

Heartbeats are routine and produce no session candidate by default. They may support a node-unavailable candidate only when:

- Heartbeat/recovery timestamp establishes restart/unavailability.
- Same PFCP node/session is used by the attempt.
- A session operation fails or times out consistently.

T08 must not diagnose node failure from a single missing heartbeat without policy and correlation evidence.

## 14. Candidate Categories and Scoring Inputs

Suggested bases:

- Explicit non-accepted response: `0.95`.
- Request timeout after visible window: `0.80`.
- Strong SEID/session inconsistency: `0.75`.
- Tunnel/rule inconsistency: `0.75-0.90` based on explicitness.
- Recovered retry: penalty/no terminal candidate.
- Low pairing confidence or capture boundary: penalty.
- Cleanup operation after terminal attempt: cleanup penalty in T12.

Store all score terms and rule IDs. Per `LLD.md` section 4.6, T08 assigns
`severity` from its rule table, resolves `capture_phase` through
`context.phase_reader`, publishes `call_impact="inconclusive"`, and mints
cited evidence through the evidence registry (`LLD.md` section 24). Published
candidates are immutable.

## 15. Attempt Association

Association requires at least one strong session signal:

- T03 PFCP session node linked to attempt session.
- CP/UP SEID within validity interval.
- SBI SM context to PFCP correlation.
- UE IP/DNN/slice plus stage-compatible transaction and endpoint.
- NGAP tunnel match plus session identity.

Timestamp proximity alone is insufficient.

## 16. Persistence and Deterministic IDs

Candidate ID:

```text
UUIDv5(attempt_id + detector_rule + transaction_id + failed_rule/item)
```

Persist transaction groups and consistency results in common diagnostics artifacts:

```text
normalized/diagnostics/pfcp_transactions.jsonl
normalized/diagnostics/pfcp_consistency.jsonl
normalized/diagnostics/failure_candidates.jsonl
```

## 17. Failure Semantics

- Unknown attempt/event: validation error.
- Ambiguous pairing: retain unpaired/ambiguous group, warn, lower confidence.
- Missing IE tree: explicit outer cause remains usable; semantic checks become inconclusive.
- Unknown cause/message: preserve raw value and continue.
- Capture boundary before timeout: no timeout candidate.
- Full evidence checksum mismatch: evidence-integrity failure for affected check.
- Rule exception: quarantine affected transaction and mark partial.

## 18. Performance and Resource Requirements

- O(PFCP events + scoped consistency checks).
- Index by endpoint pair, sequence, SEID, and session node.
- Keep only active/unpaired transactions in memory.
- Avoid all-pairs tunnel comparisons.
- Record events/sec, active transactions, pairing ambiguity, retries, consistency checks, full lookups, and latency.

## 19. Security and Privacy

- Primary capability only.
- Do not log UE IP, DNN, SEID, TEID, or raw IEs; log hashed/scoped IDs.
- Full PFCP records remain local.
- Treat IE text/values as untrusted.
- Bound nested IE materialization.

## 20. Observability

Logs include attempt, transaction, message family, pairing rule/confidence, outcome, candidate/check ID, cause category, and warning code.

Metrics include rejected/timed-out transactions, retry recovery/exhaustion, pairing ambiguity, session/tunnel inconsistencies, heartbeat-supported node failures, and detector latency.

## 21. Proposed Python Code Structure

```text
V2/harness/analysis/
  pfcp.py
  pfcp_pairing.py
  pfcp_timeouts.py
  pfcp_session_state.py
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

## 22. Implementation Sequence

1. Define transaction/consistency schemas and cause tables.
2. Implement explicit response pairing and rejection detection.
3. Add retransmission/timeout handling.
4. Add SEID/session-state validation.
5. Add rule programming checks.
6. Add NGAP tunnel consistency and mobility branches.
7. Add heartbeat/recovery support and performance tests.

## 23. Tests

### 23.1 Unit tests

- Explicit, sequence-based, and ambiguous pairing.
- Sequence/SEID reuse and validity intervals.
- Accepted/rejected/unknown causes.
- Timeout, capture boundary, retry recovery/exhaustion.
- PDR/FAR/QER/URR reference checks.
- Tunnel/QFI/UE-IP consistency.
- Deterministic IDs and score terms.

### 23.2 Integration tests

- PDU establishment rejected by PFCP then NAS reject.
- PFCP timeout with and without sufficient capture.
- Modification unknown session.
- Handover target PFCP path update failure.
- Successful path switch followed by old-path cleanup.
- Node restart/recovery timestamp and session failure.
- Multiple concurrent PFCP sessions with reused sequence values.

### 23.3 Negative tests

- Heartbeat traffic alone does not create call failure.
- Expected handover TEID change is not inconsistency.
- Timestamp proximity alone does not associate PFCP.
- T08 cannot access NRF/UDR partitions.

## 24. Acceptance Criteria

T08 is complete when:

1. PFCP requests/responses/retries are paired with explicit confidence.
2. Explicit rejection and timeout semantics respect capture visibility.
3. SEID and rule-programming checks are scoped to valid session state.
4. NGAP/PFCP consistency uses the correct procedure stage and target path.
5. Heartbeat/recovery evidence is supporting, not automatically causal.
6. Every candidate/check cites exact PFCP and correlated evidence.
7. Candidate score terms are available to T12.
8. Primary-only access is enforced.
