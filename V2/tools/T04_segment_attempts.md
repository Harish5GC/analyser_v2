# T04 `segment_attempts` Implementation Specification

## 1. Purpose

`segment_attempts` divides primary UE/session timelines into independent, typed procedure attempts. Attempts are the unit used for request extraction, diagnostics, comparison, model evidence, and reporting.

The tool must distinguish retries from new attempts and must handle repeated establishment/release cycles, overlapping procedures, mobility context changes, network-triggered procedures, and capture boundaries.

## 2. Non-Goals

T04 must not:

- Diagnose a root cause.
- Treat every missing terminal as a network failure.
- Use NRF/UDR hidden partitions.
- Merge attempts solely because they share a PDU session ID, PTI, SEID, stream, or endpoint.
- Apply scenario success/failure expectations; T14 handles scenario validation.
- Compare attempts; T11 handles baseline comparison.

## 3. Ownership Boundary

Inputs:

- Read-only `PrimaryEventReader`.
- T03 `IdentityGraphReader`.
- Versioned procedure-profile registry.
- Capture metadata and timeout configuration.

Outputs:

- Persisted attempts and event assignments.
- Retry and parent/child relationships.
- Ambiguous/unassigned event records.
- Attempt indexes and manifest.

## 4. Python Tool Contract

```python
class SegmentAttemptsRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    primary_reader: PrimaryEventReader
    identity_graph: IdentityGraphReader
    profile_registry_version: str
    config: AttemptSegmentationConfig


class AttemptSegmentationConfig(BaseModel):
    default_idle_timeout_seconds: Decimal = Decimal("30")
    default_response_timeout_seconds: Decimal = Decimal("10")
    max_open_attempts_per_ue: int = 100
    minimum_assignment_confidence: Decimal = Decimal("0.70")
    persist_unassigned_events: bool = True


class SegmentAttemptsResult(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    status: Literal["success", "partial", "failed"]
    manifest: ArtifactDescriptor
    attempt_count: int
    outcome_counts: dict[str, int]
    profile_counts: dict[str, int]
    ambiguous_assignment_count: int
    unassigned_event_count: int
    warnings: list[AttemptWarning]
```

## 5. Procedure Attempt Model

```python
class ProcedureAttempt(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    attempt_id: UUID
    analysis_id: UUID
    ue_id: UUID | None
    session_node_id: UUID | None
    profile_id: str
    procedure_type: str
    subtype: str | None
    sequence_number: int
    initiator: Literal["UE", "NETWORK", "UNKNOWN"]
    parent_attempt_id: UUID | None
    child_attempt_ids: list[UUID] = Field(default_factory=list)
    start_frame: int
    end_frame: int
    start_timestamp: Decimal | None
    end_timestamp: Decimal | None
    trigger_event_ids: list[UUID]
    event_ids: list[UUID]
    correlation_identifiers: EventIdentifiers
    request_signature: dict[str, JsonValue]
    transitions: list[StateTransition]
    retries: list[RetryRecord]
    outcome: Literal[
        "succeeded", "failed", "aborted", "timed_out", "incomplete_capture"
    ]
    completion_reason: str
    assignment_confidence: Literal["high", "medium", "low"]
    visibility: InterfaceVisibility
    warnings: list[str] = Field(default_factory=list)
```

Open attempts are internal transient objects. A completed T04 artifact must not contain `outcome=open`.

## 6. Procedure Profile Contract

```python
class ProcedureProfile(BaseModel):
    profile_id: str
    version: str
    procedure_type: str
    trigger_matchers: list[EventMatcher]
    correlation_keys: list[CorrelationKeyRule]
    stages: list[StageDefinition]
    success_terminals: list[EventMatcher]
    failure_terminals: list[EventMatcher]
    abort_terminals: list[EventMatcher]
    retry_rules: list[RetryRule]
    timeout_rules: list[TimeoutRule]
    nesting_rules: list[NestingRule]
    visibility_requirements: list[VisibilityRequirement]
```

Every stage declares `mandatory`, `conditional`, `optional`, or `repeatable`. Conditional stages include a machine-evaluable applicability predicate.

## 7. Supported Profile Families

### 7.1 Registration

- Initial registration.
- Mobility registration update.
- Periodic registration update.
- Emergency registration.
- Registration over 3GPP/non-3GPP access.
- Registration retry and re-authentication branches.

### 7.2 Session and service

- UE service request.
- Network paging and service restoration.
- PDU session establishment, modification, and release.
- Emergency PDU session.
- UE/network initiated deregistration.

### 7.3 Access and mobility

- Initial context setup and release.
- PDU session resource setup/modify/release.
- Xn handover visible from path switch.
- N2 handover.
- Inter-AMF handover/context transfer.
- Inter-system and 3GPP/non-3GPP mobility.

## 8. Attempt Triggering

An attempt opens only from a profile trigger with sufficient identity context. Trigger examples:

- NAS Registration Request.
- NAS Service Request.
- NAS PDU Session Establishment Request.
- NGAP Handover Required/Path Switch Request.
- Network paging for a new paging attempt.
- Network-initiated deregistration request.

If the capture starts mid-procedure, a profile may define a `mid_capture_trigger` such as a response or path-switch message. Such attempts are marked `incomplete_history=true` and cannot claim missing earlier stages.

## 9. Event Assignment

Assignment order:

1. Exact identity and transaction match.
2. Explicit parent/child protocol reference.
3. Strong session/context graph link.
4. Profile stage compatibility within validity/time bounds.
5. Supporting time/endpoint evidence only after one stronger match.

Each assignment stores confidence and reason codes. An event may be shared between a parent and child attempt only when the profile nesting rule permits it; otherwise it has one owning attempt plus ambiguous candidates.

## 10. Retry Versus New Attempt

A retry belongs to an open attempt when all required conditions hold:

- Same profile/procedure family.
- Compatible UE/session context.
- Same transaction identity when the protocol provides one.
- No prior terminal completion.
- Retry occurs within the profile retry window.
- Request signature is compatible under profile rules.

A new attempt is required when any decisive condition holds:

- Prior attempt reached a terminal state.
- New PTI/transaction identity indicates a fresh procedure.
- Explicit new registration/session trigger after completion.
- Retry/idle window expired.
- Identity validity interval changed.
- Profile defines the message as a new attempt rather than retransmission.

Repeated requests with ambiguous transaction information remain assignment candidates and lower attempt confidence; they are not blindly merged.

## 11. Parent and Child Attempts

Nested examples:

- Registration parent with authentication/security child procedures.
- PDU session establishment parent with SM context and PFCP subprocedures represented as linked stages/events rather than separate UE attempts unless separately reportable.
- Handover parent with path-switch and old-context release child procedures.
- Paging parent followed by UE service request child/continuation according to profile.

Parent failure does not automatically mark every child failed; outcome propagation is profile-specific.

## 12. State Transition Construction

For each assigned event:

1. Match applicable stage definitions.
2. Check ordering constraints and repeatability.
3. Record transition from prior attempt state.
4. Mark out-of-order but legal optional/retry events.
5. Record unexpected events without immediately failing the attempt.

T04 records observed transitions. T09 later determines whether a missing transition is a diagnostic failure.

## 13. Attempt Closure

### 13.1 Success

Close on a profile success terminal after required visible stages are satisfied or explicitly bypassed by a legal branch.

### 13.2 Explicit failure

Close on NAS reject, NGAP unsuccessful terminal, explicit abort/cancel, or other profile failure terminal. T04 records terminal outcome but does not choose root cause.

### 13.3 Abort

Use `aborted` for explicit cancellation, supersession, successful rollback, or replacement by a profile-defined new procedure.

### 13.4 Timeout

Use `timed_out` only when:

- Required interface is visible.
- Expected timeout elapsed inside the capture.
- No terminal response was observed.

### 13.5 Incomplete capture

Use `incomplete_capture` when the capture starts after required history or ends before a reliable timeout/terminal conclusion.

## 14. Visibility Model

Per attempt, persist observed interfaces and directions:

- N1/NAS.
- N2/NGAP.
- SBI primary HTTP.
- N4/PFCP.
- Relevant access/mobility visibility.

Profile stages belonging exclusively to an invisible interface cannot cause T04 to declare timeout/failure. Visibility is later consumed by T09 and T14.

## 15. Request Signature

T04 stores a stable request signature for T11 baseline selection:

- Procedure/profile/subtype.
- Registration/service request type.
- DNN, S-NSSAI, PDU type, SSC mode.
- Access type, emergency flag, roaming topology when known.
- PDU session ID only as scoped context, not global identity.

Dynamic frames, timestamps, stream IDs, sequence numbers, SEIDs, TEIDs, UUIDs, and ports are excluded.

## 16. Attempt ID and Sequence

Attempt IDs are deterministic UUIDv5 values derived from:

```text
analysis_id + profile_id + stable UE/context node + first trigger event ID
```

Sequence numbers are assigned per UE and procedure type by start frame. Adding later events to an attempt does not change its ID or sequence.

## 17. Ambiguous and Unassigned Events

```python
class AttemptAssignmentCandidate(BaseModel):
    event_id: UUID
    candidate_attempt_id: UUID
    confidence: Decimal
    reason_codes: list[str]
    accepted: bool
```

Events below assignment threshold are persisted as unassigned. Ambiguous assignment must remain visible to diagnostics and reports as a limitation.

## 18. Output Layout

```text
normalized/attempts/
  attempts.jsonl
  transitions.jsonl
  retries.jsonl
  event_assignments.jsonl
  ambiguous_assignments.jsonl
  unassigned_events.jsonl
  attempts_manifest.json
indexes/
  attempt_index.jsonl
  ue_attempt_index.jsonl
  event_attempt_index.jsonl
  procedure_attempt_index.jsonl
```

## 19. Manifest and Revisioning

The manifest records T02/T03 input checksums, profile registry version, configuration hash, counts by profile/outcome/confidence, ambiguous/unassigned counts, timeout use, artifacts, elapsed time, and warnings.

Changing profiles or timeout configuration creates a new immutable attempt revision.

## 20. Failure Semantics

- Invalid T02/T03 manifest: fatal.
- Unknown procedure trigger: create `unknown_procedure` only when a genuine trigger exists; warn.
- Maximum open-attempt limit exceeded: stop opening low-confidence attempts, mark partial, preserve events.
- Ambiguous assignment: nonfatal, persisted.
- Profile invariant or impossible terminal transition: warn/quarantine attempt; fatal only if output consistency cannot be maintained.
- Index/data mismatch or publication failure: fatal.

## 21. Performance and Resource Requirements

- Process ordered timelines incrementally per UE/context.
- Maintain only active attempts plus bounded recent closed-attempt state.
- Use indexes for event-to-identity access; do not rescan all events for every attempt.
- O(events * active profile candidates), with candidate profiles pruned by trigger type.
- Record events/sec, attempts/sec, maximum simultaneous open attempts, assignment ambiguity, and peak RSS.

## 22. Security and Privacy

- T04 receives primary capability interfaces only.
- Persist UE node IDs and masked aliases, not clear subscriber values in attempt files.
- Do not log request bodies or identifiers.
- Treat profile definitions/configuration as trusted versioned application data; reject arbitrary executable predicates.

## 23. Observability

Structured logs:

- `analysis_id`, `tool=T04`, `ue_id`, `attempt_id`, `profile_id`.
- Trigger/terminal event IDs and frames.
- Assignment rule, confidence bucket, retry/new-attempt decision.
- Outcome, completion reason, warning code, duration.

Metrics include attempts by profile/outcome, retry counts, timeout/incomplete counts, ambiguous assignment rate, and open-attempt high-water mark.

## 24. Proposed Python Code Structure

```text
V2/harness/analysis/
  attempt_engine.py
  attempt_runtime.py
  attempt_assignment.py
  retry_classifier.py
  attempt_ids.py
  visibility.py
  request_signature.py
  profiles/
    base.py
    registry.py
    registration.py
    authentication.py
    service_request.py
    pdu_session.py
    emergency.py
    mobility.py
    handover.py
    roaming.py
    deregistration.py
V2/harness/storage/
  attempt_store.py
V2/harness/models/
  attempts.py
```

## 25. Implementation Sequence

1. Define profile, attempt, transition, retry, and assignment schemas.
2. Implement profile registry and basic registration/PDU profiles.
3. Implement event assignment and deterministic attempt IDs.
4. Implement retry/new-attempt decisions and terminal closure.
5. Implement visibility and capture-boundary behavior.
6. Add emergency, service request, deregistration, mobility, handover, and roaming profiles.
7. Add persisted indexes, revision manifest, and performance tests.

## 26. Tests

### 26.1 Unit tests

- Trigger and terminal matcher behavior.
- Deterministic attempt IDs and sequence numbers.
- Retry versus new transaction for every supported protocol identity.
- Timeout versus incomplete-capture logic.
- Conditional/optional/repeatable stages.
- Parent/child relationship and outcome propagation.
- Assignment confidence and ambiguity.
- Request signature exclusion of dynamic values.

### 26.2 Integration tests

- Nine successful establishment/release cycles and failed tenth establishment.
- Same PDU session ID with different PTIs.
- Two UEs and overlapping procedures.
- Registration with nested authentication/security.
- Paging followed by service request.
- Periodic, mobility, emergency, and non-3GPP registration.
- Xn path switch, N2 handover, and inter-AMF handover.
- Roaming home-routed and local-breakout procedures.
- Capture starting/ending mid-attempt.
- Missing interface visibility.

### 26.3 Negative tests

- Same session ID on different UEs does not merge attempts.
- Timestamp overlap alone does not assign an event.
- Closed attempt does not absorb a new trigger.
- Primary segmentation cannot access NRF/UDR readers.

## 27. Acceptance Criteria

T04 is complete when:

1. Every persisted attempt has a valid trigger or explicit mid-capture basis.
2. Repeated cycles and reused identifiers remain separate when transactions differ.
3. Retry/new-attempt decisions are reason-coded and profile-driven.
4. Every assigned event records correlation confidence and evidence.
5. Ambiguous and unassigned events remain queryable.
6. Success, failure, abort, timeout, and incomplete-capture are distinguished correctly.
7. Interface visibility prevents false failure closure.
8. Attempt IDs and sequence numbers are deterministic.
9. Supported scenario families have versioned profiles and fixture coverage.
10. Primary-only data access is enforced.
