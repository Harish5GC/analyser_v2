# T09 `detect_missing_transitions` Implementation Specification

## 1. Purpose

`detect_missing_transitions` finds implicit failures where a procedure stops before an applicable mandatory stage and no explicit protocol failure fully explains the stop.

The tool identifies the last completed stage and first missing mandatory stage while distinguishing network timeout, interface invisibility, conditional non-applicability, and capture truncation.

## 2. Non-Goals

T09 must not:

- Invent a missing stage from a generic universal call flow.
- Treat optional or non-applicable stages as failures.
- Declare timeout when the capture ends before the configured interval.
- Diagnose a stage belonging to an uncaptured interface.
- Replace explicit failures from T06-T08.
- Read NRF/UDR partitions.

## 3. Inputs and Boundary

- One T04 `ProcedureAttempt` with observed transitions.
- Exact versioned `ProcedureProfile` used for segmentation, loaded from the
  profile registry (`profiles/README.md`).
- Existing explicit candidates from T06-T08 for suppression/linking. T09 runs
  only after all three explicit detectors for the attempt have published.
- The shared attempt-scoped `DetectionContext` (`LLD.md` section 11), carrying
  capture bounds, interface visibility, the T21 phase reader and the resolved
  timeout-policy handle.

T09 receives primary attempt data only. It is the sole owner of implicit
missing-transition/missing-response candidates; T07/T08 request-only
observations are inputs, never duplicated candidates.

## 4. Python Tool Contract

```python
class DetectMissingTransitionsRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt: ProcedureAttempt
    profile: ProcedureProfile
    explicit_candidates: list[FailureCandidate]
    context: DetectionContext


class DetectMissingTransitionsResult(BaseModel):
    schema_version: Literal["2.0"]
    attempt_id: UUID
    stage_results: list[StageResult]
    candidates: list[FailureCandidate]
    first_missing_stage_id: str | None
    last_completed_stage_id: str | None
    warnings: list[DetectorWarning]
```

## 5. Stage Definition Contract

```python
class StageDefinition(BaseModel):
    stage_id: str
    name: str
    order: int
    applicability: Literal["mandatory", "conditional", "optional"]
    condition: ConditionExpression | None
    repeatable: bool = False
    terminal_success: bool = False
    terminal_failure: bool = False
    interface_requirements: set[str]
    event_matchers: list[EventMatcher]
    timeout_rule_id: str | None
    predecessor_ids: set[str]
    legal_skip_conditions: list[ConditionExpression]
```

Conditions are declarative, allowlisted expressions over attempt/request/visibility facts; arbitrary code is forbidden.

## 6. Stage Result Contract

```python
class StageResult(BaseModel):
    stage_id: str
    status: Literal[
        "completed", "missing", "timed_out", "inconclusive",
        "not_applicable", "optional_absent", "skipped_legally"
    ]
    matched_event_ids: list[UUID]
    matched_frames: list[int]
    expected_after_frame: int | None
    timeout_at: Decimal | None
    interface_visible: bool
    reason_codes: list[str]
```

## 7. Profile Applicability

Before evaluating stages, T09 validates that the profile/subtype remains compatible with observed request and attempt context. Examples:

- Emergency procedures use emergency-specific conditional stages.
- Periodic registration does not require all initial-registration stages.
- Local-breakout roaming does not require H-SMF/N9 stages.
- Xn handover visible only at path switch does not require N2 preparation messages.
- Optional authentication may be skipped when context is reused.

An incompatible profile is a segmentation/profile warning, not a missing-stage failure.

## 8. Stage Matching Algorithm

1. Load attempt events/transitions in deterministic order.
2. Evaluate each stage applicability condition.
3. Match events to stages using exact procedure/message and scoped identifiers.
4. Resolve repeatable stages into one or more occurrences.
5. Verify predecessor/order constraints while allowing legal optional branches.
6. Mark completed, legally skipped, optional absent, or not applicable stages.
7. For remaining mandatory stages, evaluate visibility and timeout.
8. Identify the first causal missing/timed-out stage.
9. Mark later missing stages downstream and do not emit separate primary candidates.

## 9. First Missing Stage Rule

Only the earliest applicable mandatory stage after the last completed causal predecessor becomes a T09 candidate. Later stages cannot be primary because the procedure could not reach them.

If an earlier explicit T06-T08 candidate already explains why the stage was not reached, T09 emits a linked downstream missing-transition record or suppresses a duplicate candidate according to rule configuration.

## 10. Timeout Evaluation

Timeout starts from a stage-specific anchor such as request frame/timestamp or prior completed stage. A timeout candidate requires:

- Timestamp available or a validated frame-based fallback.
- Required interface visible during the interval.
- Capture extends beyond timeout plus configured tolerance.
- No matching response/terminal event.
- Attempt not explicitly aborted/superseded earlier.

Timeout policies record source/rationale and may vary by procedure/stage/vendor profile.

## 11. Capture Boundary Handling

- Capture begins after required predecessor: earlier stage becomes `inconclusive`, not missing.
- Capture ends before timeout: `inconclusive` and attempt may remain `incomplete_capture`.
- Capture contains only response side: request stage is `inconclusive` unless response references an earlier request.
- Timestamp gaps or packet loss warning lower confidence.

T09 must cite exact capture first/last frame/time in its reasoning.

## 12. Interface Visibility

Visibility is evaluated per stage, not once for the whole attempt. Examples:

- N1 encrypted: NAS semantic stage may be invisible while NGAP outer stage is visible.
- N4 absent from capture: no PFCP missing-stage failure.
- SBI primary visible but NRF/UDR hidden by design: T09 cannot declare hidden dependency stage missing.
- Handover preparation interface absent: path-switch-only profile applies.

## 13. Repeatable and Retry Stages

Repeatable authentication, identity, retransmission, or update stages are collapsed into occurrences. T09 detects missing terminal progression after the final retry, not after the first repeat.

Retry exhaustion may already be an explicit T06/T08 candidate; T09 links rather than duplicates it.

## 14. Parallel and Conditional Branches

Profiles may define:

- Any-of stage groups.
- Parallel independent branches.
- Conditional subprocedures.
- Branch joins before terminal success.

A stage is missing only when all legal alternatives fail to satisfy the requirement. For parallel branches, identify which branch blocked completion.

## 15. Candidate Contract and Scoring

T09 candidate category is `missing_transition` or `procedure_timeout` and includes:

- Last completed stage/event/frame.
- First missing stage.
- Expected interface/message.
- Timeout anchor/deadline.
- Visibility/capture evidence.
- Existing explicit candidate link.

Suggested base score is `0.65`, increased for strong visibility and elapsed timeout, reduced for partial capture/assignment ambiguity. Explicit T06-T08 candidates generally outrank T09 when they explain the same break.

Per `LLD.md` section 4.6, T09 assigns `severity` from its rule table, resolves
`capture_phase` through `context.phase_reader`, publishes
`call_impact="inconclusive"`, persists every score term, and mints cited
evidence (including synthetic `stage_expectation` records for missing stages)
through the evidence registry (`LLD.md` section 24).

## 16. Deterministic IDs and Persistence

Candidate ID:

```text
UUIDv5(attempt_id + profile_version + stage_id + timeout_anchor_event_id)
```

Persist:

```text
normalized/diagnostics/stage_results.jsonl
normalized/diagnostics/failure_candidates.jsonl
```

## 17. Failure Semantics

- Missing/invalid profile: fail T09 for attempt and report profile error.
- Condition evaluation error: mark affected stage inconclusive and detector partial.
- Unknown interface visibility: inconclusive.
- Timestamp unavailable: use frame fallback only when policy allows; otherwise inconclusive.
- Existing explicit terminal before expected stage: no missing-stage candidate after terminal.
- Output/persistence failure: fatal for diagnostic revision.

## 18. Performance and Resource Requirements

- O(profile stages + attempt events) with indexed matcher dispatch.
- Avoid testing every matcher against every event where message/protocol indexing is possible.
- Cache compiled declarative conditions/matchers by profile version.
- Record attempts/sec, stages evaluated, matcher hits, timeout checks, inconclusive reasons, and latency.

## 19. Security and Safety

- Primary capability only.
- Profile conditions are declarative and cannot execute arbitrary code.
- Do not log sensitive field values.
- Treat protocol text as untrusted.
- Configuration/profile files require schema validation and version checksum.

## 20. Observability

Logs include attempt/profile, stage ID, applicability/status, matched frames, timeout rule, visibility result, candidate ID, and warning code.

Metrics include missing/timed-out/inconclusive stages by profile, capture-boundary suppressions, invisible-interface suppressions, duplicate suppression due to explicit candidate, and detector latency.

## 21. Proposed Python Code Structure

```text
V2/harness/analysis/
  transitions.py
  stage_matcher.py
  stage_conditions.py
  timeout_policy.py
  missing_transition.py
  visibility.py
V2/harness/models/
  profiles.py
  failures.py
V2/harness/config/
  procedure_timeouts.yaml
```

## 22. Implementation Sequence

1. Define stage result/condition/timeout schemas.
2. Implement applicability and stage matching.
3. Implement order/predecessor and first-missing logic.
4. Add visibility/capture boundary and timeout evaluation.
5. Add repeatable, any-of, parallel, and legal-skip branches.
6. Add explicit-candidate linking/suppression.
7. Add profile compatibility and performance tests.

## 23. Tests

### 23.1 Unit tests

- Mandatory/conditional/optional/repeatable applicability.
- Any-of and parallel branch completion.
- First missing stage selection.
- Timeout anchor/deadline/tolerance.
- Capture start/end and timestamp fallback.
- Interface visibility per stage.
- Explicit candidate duplicate suppression.
- Deterministic candidate ID.

### 23.2 Scenario fixtures

- Silent registration timeout at each major stage.
- Periodic/emergency/mobility registration legal branches.
- Service request/paging timeout.
- PDU establishment missing SBI/PFCP/NGAP terminal with appropriate visibility.
- Xn path-switch-only and N2 handover profiles.
- Local-breakout roaming without false H-SMF/N9 stages.
- Capture truncated before timeout.

### 23.3 Negative tests

- Optional stage absent produces no failure.
- Invisible interface produces no failure.
- Later downstream missing stages produce no independent primary candidate.
- Hidden NRF/UDR stage is not evaluated by T09.

## 24. Acceptance Criteria

T09 is complete when:

1. Missing transitions are evaluated against the exact attempt profile/version.
2. Only applicable mandatory stages can generate candidates.
3. The first causal missing stage is distinguished from downstream absence.
4. Timeout requires sufficient interface and capture visibility.
5. Repeatable/parallel/conditional branches are handled deterministically.
6. Explicit T06-T08 failures are linked rather than duplicated.
7. Every result cites matched/expected stages, frames, timeout, and visibility.
8. Primary-only access is enforced.
