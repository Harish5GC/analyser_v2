# T09 `detect_missing_transitions` Implementation Specification

## 1. Purpose

`detect_missing_transitions` finds implicit failures where a procedure stops before an applicable mandatory stage and no explicit protocol failure fully explains the stop.

The tool identifies the last completed stage and first missing mandatory stage while distinguishing network timeout, missing visibility, conditional non-applicability, and capture truncation.

## 2. Non-Goals

T09 must not:

- Invent a missing stage from a generic universal call flow.
- Treat optional or non-applicable stages as failures.
- Declare timeout when the capture ends before the configured interval.
- Diagnose a stage whose required reference point, SBI service or SBI API was
  not captured.
- Replace explicit failures from T06-T08.
- Read NRF/UDR partitions.

## 3. Inputs and Boundary

- One T04 `ProcedureAttempt` with observed transitions.
- Exact versioned `ProcedureProfile` used for segmentation, loaded from the
  profile registry (`profiles/README.md`).
- Existing explicit candidates from T06-T08 for suppression/linking. T09 runs
  only after all three explicit detectors for the attempt have published.
- The shared attempt-scoped `DetectionContext` (`LLD.md` section 11), carrying
  capture bounds, reference-point/SBI visibility, the T21 phase reader and the
  resolved timeout-policy handle.

T09 receives primary attempt data only. It is the sole owner of implicit
missing-transition/missing-response candidates; T07/T08 request-only
observations are inputs, never duplicated candidates.

## 4. Python Tool Contract

```python
class DetectMissingTransitionsRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt: ProcedureAttempt
    attempts_revision: str
    profile: ProcedureProfile
    http_result: FindHTTPFailuresResult
    nas_ngap_result: FindNASNGAPFailuresResult
    pfcp_result: FindPFCPFailuresResult
    context: DetectionContext
    run_dir: Path
    diagnostics_dir: Path
    max_issue_samples_per_code: int = 20
    fsync_outputs: bool = True


class DetectMissingTransitionsResult(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    attempt_id: UUID
    status: Literal["success", "partial", "failed"]
    revision: str
    manifest: ArtifactDescriptor
    artifacts: list[ArtifactDescriptor]
    stage_results: list[StageResult]
    candidates: list[FailureCandidate]
    linked_suppressions: list[MissingStageSuppression]
    stage_timings: list[StageTimingObservation]
    first_missing_stage_id: str | None
    last_completed_stage_id: str | None
    warning_counts: dict[str, int]
    elapsed_ms: int
    issues: list[DetectorWarning]
```

T09 validates that T06/T07/T08 results are all published for the same attempt,
T04/T02/T21 lineage and `DetectionContext`; a partial explicit detector result
is accepted with its issues, but a missing/stale/failed dependency blocks T09.
The exact resolved profile ID/checksum must match the T04 selection. Output is
`normalized/diagnostics/<attempt-id>/T09`; path escape is fatal.

```python
class MissingStageSuppression(BaseModel):
    suppression_id: UUID
    stage_id: str
    explicit_candidate_ids: list[UUID]
    request_observation_ids: list[UUID]
    reason_codes: list[str]
    decision: Literal["linked_downstream", "duplicate_suppressed", "not_suppressed"]
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
    visibility_requirements: list[VisibilityRequirement]
    event_matchers: list[EventMatcher]
    timeout_rule_id: str | None
    predecessor_ids: set[str]
    legal_skip_conditions: list[ConditionExpression]
```

Conditions are declarative, allowlisted expressions over attempt/request/visibility facts; arbitrary code is forbidden.

## 6. Stage Result Contract

```python
class StageVisibilityResult(BaseModel):
    domain: Literal["reference_point", "sbi_service", "sbi_api"]
    key: str
    state: VisibilityState
    minimum_state: Literal["visible", "partial"]
    satisfied: bool

class StageResult(BaseModel):
    stage_result_id: UUID
    stage_id: str
    occurrence: int
    status: Literal[
        "completed", "missing", "timed_out", "inconclusive",
        "not_applicable", "optional_absent", "skipped_legally"
    ]
    matched_event_ids: list[UUID]
    matched_frames: list[int]
    expected_after_frame: int | None
    timeout_at: Decimal | None
    visibility_satisfied: bool
    visibility_results: list[StageVisibilityResult]
    predecessor_stage_ids: list[str]
    evidence_ids: list[UUID]
    reason_codes: list[str]
```

`timeout_at` is absolute Unix-epoch decimal seconds when a timestamp-based
deadline is valid. Frame fallback deadlines are recorded in
`expected_after_frame` plus evidence/reason codes; T09 does not serialize frame
numbers as timestamps.

## 7. Profile Applicability

Before evaluating stages, T09 validates that the profile/subtype remains compatible with observed request and attempt context. Examples:

- Emergency procedures use emergency-specific conditional stages.
- Periodic registration does not require all initial-registration stages.
- Registration Complete is evaluated only when the resolved release/profile
  sets `attempt.registration_accept_requires_ack=true`; false is
  `not_applicable`, unknown is `inconclusive`.
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
7. For remaining mandatory stages, evaluate all resolved visibility
   requirements and timeout.
8. Identify the first causal missing/timed-out stage.
9. Mark later missing stages downstream and do not emit separate primary candidates.

Mechanical evaluation:

1. Compile the validated profile into a DAG of stage occurrences, any-of
   groups, parallel branches and joins. Reject cycles, duplicate stage IDs,
   unknown predecessors/facts and executable conditions before evaluation.
2. Index T04 transitions/events by protocol/message/procedure and stage ID;
   match in `(frame,event_id,matcher_id)` order.
3. Evaluate applicability with three-valued facts. `false` becomes
   `not_applicable`; `unknown` on a conditional mandatory stage becomes
   `inconclusive`, never missing.
4. Assign each event to at most one occurrence of one mutually exclusive
   branch unless the profile explicitly permits shared evidence.
5. Mark repeatable occurrences and legal skips, then compute satisfied DAG
   reachability from the trigger.
6. Evaluate visibility/timeout only for reachable applicable mandatory nodes
   whose causal predecessors are satisfied.
7. For any-of groups, satisfaction of one legal member satisfies the group;
   for parallel joins, every applicable required branch must complete.
8. Choose the first causal break by topological order, predecessor completion
   frame, profile order, stage ID and occurrence.

Stage-result IDs use T09 revision, attempt/profile, stage ID and occurrence.
All statuses and reasons are persisted, including later downstream stages.

## 9. First Missing Stage Rule

Only the earliest applicable mandatory stage after the last completed causal predecessor becomes a T09 candidate. Later stages cannot be primary because the procedure could not reach them.

If an earlier explicit T06-T08 candidate already explains why the stage was not reached, T09 emits a linked downstream missing-transition record or suppresses a duplicate candidate according to rule configuration.

Suppression compares explicit candidate evidence/stage/session and terminal
ordering, not category text alone. An explicit candidate suppresses a duplicate
when its causal frame precedes the deadline/break and its rule maps to the same
profile edge. Otherwise T09 may link it as downstream context but retains its
own candidate. T07 request-only observations seed expected edges without being
treated as explicit failures; T08 routine/unmapped reports cannot suppress a
missing stage.

## 10. Timeout Evaluation

Timeout starts from a stage-specific anchor such as request frame/timestamp or prior completed stage. A timeout candidate requires:

- Timestamp available or a validated frame-based fallback.
- Every required reference-point, SBI service or SBI API visibility entry
  reaches the profile requirement's `minimum_state` during the interval.
- Capture extends beyond timeout plus configured tolerance.
- No matching response/terminal event.
- Attempt not explicitly aborted/superseded earlier.

Timeout policies record source/rationale and may vary by procedure/stage/vendor profile.

Timeout calculation uses the resolved timeout rule: anchor selector, decimal
duration, optional frame fallback, tolerance and visibility interval. When a
valid anchor timestamp exists, require capture end timestamp at or after
deadline+tolerance. Otherwise use the declared frame fallback and capture end
frame. Packet/time discontinuity that invalidates the bound yields
`inconclusive`. Timeout rule IDs/checksums and anchor evidence are persisted.

## 11. Capture Boundary Handling

- Capture begins after required predecessor: earlier stage becomes `inconclusive`, not missing.
- Capture ends before timeout: `inconclusive` and attempt may remain `incomplete_capture`.
- Capture contains only response side: request stage is `inconclusive` unless response references an earlier request.
- Timestamp gaps or packet loss warning lower confidence.

T09 must cite exact capture first/last frame/time in its reasoning.

## 12. Visibility Evaluation

Visibility is evaluated per stage and per namespace, not once for the whole
attempt. Examples:

- N1 encrypted: NAS semantic stage may be invisible while NGAP outer stage is visible.
- N4 absent from capture: no PFCP missing-stage failure.
- SBI primary visible but NRF/UDR hidden by design: T09 cannot declare hidden
  dependency stage missing.
- Handover preparation visibility absent: path-switch-only profile applies.

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

### 14.1 Reachability and mobile-terminated delivery

Profile-owned paging/service-request/MT-delivery edges are evaluated like other
mandatory conditional stages:

- T07 explicit paging/non-delivery/reject evidence remains explicit and may
  suppress/link a missing stage.
- T08 mapped Error Indication or user-plane path failure remains explicit and
  may suppress/link a later delivery absence.
- T09 alone may emit the implicit candidate for missing paging response,
  service response or delivery progression after a visible trigger/deadline.
- Invisible N1/N2/N3/N4 or capture truncation yields inconclusive, not device
  unreachable.
- Routine Downlink Data/Usage reports do not prove failure or reachability loss.

Candidate observed fields identify the exact profile stage and timing evidence;
they do not assert a hidden radio/user-plane cause without explicit evidence.

## 15. Candidate Contract and Scoring

T09 candidate category is `missing_transition` or `procedure_timeout` and includes:

- Last completed stage/event/frame.
- First missing stage.
- Expected visibility key and message.
- Timeout anchor/deadline.
- Visibility/capture evidence.
- Existing explicit candidate link.

Suggested base score is `0.65`, increased for strong visibility and elapsed timeout, reduced for partial capture/assignment ambiguity. Explicit T06-T08 candidates generally outrank T09 when they explain the same break.

Per `LLD.md` section 4.6, T09 assigns `severity` from its rule table, resolves
`capture_phase` through `context.phase_reader`, publishes
`call_impact="inconclusive"`, persists every score term, and mints cited
evidence (including synthetic `stage_expectation` records for missing stages)
through the evidence registry (`LLD.md` section 24).

For each stage result, T09 mints `stage_observation` evidence from matched
events or `stage_expectation` evidence from profile rule, predecessor/trigger,
visibility and deadline sources. Candidate score is the canonical-decimal sum
of base `0.65` plus named visibility/elapsed/assignment/capture/suppression
terms, clamped to `[0,1]`. Candidate ID uses T09 revision, attempt/profile,
stage occurrence and timeout-anchor evidence ID. Severity/phase/relevance are
T09-owned and call impact is inconclusive.

T09 emits `missing.deadline` timing rows for applicable evaluated deadlines and
may refine `terminal.outcome` only when the timeout/missing-stage determination
is the attempt's terminal basis. It does not emit T06/T08-owned timings.

## 16. Deterministic IDs and Persistence

Persist one immutable per-attempt T09 generation:

```text
normalized/diagnostics/<attempt-id>/T09/
  stage_results.jsonl
  failure_candidates.jsonl
  linked_suppressions.jsonl
  stage_timings.jsonl
  missing_transitions_manifest.json
staging/T09-<attempt-id>-<uuid>/
```

T09 revision inputs are T04/attempt/profile/registry revision, published
T06/T07/T08 result revisions and candidate/observation payload hashes, T21
phase revision, capture/visibility/assignment context, resolved timeout /
missing-stage scoring policy checksums, tool/schema version and
output-affecting limits.

Descriptors use types `stage_results`, `missing_transition_candidates`,
`missing_stage_suppressions`, `stage_timing_observations` and
`missing_transitions_manifest`, with verifiable counts, T04 parent checksum and
T09 revision. Empty candidate/suppression files publish.

### 16.1 Runner and publication invariants

The runner validates lineage/profile/policies/paths, returns an existing
identical revision, compiles the profile DAG, matches stages, computes
reachability/applicability/visibility/deadlines, links explicit results, mints
evidence/candidates/timings, writes descriptors/manifest, validates and
publishes manifest last.

Validation proves one result per stage occurrence; valid DAG/status/predecessor
semantics; matched assigned-primary events only; exactly one first causal
missing stage when a candidate exists; no candidate for optional,
not-applicable, invisible, unreachable-downstream or pre-timeout stages;
explicit suppression links reference published T06-T08 candidates; score equals
terms; evidence resolves; timing statuses/anchors are shared-model valid;
canonical ordering; and descriptors/counts/checksums/revisions agree.

## 17. Failure Semantics

- Missing/invalid profile: fail T09 for attempt and report profile error.
- Missing/failed/stale T06-T08 result, mixed T02/T04/T21 lineage, incompatible
  timeout policy or path escape: fatal with no T09 manifest.
- Condition evaluation error: mark affected stage inconclusive and detector partial.
- Unknown reference-point/SBI visibility: inconclusive.
- Timestamp unavailable: use frame fallback only when policy allows; otherwise inconclusive.
- Existing explicit terminal before expected stage: no missing-stage candidate after terminal.
- Output/persistence failure: fatal for diagnostic revision.

Unknown visibility, condition facts, capture-boundary deadlines and legal
profile ambiguity are represented inconclusive results, not partial execution.
Partial means a recoverable stage/rule evaluation was skipped. Fatal errors
preserve prior revisions.

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
- T09 has no event/dependency reader and can cite only attempt/T04 transitions,
  published T06-T08 evidence and profile/capture/visibility facts.

## 20. Observability

Logs include attempt/profile, stage ID, applicability/status, matched frames, timeout rule, visibility result, candidate ID, and warning code.

Metrics include missing/timed-out/inconclusive stages by profile,
capture-boundary suppressions, visibility suppressions, duplicate suppression
due to explicit candidate, and detector latency.

Minimum registered codes are `T09_PROFILE_INCOMPATIBLE`,
`T09_CONDITION_EVALUATION_FAILED`, `T09_VISIBILITY_INCONCLUSIVE`,
`T09_TIMEOUT_INCONCLUSIVE`, `T09_EXPLICIT_DUPLICATE_SUPPRESSED`,
`T09_STAGE_MATCH_CONFLICT` and `T09_OUTPUT_INVARIANT_FAILED`; shared integrity
violations use `RUN_EVIDENCE_INTEGRITY`.

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
8. Add explicit-result lineage, evidence, revision and manifest publication.

## 23. Tests

### 23.1 Unit tests

- Mandatory/conditional/optional/repeatable applicability.
- Any-of and parallel branch completion.
- First missing stage selection.
- Timeout anchor/deadline/tolerance.
- Capture start/end and timestamp fallback.
- Reference-point/SBI visibility per stage.
- Explicit candidate duplicate suppression.
- Deterministic candidate ID.
- DAG validation, three-valued conditions and stable occurrence assignment.
- Explicit suppression causal ordering and T07 request-only/T08 routine report behavior.
- Reachability/MT-delivery ownership and timing-row semantics.
- Revision, evidence, descriptor and manifest determinism.

### 23.2 Scenario fixtures

- Silent registration timeout at each major stage.
- Periodic/emergency/mobility registration legal branches.
- Service request/paging timeout.
- PDU establishment missing SBI/PFCP/NGAP terminal with appropriate visibility.
- Xn path-switch-only and N2 handover profiles.
- Local-breakout roaming without false H-SMF/N9 stages.
- Capture truncated before timeout.
- Paging/service-response and MT-delivery missing progression with visible and
  invisible interfaces.
- Identical rerun returns the same revision; explicit result/policy change
  creates a sibling.

### 23.3 Negative tests

- Optional stage absent produces no failure.
- Registration Accept without an acknowledgement trigger and no Registration
  Complete produces no failure; required-ack, no-ack and unknown-field
  fixtures cover initial, mobility and periodic profiles.
- Invisible reference point, SBI service or SBI API produces no failure.
- Later downstream missing stages produce no independent primary candidate.
- Hidden NRF/UDR stage is not evaluated by T09.
- Missing/stale T06-T08 publication, cyclic profile DAG, executable condition,
  corrupt descriptor and symlink escape publish no manifest.
- T18 resolves every emitted stage/candidate evidence ID before T15.

### 23.4 Golden tests

- Byte-stable stage results, suppressions, candidates, timings, evidence IDs,
  descriptors and manifest for registration, paging/service, PDU session,
  handover and roaming fixtures.
- Golden normalization preserves source frames, deadline semantics, statuses,
  scores, ordering and evidence IDs.

## 24. Acceptance Criteria

T09 is complete when:

1. Missing transitions are evaluated against the exact attempt profile/version.
2. Only applicable mandatory stages can generate candidates.
3. The first causal missing stage is distinguished from downstream absence.
4. Timeout requires sufficient reference-point/SBI and capture visibility.
5. Repeatable/parallel/conditional branches are handled deterministically.
6. Explicit T06-T08 failures are linked rather than duplicated.
7. Every result cites matched/expected stages, frames, timeout, and visibility.
8. Primary-only access is enforced.
9. Reachability/MT-delivery implicit failures are owned only by T09 and require
   profile, visibility, deadline and causal evidence.
10. Every T09 artifact passes section 16.1 and T09 starts only after published
    T06-T08 results for the same attempt.

## 25. Mechanical Implementation Checklist

1. Define request/result/stage/suppression models using shared types.
2. Register T09 issue and evidence record types.
3. Validate attempt/profile/context and T02/T04/T21 lineage.
4. Validate published T06/T07/T08 revisions/statuses/payload hashes.
5. Validate resolved timeout/scoring policies and per-attempt output path.
6. Build T09 revision and return an existing identical generation when valid.
7. Compile profile stages/conditions/branches into a validated DAG.
8. Index T04 transitions/events and assign deterministic stage occurrences.
9. Evaluate three-valued applicability, legal skips, any-of and parallel joins.
10. Compute causal reachability and matched/completed stage results.
11. Evaluate per-stage visibility namespaces/minimum states.
12. Compute timestamp or allowed frame deadlines with capture tolerance.
13. Identify the first causal missing/timed-out stage and downstream absences.
14. Consume T07 request-only and T08 report observations without treating them
    as explicit candidates.
15. Link/suppress duplicates using published T06-T08 causal evidence.
16. Evaluate paging/service/MT-delivery implicit stages under section 14.1.
17. Mint stage observation/expectation evidence and canonical score terms.
18. Build candidate, suppression and stage timing records deterministically.
19. Write all JSONL outputs including empty candidate/suppression files.
20. Validate section 16.1 DAG/status/visibility/deadline/evidence/count rules.
21. Build descriptors/manifest and publish evidence/data then manifest last.
22. Preserve sibling revisions and add all section 23 tests.
