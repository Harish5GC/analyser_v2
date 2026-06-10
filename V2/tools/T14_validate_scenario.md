# T14 `validate_scenario` Implementation Specification

## 1. Purpose

`validate_scenario` evaluates a parsed `ScenarioSpec` against deterministic attempt/request/event/stage evidence. It selects applicable attempts, evaluates checkpoints, and produces auditable verified/failed/inconclusive/not-applicable results.

The model may later explain results but cannot change them.

## 2. Non-Goals

T14 must not:

- Parse free text; T13 owns parsing.
- Diagnose root cause beyond scenario checkpoint status.
- Use model narrative as evidence.
- Treat absent evidence as failure when the interface/capture is insufficient.
- Read hidden NRF/UDR partitions directly.
- Expand a scenario with unstated expectations.

## 3. Inputs and Boundary

- Valid T13 `ScenarioSpec` or no-op empty result.
- T04 attempts and indexes.
- T05 request results.
- T09 stage/visibility results.
- Primary canonical events and evidence references.
- Optional admitted T24/T25 inspection result only when a checkpoint explicitly concerns NRF/UDR and the dependency flow was requested/inspected. Admitted statuses are `completed`, `empty` and `partial`; failed/invalid outcomes remain reporting metadata only.

Initial validation uses primary evidence only. Dependency checkpoints may remain inconclusive until inspected.

## 4. Python Tool Contract

`EvidenceStage` is imported from the shared `models/common.py` definition in
`LLD.md` section 4.10; T14 does not redeclare the enum.

```python
class ValidateScenarioRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    scenario: ScenarioSpec
    explicit_attempt_id: UUID | None
    dependency_results: list[DependencyInspectionResult] = Field(default_factory=list)
    pass_stage: EvidenceStage
    primary_validation_revision: str | None = None
    validator_policy_version: str


class ValidateScenarioResult(BaseModel):
    schema_version: Literal["2.0"]
    scenario_id: UUID
    selected_attempt_ids: list[UUID]
    selection_candidates: list[ScenarioAttemptCandidate]
    checkpoints: list[CheckpointResult]
    overall_status: Literal["verified", "failed", "inconclusive", "not_applicable"]
    conflicts: list[ScenarioEvidenceConflict]
    warnings: list[str]
    pass_stage: EvidenceStage
    parent_validation_revision: str | None
    dependency_result_revisions: list[str]
    validation_revision: str
```

Primary validation requires no dependency results and no parent revision. Dependency-expanded validation requires the immutable primary validation revision plus admitted `completed`, `empty` or `partial` results whose analysis/attempt/initial-packet lineage and integrity were validated by the orchestrator. T14 accepts only results relevant to at least one dependency-aware checkpoint and records exactly the revisions it consumed; unrelated admitted results remain T12/T17 inputs but are not T14 inputs. Consumed results are sorted deterministically and duplicate/stale revisions are rejected.

## 5. Attempt Selection

Selection priority:

1. Explicit internal attempt ID.
2. Explicit UE + procedure + frame/time selector.
3. Procedure/profile/subtype and request-signature match.
4. Nearest attempt in scenario time scope.

Each candidate retains score/reasons. If multiple attempts remain equally plausible and the scenario does not clearly target all of them, overall result is inconclusive with candidate list rather than silently selecting one.

## 6. Attempt Candidate Model

```python
class ScenarioAttemptCandidate(BaseModel):
    attempt_id: UUID
    score: Decimal
    matched_selectors: list[str]
    mismatched_selectors: list[str]
    ambiguous: bool
    selected: bool
```

PDU session ID alone cannot select an attempt without UE/time/procedure scope.

## 7. Checkpoint Result Model

```python
class CheckpointResult(BaseModel):
    checkpoint_id: str
    status: Literal["verified", "failed", "inconclusive", "not_applicable"]
    expected: JsonValue | None
    observed: JsonValue | None
    attempt_id: UUID | None
    evidence_ids: list[UUID]
    frames: list[int]
    reason_codes: list[str]
    visibility: str
    conflict: bool = False
```

Every failed or verified result must cite exact evidence. Inconclusive results cite missing visibility/data reasons and available boundary evidence.

## 8. Status Semantics

### Verified

Expected value/event/order/outcome is observed with sufficient correlation and visibility.

### Failed

Contradictory value/event is observed, or an applicable mandatory expectation is absent after a valid timeout on a visible interface.

### Inconclusive

Capture/interface/identity/attempt selection is insufficient, a required dependency flow was not inspected, or evidence conflicts cannot be resolved.

### Not applicable

Checkpoint condition is false for the selected procedure/profile/topology or no selected attempt falls within its defined scope.

## 9. Request Expectation Validation

Compare expected values against T05 `RequestedField`, not network-selected outcomes:

- DNN.
- S-NSSAI.
- PDU type.
- SSC mode.
- Registration/service type.
- Access/emergency indicators.

If request value is unknown due to encrypted/missing NAS, result is inconclusive. A later accepted value cannot automatically verify what the UE requested.

## 10. Outcome Validation

- Expected success: verify T04 succeeded terminal; explicit failed/timed-out terminal -> failed; incomplete capture -> inconclusive.
- Expected failure: verify terminal failure; successful attempt -> failed; incomplete -> inconclusive.
- Expected named failure stage: compare T06-T09/T12 evidence and stage results; a different failure stage is failed with observed stage.

## 11. Protocol Checkpoint Validation

Checkpoint matchers can reference allowlisted fields:

- Protocol/message/procedure/stage.
- HTTP operation/status/ProblemDetails cause.
- NAS/NGAP message/cause.
- PFCP message/cause/rule/tunnel consistency.
- Request semantic fields.
- Attempt outcome/state.
- Completed dependency inspection summaries.

Matchers operate over normalized values and exact evidence references. They cannot execute arbitrary JSONPath/regex/code.

## 12. Ordering Constraints

Validate ordered checkpoints using semantic event/stage order, then timestamps/frames. Same-frame NGAP/NAS nesting uses T10 semantic ordinal.

Supported constraints:

- A before B.
- A immediately followed by B at semantic stage level.
- A occurs at least/at most N times.
- No forbidden event between A and B.

Capture boundaries can make ordering inconclusive.

## 13. Forbidden Events

A forbidden checkpoint is:

- Verified absence only when its entire relevant interval/interface is visible.
- Failed when matching evidence is observed.
- Inconclusive when visibility is incomplete.

Do not claim "no error occurred" from an incomplete capture.

## 14. Applicability and Profiles

Use selected attempt profile facts:

- Emergency-specific conditional expectations.
- Periodic versus initial registration.
- Xn versus N2/inter-AMF handover.
- Home-routed versus local-breakout roaming.
- 3GPP versus non-3GPP access.

Scenario checkpoint conditions are evaluated using allowlisted declarative expressions and profile facts.

## 15. Dependency Checkpoints

For NRF/UDR scenario expectations:

- Initial validation can identify that dependency evidence is unavailable and mark inconclusive.
- Scenario text may support a T16 suspicion/request but cannot bypass T24/T25 request validation.
- After approved inspection, T14 may produce a dependency-expanded checkpoint revision using only returned results.
- Run one dependency-expanded validation after all selected attempts' approved inspections settle, not once per arriving result.
- Re-evaluate only checkpoints whose matcher/applicability can consume an admitted dependency result. Copy unaffected checkpoint results unchanged, including evidence IDs and reason codes.
- An `empty` result proves that the approved bounded inspection found no matching record; checkpoint status still follows visibility and expectation semantics rather than automatically becoming failed or verified.
- A `partial` result may resolve only the portion supported by valid returned evidence. Failed/invalid results do not enter validation and leave affected checkpoints inconclusive with an inspection-failure reason.

Hidden dependency events are never read directly by T14.

## 16. Evidence Conflicts

```python
class ScenarioEvidenceConflict(BaseModel):
    checkpoint_id: str
    values: list[JsonValue]
    evidence_ids: list[UUID]
    resolution: Literal["prefer_request", "prefer_explicit_terminal", "unresolved"]
    reason: str
```

Examples: explicit NAS request conflicts with SBI-derived value, mixed terminal outcomes for scoped sessions, ambiguous attempt selector.

Unresolved conflicts produce inconclusive checkpoint status.

## 17. Overall Status Aggregation

Default aggregation:

- Any required checkpoint `failed` -> overall failed.
- Else any required checkpoint `inconclusive` -> overall inconclusive.
- Else at least one applicable required checkpoint and all verified -> verified.
- All checkpoints not applicable -> not applicable.

Optional checkpoint failure is reported but does not fail overall unless scenario marks it required.

## 18. Revision and Persistence

Validation revision hash includes scenario spec, selected attempt revisions, request/stage artifacts, dependency result revisions, and validator policy version.

Dependency-expanded revisions additionally include the primary validation parent revision and the sorted revisions actually consumed by dependency-aware checkpoints. The result persists both fields so T15/T17 can verify lineage against a subset of the admitted inspection set.

```text
normalized/scenario/
  scenario_validation.json
  scenario_validation_manifest.json
```

Primary-only and dependency-expanded validations are separate immutable revisions.

## 19. Failure Semantics

- Invalid ScenarioSpec: validation error.
- No matching attempt: successful inconclusive/not-applicable according to selector scope, with reason.
- Ambiguous attempt selection: inconclusive.
- Missing request/stage artifact: affected checkpoint inconclusive; partial validation.
- Invalid matcher/condition: fail scenario validation configuration.
- Evidence checksum mismatch: affected checkpoint integrity failure; do not verify/fail from corrupt evidence.
- Publication failure: fatal.

## 20. Performance and Resource Requirements

- Use attempt/event/stage indexes; no full-capture scan per checkpoint.
- Compile matcher/condition schemas once.
- Default checkpoint count bounded by scenario parser policy.
- O(selected attempts * checkpoints * indexed matches).
- Record candidates, checkpoints/statuses, evidence lookups, dependency revisions, and latency.

## 21. Security and Privacy

- Primary evidence capabilities only; dependency results as value objects.
- Clear identifiers remain local/masked in output.
- Scenario matchers cannot run code or arbitrary queries.
- Treat scenario text/values and protocol text as untrusted.
- Reports/provider packets use T15-masked result.

## 22. Observability

Logs include scenario/attempt/checkpoint IDs, selection scores, status/reason codes, evidence counts, conflict code, revision, and duration.

Metrics include overall/checkpoint statuses, no/ambiguous attempt selection, visibility-driven inconclusive count, dependency-pending checkpoints, conflicts, and validation latency.

## 23. Proposed Python Code Structure

```text
V2/harness/scenario/
  validator.py
  attempt_selector.py
  checkpoint_matcher.py
  ordering.py
  applicability.py
  aggregation.py
  conflicts.py
V2/harness/storage/
  scenario_store.py
V2/harness/models/
  scenario.py
```

## 24. Implementation Sequence

1. Define selection/checkpoint/conflict/result schemas.
2. Implement attempt selection and ambiguity.
3. Implement request and outcome validation.
4. Implement protocol matcher and ordering constraints.
5. Add applicability/visibility/forbidden-event semantics.
6. Add dependency-expanded revisions and overall aggregation.
7. Add persistence, performance, and adversarial tests.

## 25. Tests

### 25.1 Unit tests

- Attempt selector priority/scoring/ambiguity.
- Four checkpoint status semantics.
- Request versus network-selected values.
- Outcome and named-stage validation.
- Ordering/count/forbidden event.
- Applicability and overall aggregation.
- Evidence conflict handling.
- Revision hash stability.

### 25.2 Integration tests

- Expected PDU request success and mismatch.
- Emergency/periodic registration.
- Paging/service request.
- Handover profile/topology conditions.
- Roaming local breakout versus home routed.
- Missing interface/capture truncation.
- Explicit NRF/UDR scenario before and after approved inspection.
- Multiple attempts with NRF/UDR results arriving in different orders produce one deterministic expanded validation.
- Empty, partial and failed inspections preserve correct checkpoint semantics.
- Multiple matching attempts.

### 25.3 Negative tests

- Model explanation cannot change status.
- Later accepted DNN does not verify unknown requested DNN.
- Forbidden event absence is not verified with partial visibility.
- T14 cannot open NRF/UDR readers.
- Cross-attempt, stale-parent, duplicate or integrity-invalid dependency result is rejected.

## 26. Acceptance Criteria

T14 is complete when:

1. Attempt selection is deterministic, evidence-based, and ambiguity-preserving.
2. Every verified/failed checkpoint cites exact observed evidence.
3. Inconclusive/not-applicable are used correctly for visibility and profile conditions.
4. Request expectations use T05 UE intent, not later network selection.
5. Ordering and forbidden-event checks respect capture boundaries.
6. Overall status aggregation is deterministic and configurable.
7. Dependency checkpoints require completed T24/T25 results.
8. Model narrative cannot override checkpoint status.
9. Expanded validation preserves unaffected primary checkpoints and records its parent plus exact dependency revisions.
