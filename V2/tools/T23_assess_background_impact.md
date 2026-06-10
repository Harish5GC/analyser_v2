# T23 `assess_background_impact` Implementation Specification

## 1. Purpose

`assess_background_impact` determines whether a pre-call, concurrent-background, or infrastructure anomaly returned by an approved NRF/UDR inspection caused, contributed to, did not affect, or cannot conclusively be linked to one UE attempt.

It is the causal gate preventing startup noise from becoming a call root cause merely because it occurred earlier in the capture.

## 2. Invocation Boundary

T23 runs only inside T24/T25 after hidden dependency evidence has been retrieved through an approved request. It receives bounded result objects/events and cannot open NRF/UDR readers itself.

It cannot assess uninspected hidden events.

## 3. Non-Goals

T23 must not:

- Promote an anomaly using timestamp proximity alone.
- Treat every unresolved infrastructure event as causal.
- Override T12 ranking; it supplies eligibility/impact evidence.
- Infer dependency health for services not selected/used by the attempt.
- Read complete captures or perform new inspection.
- Reclassify recovered startup cleanup as failure without recurrence.

## 4. Python Tool Contract

```python
class AssessBackgroundImpactRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    approved_request_id: UUID
    attempt: ProcedureAttempt
    initial_packet_id: UUID
    initial_symptom_evidence_ids: list[UUID]
    dependency_type: Literal["NRF", "UDR"]
    dependency_events: list[DependencyEventSummary]
    lifecycle: BuildNFLifecycleResult | None
    dependency_comparison: DependencyBaselineComparison | None
    impact_policy: ResolvedPolicy


class AssessBackgroundImpactResult(BaseModel):
    schema_version: Literal["2.0"]
    impact_id: UUID
    approved_request_id: UUID
    attempt_id: UUID
    call_impact: Literal["causal", "contributing", "unrelated", "inconclusive"]
    primary_dependency_event_ids: list[UUID]
    supporting_event_ids: list[UUID]
    recovery_frame: int | None
    causal_path: list[CausalLink]
    promotion_conditions: list[str]
    demotion_conditions: list[str]
    contradictions: list[str]
    missing_evidence: list[str]
    counterfactual_supported: bool | None
    decision_trace: list[ImpactDecisionStep]
    confidence: Literal["high", "medium", "low", "inconclusive"]
```

## 5. Required Evidence Domains

T23 evaluates four domains:

1. Dependency anomaly/state.
2. Attempt-required dependency/service/resource.
3. Visible primary symptom cited by initial model request.
4. Temporal/profile ordering and recovery.

A causal conclusion generally requires evidence in at least the first three domains plus compatible ordering.

## 6. Strong Promotion Conditions

At least one strong condition is mandatory for `causal` or `contributing`:

- Same exact NF instance ID selected/used by call.
- Same service/API/version and discovery returned no healthy instance.
- Exact endpoint selected by consumer is unavailable/stale.
- NF required service remains unavailable at attempt start and attempt fails at that stage.
- Explicit primary call-time error references the dependency operation/state/resource.
- UDR transaction exact consumer + masked subscriber/context + operation correlates to visible UDM/PCF/NEF failure.
- First divergence from equivalent success is dependency readiness/transaction outcome.

Timestamp/endpoint/NF-type similarity alone are supporting only.

## 7. Demotion Conditions

Strong demotion:

- Failure recovered before attempt start and required service was ready.
- Anomaly concerns unused instance/service/resource/subscriber context.
- Expected idempotent cleanup such as stale DELETE 404 followed by healthy registration.
- UE attempt succeeds despite anomaly.
- Alternate healthy NF was selected and call dependency completed.
- UDR error belongs to another consumer/subscriber/operation.

Supporting demotion:

- Only temporal overlap/proximity.
- Low-confidence entity mapping.
- Capture starts after likely recovery/history.

## 8. Impact Semantics

### Causal

Dependency anomaly is the earliest supported cause explaining the primary symptom and terminal failure; without it, evidence indicates the attempt could have progressed.

### Contributing

Dependency anomaly materially worsened/participated in failure but another independent/earlier cause exists, or evidence supports impact without exclusive causality.

### Unrelated

Evidence demonstrates recovery, different entity/resource, successful bypass/alternate, or successful attempt despite anomaly.

### Inconclusive

Evidence is insufficient/conflicting: missing selection mapping, incomplete capture, ambiguous identity, no visible causal bridge.

### 8.1 Executable decision table

T23 executes the following gates in order. Later rows cannot override an
earlier terminal result except where the row explicitly says to continue.

| Order | Gate | Deterministic rule | Outcome/action |
|---:|---|---|---|
| 1 | Input eligibility | Approved request/attempt/initial symptom lineage and at least one dependency event are valid | Invalid lineage fails inspection; no event produces `inconclusive` or `unrelated` only when positive non-use/recovery evidence exists |
| 2 | Requirement mapping | Map the attempt stage to exact dependency instance/service/resource/context/operation | No supported mapping -> `inconclusive`; explicit different/unused mapping -> `unrelated` |
| 3 | Causal-link construction | Build strong/supporting/contradictory links from hidden anomaly through selection/propagation to visible symptom and failed stage | No strong promotion link means `unrelated` when a strong demotion exists, otherwise `inconclusive` |
| 4 | Temporal reachability | Cause is unresolved before the symptom/stage; post-terminal cleanup is excluded | Impossible ordering -> `unrelated`; unknown ordering -> `inconclusive`; otherwise continue |
| 5 | Recovery/bypass | Evaluate recovery before required stage, healthy alternate selection, retry success and attempt success | Proven recovery/bypass/success -> `unrelated`; partial/late recovery is recorded and continues |
| 6 | Hard contradictions | Evaluate section 13 after links and temporal facts exist | Contradiction disproving same dependency -> `unrelated`; unresolved hard contradiction -> `inconclusive`; no hard contradiction -> continue |
| 7 | Earliest-cause ordering | Compare dependency anomaly with other independently supported attempt causes and first divergence | Earlier independent cause present -> dependency cannot be `causal`; continue as possible `contributing` |
| 8 | Counterfactual | Ask only from evidence: if this dependency anomaly were absent, do healthy alternate/baseline/profile facts show the attempt could reach the failed stage? | Supported and dependency is earliest complete causal path -> `causal`; false/contradicted -> not causal; unknown -> possible `contributing`/`inconclusive` |
| 9 | Final classification | Apply the rules below | Exactly one terminal impact and confidence are emitted |

Final classification precedence:

1. `unrelated` for proved non-use, different context, pre-stage recovery,
   successful bypass/alternate, successful attempt, or impossible timing.
2. `inconclusive` for missing requirement mapping/causal bridge, ambiguous
   identity, unknown temporal order, incomplete visibility or unresolved hard
   contradiction.
3. `causal` only when there is a complete strong path, valid ordering, no hard
   contradiction, the dependency is the earliest supported cause, and the
   evidence-backed counterfactual is true.
4. `contributing` when a complete/strong impact path exists and the anomaly
   materially worsened or blocked progression, but another earlier/independent
   cause exists, exclusivity/counterfactual is not proved, or recovery occurred
   only after material delay/failure.

Section 6 conditions gate eligibility only. No single promotion condition is
sufficient for `causal`; causal requires sections 9-13 plus the ordered table.

```python
class ImpactDecisionStep(BaseModel):
    order: int
    gate: str
    result: Literal["pass", "fail", "unknown", "not_applicable"]
    reason_codes: list[str]
    evidence_ids: list[UUID]
    terminal_impact: Literal["causal", "contributing", "unrelated", "inconclusive"] | None
```

Every gate appends one trace row. Policy tables define reason-code membership,
not execution order. The trace and input revisions make classification
replayable without model interpretation.

## 9. Causal Link Model

```python
class CausalLink(BaseModel):
    from_evidence_id: UUID
    to_evidence_id: UUID
    relation: Literal[
        "SAME_INSTANCE", "SAME_SERVICE", "SELECTED_ENDPOINT", "SAME_CONTEXT",
        "PROPAGATED_ERROR", "PRECEDES_STAGE_FAILURE", "BASELINE_DIVERGENCE",
        "RECOVERED_BEFORE", "ALTERNATE_SUCCEEDED"
    ]
    strength: Literal["strong", "supporting", "contradictory"]
    rationale: str
```

The causal path must connect hidden anomaly to visible initial symptom and attempt stage. Gaps are recorded in `missing_evidence`.

## 10. Temporal Rules

- Dependency cause must occur/be unresolved before the stage symptom it explains.
- Recovery before attempt/stage demotes unless the failure recurs.
- Recovery after terminal failure does not erase causality but is recorded.
- Post-call cleanup cannot cause an earlier failure.
- Concurrent background event requires explicit dependency link, not overlap.

Use frame ordering as fallback when timestamp unavailable.

## 11. Attempt Requirement Mapping

Determine what dependency the attempt actually required from:

- Primary symptom/operation.
- Procedure profile stage.
- Consumer NF/service request.
- Discovery criteria/selected endpoint.
- UDR consumer/resource/operation and masked context.

Generic NF type availability does not prove this attempt required a particular instance.

## 12. Baseline Support

Dependency comparison can strengthen but not create causality alone:

- Prior equivalent success used healthy dependency/service/operation.
- Failed attempt first diverges at dependency state/response.
- Request parameters remain equivalent.

Different request/context reduces baseline relevance.

## 13. Contradiction Handling

Examples:

- Lifecycle says ready but discovery says none available.
- Dependency failure recovered, yet primary symptom later claims unavailable.
- Selected endpoint differs from failed instance.
- Attempt succeeds but hidden error exists.

Hard contradiction prevents `causal`; result becomes unrelated/inconclusive depending evidence. Preserve all contradiction evidence.

A contradiction is evaluated after temporal and selection links are built.
It cannot be used as a generic score penalty. Contradictions proving a
different entity/context or successful bypass are `unrelated`; contradictions
caused by incomplete/ambiguous evidence are `inconclusive`.

## 14. Confidence Rules

High causal confidence requires exact entity/context, direct visible propagation/selection link, correct ordering, and no strong contradiction.

Medium: strong service/context link with one missing hop/partial capture.

Low: contributing/inconclusive with supporting links only.

Confidence is condition-based, not a numerical probability.

## 15. Candidate Generation for T12

T23 does not create arbitrary candidates, but inspection may wrap the key dependency event as a `FailureCandidate` with:

- `relevance=dependency_related` or `unresolved_infrastructure`.
- `call_impact` from T23.
- Exact causal path/rationale/evidence.
- Detector score based on explicit hidden failure.

T12 eligibility requires `causal` or `contributing`. `unrelated` is excluded; `inconclusive` remains non-primary by default.

## 16. Deterministic Impact ID and Revision

Impact ID UUIDv5 includes approved request, attempt, dependency result revision, initial packet/symptom IDs, and policy version. Same inputs yield same result.

## 17. Persistence

Stored under dependency request artifact:

```text
evidence/dependency/<request-id>/
  background_impact.json
  causal_links.jsonl
```

The result contains summaries/references, not complete hidden records.

## 18. Failure Semantics

- Invocation without approved request/initial symptom IDs: reject.
- Dependency result for another attempt/request: reject.
- No matching dependency event: inconclusive or unrelated according to evidence, not failure.
- Missing lifecycle for UDR: allowed; use transaction correlation.
- Missing visible symptom evidence: inconclusive and validation warning.
- Contradictory/corrupt evidence: inconclusive/evidence-integrity failure.
- Policy error/publication failure: fail inspection stage.

## 19. Performance and Resource Requirements

- Operate on bounded inspection result, usually tens/hundreds of events.
- Build indexed links by instance/service/context/operation.
- O(events + candidate links), avoid all-pairs where selectors exist.
- Record events/links/conditions/contradictions, result, and latency.

## 20. Security and Privacy

- Value objects only; no partition readers.
- Sensitive UDR/subscriber values remain masked.
- Do not log entity/context values or body details.
- Treat rationales/details as untrusted text.
- Persist approved request and evidence references for audit.

## 21. Observability

Logs include request/attempt/dependency type, impact/confidence, promotion/demotion/contradiction codes, causal-link count, recovery frame, and duration.

Metrics include impact outcomes by dependency, promotion/demotion conditions, recovered-before-call count, timestamp-only rejection, contradictions, and latency.

## 22. Proposed Python Code Structure

```text
V2/harness/dependency_tools/
  impact_common.py
  causal_links.py
  impact_policy.py
V2/harness/dependency_tools/nrf/
  impact.py
V2/harness/dependency_tools/udr/
  impact.py
V2/harness/models/
  dependency.py
  failures.py
```

## 23. Implementation Sequence

1. Define impact/causal-link/condition schemas.
2. Implement temporal/recovery and attempt-requirement mapping.
3. Implement NRF instance/service/selection links.
4. Implement UDR consumer/context/operation links.
5. Add baseline/contradiction/confidence rules.
6. Add T12 candidate adapter/persistence/audit tests.

## 24. Tests

### 24.1 Unit tests

- Every promotion/demotion condition.
- Every decision-table row and terminal short-circuit.
- Causal requires complete path, earliest-cause ordering, true counterfactual
  and no hard contradiction.
- Contributing with earlier independent cause or unknown exclusivity.
- Temporal ordering and recovery before/after call.
- Exact versus supporting entity/context links.
- Causal/contributing/unrelated/inconclusive semantics.
- Contradiction and confidence rules.
- Deterministic impact ID.

### 24.2 Integration tests

- NRF cleanup 404 recovered before call -> unrelated.
- Unresolved selected NF/service -> causal.
- Failed unused NF instance -> unrelated.
- Alternate healthy NF selected -> unrelated.
- UDR error propagated through UDM -> causal.
- UDR retry delay contributes alongside another failure.
- Baseline dependency divergence support.
- Capture starts mid-lifecycle -> inconclusive.

### 24.3 Negative tests

- Timestamp proximity alone never promotes.
- Uninspected hidden event cannot be assessed.
- Event after terminal cannot cause earlier failure.
- T23 cannot open NRF/UDR readers.

## 25. Acceptance Criteria

T23 is complete when:

1. Causal/contributing outcomes require at least one strong evidence link.
2. Recovery before attempt and unrelated entity/resource explicitly demote anomalies.
3. Every conclusion includes a visible-to-hidden causal path or missing-evidence explanation.
4. Contradictions and capture uncertainty remain explicit.
5. T12 receives impact-gated candidate metadata.
6. Uninspected hidden events cannot influence results.
7. Results are deterministic, bounded, privacy-safe, and auditable.
