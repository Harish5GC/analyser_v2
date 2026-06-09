# T12 `rank_root_causes` Implementation Specification

## 1. Purpose

`rank_root_causes` combines deterministic failure candidates for one attempt and selects a primary cause, credible alternatives, and downstream symptoms. It uses explicit causal/temporal/correlation rules and baseline divergence; its score is not a statistical probability.

T12 can run twice: first on primary candidates, then after approved T24/T25 dependency inspection adds candidates/impact evidence.

## 2. Non-Goals

T12 must not:

- Generate new protocol candidates.
- Read raw/full evidence or hidden partitions directly.
- Promote an event based only on timestamp proximity.
- Always choose the earliest event.
- Treat a terminal NAS reject as automatically primary.
- Hide ambiguity to force one answer.
- Let model narrative override deterministic ranking.

## 3. Inputs and Boundary

- One T04 attempt.
- T06-T09 primary candidates.
- T07 terminal effects.
- T11 comparison/first divergence.
- Optional T23/T24/T25 dependency candidates and call-impact results.
- Versioned ranking policy.

T12 receives immutable candidate/result objects only. It cannot instantiate protocol readers.

## 4. Python Tool Contract

```python
class RankRootCausesRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt: ProcedureAttempt
    candidates: list[FailureCandidate]
    terminal_effects: list[TerminalEffect]
    comparison: AttemptComparison | None
    dependency_results: list[DependencyInspectionResult] = Field(default_factory=list)
    pass_stage: Literal["primary", "dependency_expanded"]
    ranking_policy_version: str


class RootCauseResult(BaseModel):
    schema_version: Literal["2.0"]
    attempt_id: UUID
    pass_stage: str
    primary_candidate_id: UUID | None
    alternative_candidate_ids: list[UUID]
    downstream_candidate_ids: list[UUID]
    excluded_candidate_ids: list[UUID]
    ranked_candidates: list[RankedCandidate]
    confidence: Literal["high", "medium", "low", "inconclusive"]
    rationale_codes: list[str]
    limitations: list[str]
    ranking_revision: str
```

## 5. Candidate Eligibility

A candidate is eligible when:

- It belongs to the same attempt, or
- It has an explicit supported parent/child or cross-protocol link to the attempt, or
- It is an inspected dependency event with T23 impact `causal` or `contributing`.

Candidates are ineligible when:

- Only timestamp proximity links them.
- They are resolved startup/background anomalies.
- They concern another UE/session/service without a supported link.
- They occur after terminal failure and are pure cleanup.
- They depend on an invisible/unverified interface and carry only inferred evidence.
- Their evidence references fail integrity validation.

Ineligible candidates remain persisted with exclusion reasons.

## 6. Candidate Normalization

Before scoring:

- Validate unique candidate ID and source evidence.
- Normalize severity/category/protocol.
- Attach attempt-assignment confidence.
- Attach terminal/downstream/cleanup metadata.
- Attach capture phase/relevance/call impact.
- Attach first-divergence relationship.
- Deduplicate candidates representing the same protocol event/rule outcome.

Deduplication retains the strongest evidence and all detector reason codes; it does not merge distinct failed resource items.

## 7. Causal Relationship Graph

T12 builds a small candidate graph:

```python
class CandidateRelation(BaseModel):
    source_candidate_id: UUID
    target_candidate_id: UUID
    relation: Literal[
        "CAUSES", "CONTRIBUTES_TO", "DOWNSTREAM_OF", "CLEANUP_AFTER",
        "RETRY_OF", "CONTRADICTS", "SAME_EVENT_AS", "UNRELATED"
    ]
    confidence: Decimal
    evidence_ids: list[UUID]
    rationale_codes: list[str]
```

Relations derive from explicit references, shared scoped identifiers, profile stage ordering, retry groups, terminal effects, and T23 impact. Timestamp ordering alone cannot create `CAUSES`.

Cycles in causal relations indicate inconsistent evidence; break weakest relation and record a warning.

## 8. Score Model

```text
rank_score = detector_base
           + explicit_failure_bonus
           + exact_attempt_link_bonus
           + cross_protocol_explanatory_bonus
           + first_divergence_bonus
           + terminal_explanation_bonus
           + inspected_dependency_impact_bonus
           - downstream_penalty
           - cleanup_penalty
           - recovered_retry_penalty
           - assignment_ambiguity_penalty
           - incomplete_capture_penalty
           - contradiction_penalty
```

Every term is persisted:

```python
class ScoreTerm(BaseModel):
    name: str
    value: Decimal
    rationale_code: str
    evidence_ids: list[UUID]

class RankedCandidate(BaseModel):
    candidate_id: UUID
    eligible: bool
    final_score: Decimal | None
    score_terms: list[ScoreTerm]
    rank: int | None
    classification: Literal["primary", "alternative", "downstream", "excluded"]
    exclusion_reasons: list[str]
```

Weights/thresholds are versioned configuration and included in the ranking revision hash.

## 9. Temporal Rules

- Candidate after terminal failure cannot be primary unless it explicitly exposes an earlier hidden cause through inspected/correlated evidence.
- Cleanup/release after failure is downstream.
- Earlier recovered errors are not preferred over later terminal causes.
- The first causal event is preferred only when it explains subsequent effects.
- Capture preamble events require T23 causal/contributing impact before eligibility.

Frame order is used only when timestamps are absent; same-frame embedded events use semantic ordering.

## 10. Explicit Versus Inferred Evidence

Explicit protocol rejection generally outranks a T09 missing transition describing its consequence. However, an explicit terminal NAS reject may remain downstream of an earlier explicit HTTP/PFCP failure.

An inferred missing transition may be primary when no explicit failure is visible and timeout/visibility evidence is strong.

## 11. Cross-Protocol Explanation

A candidate receives explanatory bonus when it accounts for later effects through supported links, for example:

- SBI failure -> NAS reject.
- PFCP establishment rejection -> SMF error -> PDU Session Reject.
- NGAP resource failure -> NAS release/reject.
- NRF discovery failure -> primary no-instance symptom -> UE reject, after T24/T23.
- UDR failure -> UDM/PCF response failure -> call failure, after T25/T23.

The graph must cite evidence from each link.

## 12. Baseline Divergence

T11 first divergence adds support when the candidate occurs at or explains that stage. A harmless changed UE request can explain different behavior without proving a network fault; T12 records this as request-driven divergence and may lower network-failure confidence.

No baseline is not a penalty by default.

## 13. Dependency-Expanded Reranking

On primary pass, hidden NRF/UDR events cannot appear. The result may remain inconclusive or identify a visible upstream symptom.

After T24/T25:

- Add only inspection-returned candidates/evidence.
- Require T23 impact `causal` or `contributing` for primary eligibility.
- `unrelated` is excluded.
- `inconclusive` may be alternative only with low confidence, not primary unless no stronger candidate and policy permits explicit inconclusive reporting.
- Preserve primary-pass result in report history for audit.

No third recursive pass exists.

## 14. Primary, Alternatives, and Downstream

### Primary

Highest eligible candidate satisfying minimum evidence threshold and not dominated by a stronger cause relation.

### Alternatives

Retain candidates when:

- Score is within configured margin.
- Evidence paths conflict.
- Capture visibility prevents choosing.
- Multiple independent causes may contribute.

### Downstream

Candidates explicitly caused by/after the primary, including terminal rejects and cleanup.

If no candidate meets threshold, return no primary and `confidence=inconclusive`.

## 15. Confidence Determination

`high` requires:

- Explicit or strongly inspected cause.
- Exact/strong attempt link.
- Explains terminal outcome.
- No comparable contradictory alternative.
- Sufficient visibility.

`medium`: credible cause with one material limitation/alternative.

`low`: inferred/ambiguous cause that remains useful.

`inconclusive`: no eligible cause, unresolved conflict, or insufficient capture.

Confidence is determined from evidence conditions, not score alone.

## 16. Tie Breaking

Deterministic tie order:

1. Dominates other candidate in causal graph.
2. Explicit over inferred.
3. Stronger correlation.
4. Explains terminal/first divergence.
5. Earlier causal stage/frame.
6. Protocol/rule priority from policy.
7. Candidate UUID lexical order.

## 17. Contradiction Handling

Examples:

- Candidate claims timeout but a valid response exists.
- Baseline divergence contradicts candidate stage.
- Dependency marked recovered before attempt but candidate claims causal.
- Two candidates require incompatible identity mappings.

Contradictions add score penalties, relation records, and limitations. Hard contradictions exclude a candidate.

## 18. Deterministic Revision and Persistence

Ranking revision hash includes:

- Candidate set/checksums.
- Attempt/profile revision.
- Comparison revision.
- Dependency result revisions.
- Ranking policy version/config hash.

Persist:

```text
normalized/diagnostics/root_causes.jsonl
normalized/diagnostics/candidate_relations.jsonl
normalized/diagnostics/ranking_manifest.json
```

Primary and dependency-expanded results are separate immutable revisions.

## 19. Failure Semantics

- Unknown attempt/candidate: validation error.
- Duplicate candidate ID with different content: evidence-integrity failure.
- Missing evidence for major candidate: exclude candidate and warn; fail only if all major evidence is corrupted.
- Causal graph cycle: break weakest relation, mark partial/inconclusive as needed.
- Invalid policy/weight configuration: fatal.
- No eligible candidate: successful inconclusive result.
- Publication failure: fatal.

## 20. Performance and Resource Requirements

- Candidate sets are small/bounded per attempt; default maximum before prefilter 100.
- Build O(C^2) relation comparisons only after category/stage pruning; otherwise use indexed relation generation.
- Record candidates input/eligible/excluded, relations, ranking latency, and policy revision.
- Ranking should complete in milliseconds for normal attempts.

## 21. Security and Privacy

- T12 receives summaries/evidence IDs, not raw protocol bodies.
- No direct data readers or provider calls.
- Logs contain candidate IDs/reason codes, not sensitive observed values.
- Treat candidate summaries as untrusted text when later included in model evidence.

## 22. Observability

Logs include attempt/pass stage, candidate eligibility/exclusion, score terms, relations, selected primary/alternatives, confidence, and limitations.

Metrics include primary protocol/category, inconclusive rate, alternatives count, exclusion reasons, dependency rerank changes, causal-cycle warnings, and latency.

## 23. Proposed Python Code Structure

```text
V2/harness/analysis/
  ranker.py
  candidate_eligibility.py
  candidate_dedup.py
  causal_graph.py
  scoring.py
  confidence.py
  ranking_revision.py
V2/harness/config/
  ranking.yaml
V2/harness/models/
  failures.py
```

## 24. Implementation Sequence

1. Define score term, ranked candidate, relation, and result schemas.
2. Implement validation/dedup/eligibility.
3. Implement base scoring and deterministic ties.
4. Add causal graph/downstream/cleanup relations.
5. Add terminal-effect and baseline-divergence bonuses.
6. Add dependency-expanded reranking/T23 gates.
7. Add contradiction/confidence logic and revision persistence.

## 25. Tests

### 25.1 Unit tests

- Eligibility/exclusion for every relevance/call-impact type.
- Score terms and deterministic ties.
- Cause/downstream/cleanup/retry relations.
- Cycle detection and weakest-edge removal.
- Confidence conditions.
- Deduplication and item-scoped candidates.
- Ranking revision hash.

### 25.2 Integration tests

- HTTP/PFCP cause followed by NAS reject.
- Explicit NGAP failure versus missing transition.
- Cleanup errors after terminal failure.
- Ambiguous alternatives.
- Recovered startup anomaly excluded.
- T24 NRF result changes primary ranking.
- T25 UDR result contributes but does not replace stronger visible cause.
- Capture truncation yields inconclusive.
- Changed UE request explains baseline divergence.

### 25.3 Negative tests

- Earliest timestamp alone does not win.
- Terminal NAS reject is not automatically primary.
- Unrelated/inconclusive hidden dependency cannot be promoted improperly.
- Model narrative cannot alter ranking.
- T12 cannot access event partitions.

## 26. Acceptance Criteria

T12 is complete when:

1. Candidate eligibility and exclusion are deterministic and reason-coded.
2. Every rank score is decomposed into persisted terms.
3. Causal/downstream/cleanup relationships are evidence-backed.
4. Explicit terminal effects can be demoted when an earlier cause explains them.
5. First baseline divergence influences ranking without treating harmless dynamic changes as faults.
6. Dependency candidates require approved inspection and T23 impact.
7. Ambiguity yields alternatives or inconclusive output rather than a forced answer.
8. Primary and dependency-expanded rankings are immutable/auditable.
9. No model or direct evidence-reader access exists.
