# T11 `compare_attempts` Implementation Specification

## 1. Purpose

`compare_attempts` selects relevant successful baseline attempts and compares them with a failed/incomplete attempt at semantic procedure-stage level. It identifies the first meaningful divergence and changed request/network behavior without diffing raw JSON or dynamic identifiers.

## 2. Non-Goals

T11 must not:

- Compare raw frame numbers, timestamps, UUIDs, stream IDs, SEIDs, or TEIDs as ordinary differences.
- Compare incompatible procedure, emergency, access, or roaming profiles.
- Fabricate a baseline when no suitable successful attempt exists.
- Rank root causes; T12 consumes divergence evidence.
- Read hidden NRF/UDR partitions. Dependency comparisons occur only inside T24/T25.

## 3. Inputs and Boundary

- Failed/target T04 attempt.
- Candidate successful attempts from the same identity graph/UE.
- T05 request results.
- T10 internal timelines/stage results.
- Profile registry and comparison policy version.

T11 uses primary-derived artifacts only.

## 4. Python Tool Contract

```python
class CompareAttemptsRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    failed_attempt_id: UUID
    max_baselines: int = 2
    comparison_policy: ResolvedPolicy


class CompareAttemptsResult(BaseModel):
    schema_version: Literal["2.0"]
    failed_attempt_id: UUID
    selected_baseline_id: UUID | None
    comparisons: list[AttemptComparison]
    no_baseline_reason: str | None
    warnings: list[str]
```

## 5. Baseline Candidate Eligibility

A baseline must:

- Belong to the same resolved UE. Population baselines are a deferred
  `population_baselines` capability, not a V2 behavior.
- Use the same procedure/profile family.
- Have `outcome=succeeded`.
- Precede the failed attempt. Future-success baselines belong to the same
  deferred capability.
- Have sufficient interface visibility for compared stages.
- Match emergency/non-emergency and relevant access context.
- Match roaming topology/fault-domain expectations where applicable.
- Consume the persisted T03 topology interval/revision; do not independently
  infer roaming from request strings or candidate fault domain.

Candidate is excluded when identity correlation is unresolved or profile differs materially.

## 6. Request Signature

Signature fields are profile-specific and may include:

- Procedure/subtype.
- Registration/service request type.
- DNN.
- Requested S-NSSAI.
- PDU type and SSC mode.
- Access type.
- Emergency flag.
- Roaming topology.
- Relevant QoS request class.

Dynamic values excluded by default:

- Frames/timestamps.
- Transaction sequence numbers.
- HTTP/TCP streams.
- UUIDs/correlation invocation IDs.
- SEIDs/TEIDs and allocated UE IP.
- Ephemeral ports.

A detector/profile can mark a normally dynamic value relevant, such as unexpected reuse of a SEID, but it must give a reason code.

## 7. Baseline Selection and Audit Scoring

Selection among eligible candidates is lexicographic, per the canonical
contract in `LLD.md` section 13. A later criterion can never override an
earlier one:

1. Higher request-signature similarity band. Similarity is computed as a
   versioned `Decimal` and mapped into configured bands (for example `exact`,
   `high`, `partial`); candidates are compared band-first so numeric noise
   cannot outrank the band order.
2. Within the same band, nearest earlier attempt by frame.
3. Remaining ties: lowest attempt UUID lexical order.

For audit, every considered candidate also retains a numeric score and its
components:

```text
baseline_score = same_profile_weight
               + request_signature_similarity
               + same_access_context_weight
               + same_roaming/emergency_weight
               + visibility_similarity
               + temporal_nearness_weight
               - correlation_ambiguity_penalty
               - missing_data_penalty
```

Weights are versioned. `baseline_score` exists for transparency and candidate
review only; it never overrides the lexicographic order above.

The selected baseline and all rejected top candidates retain score components/reasons for audit.

## 8. Semantic Stage Representation

```python
class ComparableStage(BaseModel):
    stage_id: str
    occurrence: int
    status: str
    operation_signature: str | None
    request_values: dict[str, JsonValue]
    response_values: dict[str, JsonValue]
    outcome: str | None
    cause: str | None
    retry_count: int
    evidence_ids: list[UUID]
```

Stages derive from profile/T04/T09, not raw packet positions.

## 9. Stage Alignment Algorithm

1. Build comparable stage sequences for failed and baseline attempts.
2. Align by profile stage ID and occurrence.
3. Resolve optional/repeatable branches using operation signature and stage role.
4. Mark stages as matched, changed, missing in failed, extra in failed, or not comparable.
5. Identify the first causally meaningful divergence after all earlier mandatory stages align.
6. Preserve later divergences as secondary.

Dynamic packet count differences do not shift semantic alignment.

## 10. Value Comparison

Comparison categories:

- Request changed.
- Network selection changed.
- Response status/cause changed.
- Retry behavior changed.
- Stage missing/extra.
- Timing class changed (normal versus timeout), using policy buckets rather than raw latency unless configured.
- Endpoint/NF role changed when visible in primary flow and semantically relevant.

Canonical comparison normalizes case/format but preserves display values and evidence.

## 11. First Divergence

```python
class AttemptDivergence(BaseModel):
    divergence_id: UUID
    stage_id: str
    category: str
    failed_value: JsonValue | None
    baseline_value: JsonValue | None
    failed_evidence_ids: list[UUID]
    baseline_evidence_ids: list[UUID]
    causal_relevance: Literal["strong", "supporting", "unknown"]
    rationale: str
```

The first divergence must not be a harmless dynamic difference. If the first changed request parameter explains expected behavior, report it explicitly rather than labelling the network faulty.

## 12. Repeated Attempts

For a tenth failed establishment after nine successes:

- Select the closest prior success with matching request signature.
- Optionally retain a second baseline if the closest differs materially or evidence is partial.
- Do not aggregate all nine into model context.
- Record whether the failure is a one-off divergence or follows a trend in retry/timing outcomes.

Population/statistical trend analysis belongs to the deferred `population_baselines` capability.

## 13. Procedure-Specific Rules

- Emergency attempts compare only with equivalent emergency policy where possible.
- Periodic registration compares with periodic, not initial registration.
- Mobility/handover compares same handover type and source/target topology.
- Home-routed and local-breakout roaming are not interchangeable.
- PDU establishment requires compatible DNN/slice/PDU type unless the changed request itself is the intended divergence.

## 14. Comparison Result Model

```python
class AttemptComparison(BaseModel):
    comparison_id: UUID
    failed_attempt_id: UUID
    baseline_attempt_id: UUID
    baseline_score: Decimal
    baseline_reasons: list[str]
    request_differences: list[FieldDifference]
    stage_alignment: list[StageAlignment]
    first_divergence: AttemptDivergence | None
    later_divergences: list[AttemptDivergence]
    visibility_limitations: list[str]
    evidence_ids: list[UUID]
```

## 15. No-Baseline Behavior

Return no comparison when:

- No prior successful same-profile attempt exists.
- Identity is unresolved.
- Candidate visibility is too different.
- Only incompatible emergency/roaming/access attempts exist.

This is a normal result with `no_baseline_reason`; it does not lower deterministic diagnosis by itself.

## 16. Deterministic IDs and Caching

Comparison ID is UUIDv5 of failed attempt revision + baseline revision + policy version.

Cache by those revision checksums. Changed profiles, request extraction, or comparison policy create a new immutable comparison revision.

## 17. Persistence

```text
normalized/comparisons/
  attempt_comparisons.jsonl
  baseline_candidates.jsonl
  comparison_manifest.json
indexes/
  failed_attempt_comparison_index.jsonl
```

Manifest records input revisions, policy version, candidate counts, no-baseline reasons, artifacts, timing, and warnings.

## 18. Failure Semantics

- Unknown failed attempt: validation error.
- No suitable baseline: successful empty result.
- Missing T05/T10 artifact for a candidate: exclude candidate and warn.
- Profile version mismatch: exclude/inconclusive unless compatible migration exists.
- Ambiguous identity: no baseline or lower score according to policy.
- Alignment exception for one baseline: skip baseline, mark partial.
- Publication/index failure: fatal.

## 19. Performance and Resource Requirements

- Use UE/profile/request-signature indexes to select a small baseline set.
- Do not compare every attempt in the capture.
- Default candidate shortlist <= 20 before detailed alignment.
- O(shortlisted baselines * semantic stages).
- Record shortlist size, selected score, alignment stages, cache hit, and latency.

## 20. Security and Privacy

- Primary-derived data only.
- Compare masked identities and semantic request values.
- Do not include full bodies or clear identifiers.
- Treat request/body text as untrusted.

## 21. Observability

Logs include failed/baseline attempt IDs, eligibility decisions, score components, selected baseline, divergence stage/category, no-baseline reason, and duration.

Metrics include baseline availability, candidate shortlist size, selected similarity, first divergence category, no-baseline reasons, cache hit rate, and latency.

## 22. Proposed Python Code Structure

```text
V2/harness/analysis/
  compare.py
  baseline_selector.py
  request_signature.py
  stage_alignment.py
  semantic_diff.py
V2/harness/storage/
  comparison_store.py
V2/harness/models/
  comparisons.py
```

## 23. Implementation Sequence

1. Define signature, baseline score, alignment, and divergence schemas.
2. Implement candidate eligibility and scoring.
3. Implement profile stage projection/alignment.
4. Implement semantic value diff and dynamic exclusions.
5. Add procedure-specific compatibility rules.
6. Add persistence/cache and performance fixtures.

## 24. Tests

### 24.1 Unit tests

- Baseline eligibility and deterministic scoring/ties.
- Dynamic value exclusion.
- Optional/repeatable stage alignment.
- First divergence selection.
- Request versus network-selection difference.
- No-baseline reasons.
- Comparison UUID/cache key stability.

### 24.2 Integration tests

- Nine successful cycles and tenth failure.
- Changed DNN/slice/PDU type.
- Same request, changed HTTP/PFCP response.
- Emergency/periodic/mobility profile matching.
- Xn versus N2 handover incompatibility.
- Home-routed versus local-breakout roaming.
- Partial visibility baseline excluded.

### 24.3 Negative tests

- Frame/SEID/TEID changes alone do not create divergence.
- Different UE is not selected.
- Future success is never selected; the `population_baselines` capability is deferred.
- Hidden NRF/UDR traffic is not compared.

## 25. Acceptance Criteria

T11 is complete when:

1. Baselines are selected using explicit, versioned eligibility and scoring.
2. Comparisons align semantic stages rather than packet positions.
3. Dynamic identifiers do not produce false divergence.
4. First divergence cites failed and baseline evidence.
5. Request changes are distinguished from network behavior changes.
6. Procedure/emergency/roaming/access incompatibilities prevent bad baselines.
7. No-baseline is handled explicitly without fabrication.
8. Results are deterministic, cacheable, and primary-only.
