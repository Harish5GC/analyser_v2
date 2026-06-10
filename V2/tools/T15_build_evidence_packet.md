# T15 `build_evidence_packet` Implementation Specification

## 1. Purpose

`build_evidence_packet` creates the only protocol/evidence payload sent to a model. It converts deterministic results into a compact, schema-described, privacy-filtered packet that fits the configured model context.

T15 supports an initial primary-only packet and one dependency-expanded packet after approved T24/T25 inspection.

## 2. Non-Goals

T15 must not:

- Parse raw PCAP or decoder artifacts directly.
- Diagnose or rerank failures.
- Include hidden NRF/UDR events in the initial packet.
- Retrieve unbounded full records or packet context.
- Let body/scenario text act as model instructions.
- Drop primary evidence merely to retain verbose alternatives.

## 3. Inputs and Boundary

Initial inputs:

- T05 UE request result.
- T04 attempt summary.
- T12 primary root-cause result and selected candidates.
- T10 model timeline.
- T11 comparison.
- T14 scenario validation.
- Bounded exact evidence records resolved through T18.

Expanded inputs add admitted T24/T25 `DependencyInspectionResult` objects, the dependency-expanded T12 result, and the latest applicable T14 revision. Admitted means published status `completed`, `empty` or `partial` with validated lineage/integrity. T15 never receives NRF/UDR readers.

## 4. Python Tool Contracts

```python
class TokenCounterSpec(BaseModel):
    method: Literal["pinned_tokenizer", "utf8_bytes_v1"]
    tokenizer_id: str
    tokenizer_version: str
    vocabulary_checksum: str | None = None
    canonical_serialization: Literal["canonical_json_v1"] = "canonical_json_v1"


class ResolvedTokenBudget(BaseModel):
    context_window_tokens: int
    configured_input_cap: int
    hard_input_cap: int
    reserved_system_tokens: int
    reserved_output_tokens: int
    provider_framing_tokens: int
    safety_margin_tokens: int
    target_min_tokens: int
    target_max_tokens: int
    effective_input_tokens: int
    soft_target_tokens: int
    counter: TokenCounterSpec


class EvidencePacketConfig(BaseModel):
    target_min_tokens: int = 2000
    target_max_tokens: int = 8000
    hard_input_cap: int = 12000
    safety_margin_tokens: int = 256
    max_alternatives: int = 5
    max_timeline_items: int = 20
    max_comparisons: int = 2


class BuildInitialEvidenceRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt_id: UUID
    provider_mode: Literal["local", "openrouter"]
    token_budget: ResolvedTokenBudget
    config: EvidencePacketConfig


class BuildExpandedEvidenceRequest(BaseModel):
    initial_packet: EvidencePacket
    dependency_results: list[DependencyInspectionResult]
    expanded_root_cause: RootCauseResult
    scenario_validation: ValidateScenarioResult | None
    token_budget: ResolvedTokenBudget


class BuildEvidencePacketResult(BaseModel):
    packet: EvidencePacket
    artifact: ArtifactDescriptor
    token_count: int
    token_counter: TokenCounterSpec
    truncations: list[EvidenceTruncation]
    warnings: list[str]
```

## 5. Evidence Packet Schema

```python
class EvidencePacket(BaseModel):
    schema_version: Literal["2.0"]
    packet_id: UUID
    analysis_id: UUID
    pass_stage: EvidenceStage
    token_budget: ResolvedTokenBudget
    task: Literal["diagnose_failed_attempt"]
    schema_guide: EvidenceSchemaGuide
    ue: MaskedUEIdentity
    ue_request: UERequestEvidence
    attempt: AttemptEvidence
    primary_failure: FailureEvidence | None
    alternatives: list[FailureEvidence]
    downstream_effects: list[FailureEvidence]
    timeline: list[TimelineEvidence]
    comparison: AttemptComparisonEvidence | None
    scenario_results: list[CheckpointEvidence]
    evidence: list[EvidenceRecord]
    dependency_tools_available: list[DependencyToolDescriptor]
    dependency_evidence: list[DependencyInspectionEvidence]
    deterministic_limitations: list[str]
    warnings: list[str]
    parent_packet_id: UUID | None
    root_cause_revision: str
    scenario_validation_revision: str | None
    dependency_result_revisions: list[str]
```

## 6. Initial Versus Expanded Invariants

`pass_stage` uses the shared `EvidenceStage` enum (`LLD.md` section 4.10):
the packet built at stage `primary` is the "initial packet" consumed by the
initial model pass; the packet built at stage `dependency_expanded` is
consumed by the single final model pass.

### Initial packet

- `pass_stage=primary`.
- `parent_packet_id=None`.
- `root_cause_revision` identifies the immutable primary T12 result.
- `scenario_validation_revision` identifies the primary T14 result when a scenario exists.
- `dependency_result_revisions=[]`.
- `dependency_evidence=[]`.
- No detailed NRF/UDR transaction, status, frame, lifecycle, or failure summary.
- May state only that NRF/UDR inspection tools exist and include primary-flow suspicions/target hints.

### Expanded packet

- Derived from the exact initial packet ID.
- Includes only validated T24/T25 result summaries/evidence.
- Requires a dependency-expanded T12 result whose parent is the initial packet's primary ranking revision and whose consumed dependency revisions exactly equal the admitted result set.
- Uses the latest applicable T14 revision. This may remain the primary revision when no checkpoint consumes dependency evidence. When dependency checkpoints were revalidated, the supplied revision must descend from the primary scenario revision and consume the same applicable result revisions.
- Filters run-level scenario checkpoint content to the selected attempt while retaining the run-level validation revision for lineage.
- Replaces model-visible primary/alternative/downstream/scenario sections with the revised deterministic values; it does not merely append dependency evidence to stale initial conclusions.
- Does not add unrelated hidden events.
- Marks tool request, validation, query scope, and result revision.
- Sets `parent_packet_id` to the initial packet, records all deterministic input revisions, and receives a new packet ID.

Packet validation rejects invariant violations.

## 7. Content Priority

Mandatory priority order:

1. Task/schema guide and evidence-use rules.
2. UE request and attempt identity/profile/outcome.
3. Primary deterministic candidate and exact evidence.
4. Terminal/downstream effects needed to explain failure.
5. Failed/inconclusive required scenario checkpoints.
6. First baseline divergence.
7. Bounded timeline.
8. Alternative candidates.
9. Additional successful/context evidence.

Dependency-expanded packets treat causal/contributing inspection evidence as mandatory after the initial primary content.

## 8. Evidence Record Model

Evidence identity is owned by the evidence registry (`LLD.md` section 24).
T15 **selects and re-serializes** existing registry records into the packet
form below; it never mints `evidence_id` values. Every `evidence_id` in a
packet must already resolve through T18 without the packet existing.

```python
class PacketEvidenceRecord(BaseModel):
    evidence_id: UUID
    source_event_ids: list[UUID]
    frames: list[int]
    protocol: str
    record_type: str
    observed: dict[str, JsonValue]
    source_refs: list[CompactSourceRef]
    exact: bool
    masked: bool
    truncated: bool
```

`PacketEvidenceRecord` is the masked, bounded packet projection of the
canonical `EvidenceRecord`; `evidence_id`, `source_event_ids`, `frames` and
`record_type` are copied unchanged from the registry record. `observed` uses
allowlisted semantic fields. Full bodies/trees are not embedded; small exact
excerpts are permitted only when essential and policy-safe.

## 9. Schema Guide

Small models need field meaning. Include a compact guide explaining:

- Candidate IDs and evidence IDs are references, not natural language.
- `observed` versus `inference`.
- Timeline labels.
- Confidence/limitations.
- Initial dependency requests and final no-tool rule.
- Hidden NRF/UDR absence does not prove success/failure.

The guide is versioned and counted in the token budget.

## 10. Token Budget Calculation

The orchestrator resolves provider/model limits and the counting method once at
startup. T15 never probes tokenizer availability or changes methods during a
run. The same immutable `ResolvedTokenBudget` is supplied to T15 and validated
again by T16.

```text
available_input = context_window_tokens
                - reserved_system_tokens
                - reserved_output_tokens
                - provider_framing_tokens
                - safety_margin_tokens

effective_input_tokens = min(
    available_input,
    configured_input_cap,
    hard_input_cap,
)

soft_target_tokens = min(target_max_tokens, effective_input_tokens)
```

All values must be positive and internally consistent; a non-positive
`effective_input_tokens` is a provider/model configuration failure before T15.
The local default `hard_input_cap` is 12,000. Remote/provider profiles may set
a lower cap. `target_min_tokens` and `target_max_tokens` are quality targets,
not alternate hard limits.

`reserved_system_tokens` is counted from the exact versioned system prompt and
response schema with the selected counter. `provider_framing_tokens` comes
from the pinned provider/model profile. `reserved_output_tokens` equals the
validated T16 maximum output setting.

### 10.1 Deterministic counting method

`pinned_tokenizer` names an installed tokenizer artifact/version and optional
vocabulary checksum. If that exact artifact is unavailable, startup fails
unless configuration explicitly selected the fallback profile; the run never
silently switches counters.

`utf8_bytes_v1` counts one token per byte of canonical UTF-8 JSON. It is
deliberately conservative and deterministic, including escaped strings,
Unicode and numeric text. It may be used only for provider/model profiles whose
conformance corpus proves actual token count never exceeds this estimate.
Unsupported tokenizers require a new validated counter profile.

Provider-reported token usage and remotely reported tokenizer counts are
observability data only; they never change trimming or packet identity.

Build incrementally using canonical serialization and recompute after each
content block. Optional content stops at `soft_target_tokens`. Mandatory
content may exceed the soft target but must not exceed
`effective_input_tokens`.

### 10.2 Below-target and over-budget behavior

When `effective_input_tokens < target_min_tokens`, T15 builds a mandatory-only
packet first and emits `T15_TOKEN_BUDGET_BELOW_TARGET`. Optional content is
added only if it still fits. This is not a construction failure by itself.

If mandatory content exceeds `effective_input_tokens`, T15 fails with
`T15_EVIDENCE_BUDGET_EXCEEDED`, records per-block counts and never removes the
mandatory evidence guarantee.

## 11. Trimming Algorithm

1. Remove repetitive successful timeline items.
2. Collapse retry groups to summaries.
3. Remove alternatives beyond configured maximum (default five).
4. Reduce baseline to first divergence and key matched stages.
5. Shorten nonessential text/details.
6. Replace large observed structures with field-presence/size/checksum summaries.
7. Paginate/defer secondary evidence.

Never remove:

- UE request fields needed to answer the task.
- Primary candidate ID/observations/evidence.
- Terminal effect needed for causal chain.
- Failed required scenario checkpoint evidence.
- Model-output schema/rules.
- Deterministic limitations.

If mandatory content exceeds budget, return a construction error or create a smaller evidence plan; do not silently omit primary evidence.

## 12. Full Evidence Selection

T15 may request T18 for:

- Complete record backing the primary candidate.
- Exact cause/status/field omitted from normalized candidate.
- Bounded records backing a failed checkpoint or first divergence.

It must specify exact event/evidence IDs. It cannot issue broad frame/capture queries; T19/T20 are orchestrator-controlled evidence tools.

## 13. Timeline Selection

Use T10 model mode. Retain:

- Trigger/request.
- Major state transitions.
- Relevant retries.
- Primary/alternative failure points.
- Terminal UE effect.
- Cleanup only when it clarifies downstream behavior.

Maximum default 20 items. Every timeline item cites evidence.

## 14. Alternative and Comparison Limits

- Alternatives default maximum five after deterministic rank.
- Comparisons maximum two, but packet normally includes selected baseline only.
- Baseline body contains request similarity, matched earlier stages, first divergence, and evidence.
- Do not include all previous attempts.

## 15. Privacy Policy

### Local provider

Use configured local masking policy; secrets/authorization/authentication material remain excluded.

### OpenRouter

Mandatory masking:

- SUPI/SUCI/GPSI/GUTI/PEI.
- UE IP and private endpoint details according to policy.
- Authorization/cookie/cert headers.
- Authentication vectors/keys.
- Full subscription/profile bodies.
- Potentially identifying free text.

Masking must preserve stable aliases within the packet so correlations remain understandable.

## 16. Prompt-Injection Isolation

Evidence body/detail/scenario strings are untrusted quoted data. T15:

- Separates system instructions from evidence JSON.
- Adds type/field labels.
- Escapes/control-character normalizes strings.
- Limits text lengths.
- Flags text that resembles instructions without deleting forensic content from local evidence.

The model prompt instructs it not to follow evidence-embedded instructions.

## 17. Dependency Tool Descriptor

Initial packet exposes only tool schemas and constraints:

```python
class DependencyToolDescriptor(BaseModel):
    tool: Literal["inspect_nrf_flow", "inspect_udr_flow"]
    purpose: str
    required_arguments: list[str]
    allowed_reason_codes: list[str]
    maximum_requests: int
```

No hidden counts, failure hints, or flow summaries are leaked through the descriptor.

## 18. Deterministic Packet ID and Persistence

Packet ID UUIDv5 includes input revision hashes, pass stage, provider privacy
mode, schema-guide version, the complete resolved token budget, counter method,
tokenizer/version/checksum and canonical-serialization version. The resulting
packet ID is assigned before the final provider-bound count; token count is
stored and validated but is not an input to its own identifier.

For an expanded packet, input revisions include the parent packet ID, expanded T12 revision, applicable T14 revision and sorted dependency-result revisions. Rebuilding with the same logical inputs in a different completion order must produce the same packet ID.

```text
evidence/packets/
  <packet-id>.json
  evidence_packet_manifest.jsonl
```

Persist local packet and a provider-bound checksum/metadata record. Do not persist API keys. Remote packet persistence follows privacy policy.

## 19. Validation

Before publication/provider call:

- Pydantic/schema validation.
- Evidence/candidate IDs resolve and belong to attempt.
- Frame numbers exist in cited evidence.
- Initial dependency invariant holds.
- Masking policy passes.
- Token budget passes.
- Text/control/depth/size limits pass.

Invalid packet never reaches T16.

## 20. Failure Semantics

- Missing primary candidate evidence: fail packet construction, unless deterministic result is explicitly inconclusive with no candidate.
- Unresolvable secondary evidence: omit with warning.
- Effective budget below target minimum: publish a valid mandatory-first packet
  with `T15_TOKEN_BUDGET_BELOW_TARGET` when mandatory content fits.
- Mandatory content exceeds effective budget: fail with
  `T15_EVIDENCE_BUDGET_EXCEEDED` and detailed block counts/sizes.
- Masking failure: fatal for remote provider.
- Dependency result belongs to another attempt/packet: reject.
- Expanded T12/T14 lineage does not match the initial packet or admitted dependency revisions: reject.
- Failed, unpublished, duplicate, stale or integrity-invalid inspection result: reject.
- Hidden NRF/UDR detail in initial packet: fatal invariant violation.
- Publication failure: fatal.

## 21. Performance and Resource Requirements

- Build from bounded indexed results.
- Avoid repeated serialization/tokenization by caching block estimates.
- Do not materialize unbounded full records.
- Record build latency, token estimate/actual usage later, block sizes, trims, evidence lookups, and masking time.
- Typical packet build should remain below model latency by orders of magnitude.

## 22. Security Requirements

- T15 accepts only validated deterministic result objects and bounded T18 responses.
- It has no direct access to PCAP files, decoder directories, event partitions, or provider credentials.
- All IDs, frames, source references, and dependency results are validated against the selected analysis/attempt revision.
- Remote masking is fail-closed: a masking or policy validation error prevents provider submission.
- Packet JSON depth, string length, list counts, and total bytes are bounded before serialization.
- Evidence and scenario text is treated as untrusted data and cannot alter system instructions or tool policy.
- Persisted packets use run-directory path validation, restrictive permissions, checksums, and atomic publication.
- Production logs contain packet IDs/checksums and sizes only, never packet content.

## 23. Observability

Logs include packet/attempt/pass stage/provider mode, token budget/estimate, block counts, truncation codes, masking policy, validation status, and duration. Never log packet contents in production.

Metrics include packets by stage/provider, token sizes, truncation types, budget failures, masking failures, lookup counts, and latency.

## 24. Proposed Python Code Structure

```text
V2/harness/evidence/
  initial_builder.py
  expanded_builder.py
  block_selector.py
  schema_guide.py
  token_budget.py
  tokenizer.py
  masking.py
  injection_guard.py
  packet_validator.py
V2/harness/models/
  evidence.py
V2/harness/schemas/
  evidence_packet.schema.json
```

## 25. Implementation Sequence

1. Define packet/evidence/tool descriptor schemas.
2. Implement primary block selection and ID validation.
3. Implement tokenizer/budget/trimming.
4. Implement provider privacy masking.
5. Add initial hidden-dependency invariant.
6. Add expanded packet builder and dependency validation.
7. Add persistence, injection hardening, and performance tests.

## 26. Tests

### 26.1 Unit tests

- Content priority and trimming order.
- Mandatory block protection.
- Exact pinned tokenizer and `utf8_bytes_v1` counting, including method identity.
- Effective-budget precedence and safety/provider-framing reserves.
- Below-target mandatory-only packet and mandatory-over-budget failure.
- Adversarial Unicode, escapes, long numbers and deeply nested JSON strings.
- Missing/wrong tokenizer version or vocabulary checksum fails at startup.
- Candidate/evidence/frame validation.
- Stable masking aliases.
- Packet UUID/revision.
- Text injection/control/depth limits.

### 26.2 Initial/expanded invariants

- Initial packet rejects NRF/UDR transaction/detail/frame leakage.
- Tool descriptor contains no hidden hints.
- Expanded packet accepts only matching validated inspection results.
- Expanded packet cannot be built before dependency-expanded T12 and applicable T14 revisions exist.
- Expanded packet renders revised ranking/checkpoint values, not stale initial values.
- Reordered NRF/UDR result arrival produces the same packet ID/content.
- Unrelated dependency records rejected.
- Final packet remains within budget.

### 26.3 Provider fixtures

- Small local-model budget.
- OpenRouter strict masking.
- Very large primary record summarized through T18.
- Many retries/alternatives compressed correctly.
- Mandatory evidence itself exceeds budget.
- Identical inputs with the same counter profile produce byte-identical
  trimming, packet token count and packet ID.

## 27. Acceptance Criteria

T15 is complete when:

1. It is the only path by which protocol evidence reaches a model.
2. Initial packets contain no detailed NRF/UDR evidence.
3. Expanded packets contain only approved bounded inspection results.
4. Every model-visible conclusion/evidence reference resolves locally.
5. Expanded packets cryptographically identify their parent packet and exact revised deterministic/dependency inputs.
5. Mandatory primary evidence survives trimming.
6. Packets fit model-specific budgets with recorded truncations.
7. Remote masking prevents sensitive-data leakage while preserving correlation aliases.
8. Evidence text cannot alter system/tool policy.
9. Invalid packets never reach T16.
