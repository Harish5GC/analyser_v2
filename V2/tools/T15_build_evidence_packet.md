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

Expanded inputs add only completed T24/T25 `DependencyInspectionResult` objects. T15 never receives NRF/UDR readers.

## 4. Python Tool Contracts

```python
class BuildInitialEvidenceRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt_id: UUID
    provider_mode: Literal["local", "openrouter"]
    model_context_limit: int
    config: EvidencePacketConfig


class BuildExpandedEvidenceRequest(BaseModel):
    initial_packet: EvidencePacket
    dependency_results: list[DependencyInspectionResult]
    final_model_context_limit: int


class BuildEvidencePacketResult(BaseModel):
    packet: EvidencePacket
    artifact: ArtifactDescriptor
    token_estimate: int
    truncations: list[EvidenceTruncation]
    warnings: list[str]
```

## 5. Evidence Packet Schema

```python
class EvidencePacket(BaseModel):
    schema_version: Literal["2.0"]
    packet_id: UUID
    analysis_id: UUID
    pass_stage: Literal["initial", "dependency_expanded"]
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
```

## 6. Initial Versus Expanded Invariants

### Initial packet

- `pass_stage=initial`.
- `dependency_evidence=[]`.
- No detailed NRF/UDR transaction, status, frame, lifecycle, or failure summary.
- May state only that NRF/UDR inspection tools exist and include primary-flow suspicions/target hints.

### Expanded packet

- Derived from the exact initial packet ID.
- Includes only validated T24/T25 result summaries/evidence.
- Does not add unrelated hidden events.
- Marks tool request, validation, query scope, and result revision.

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

```python
class EvidenceRecord(BaseModel):
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

`observed` uses allowlisted semantic fields. Full bodies/trees are not embedded; small exact excerpts are permitted only when essential and policy-safe.

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

Configuration:

- Target minimum/maximum, typically 2,000-8,000 input tokens.
- Hard maximum default 12,000 for local models or lower provider context budget after reserving output/system tokens.
- Provider/model tokenizer when available; conservative fallback estimator otherwise.

```text
available_input = model_context
                - reserved_system_tokens
                - reserved_output_tokens
                - safety_margin
```

Build incrementally and recompute after each content block.

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

Packet ID UUIDv5 includes input revision hashes, pass stage, provider privacy mode, schema-guide version, and token-budget configuration.

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
- Mandatory content exceeds budget: fail with `EVIDENCE_BUDGET_EXCEEDED` and detailed block sizes.
- Masking failure: fatal for remote provider.
- Dependency result belongs to another attempt/packet: reject.
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
- Token estimator/tokenizer and safety margin.
- Candidate/evidence/frame validation.
- Stable masking aliases.
- Packet UUID/revision.
- Text injection/control/depth limits.

### 26.2 Initial/expanded invariants

- Initial packet rejects NRF/UDR transaction/detail/frame leakage.
- Tool descriptor contains no hidden hints.
- Expanded packet accepts only matching validated inspection results.
- Unrelated dependency records rejected.
- Final packet remains within budget.

### 26.3 Provider fixtures

- Small local-model budget.
- OpenRouter strict masking.
- Very large primary record summarized through T18.
- Many retries/alternatives compressed correctly.
- Mandatory evidence itself exceeds budget.

## 27. Acceptance Criteria

T15 is complete when:

1. It is the only path by which protocol evidence reaches a model.
2. Initial packets contain no detailed NRF/UDR evidence.
3. Expanded packets contain only approved bounded inspection results.
4. Every model-visible conclusion/evidence reference resolves locally.
5. Mandatory primary evidence survives trimming.
6. Packets fit model-specific budgets with recorded truncations.
7. Remote masking prevents sensitive-data leakage while preserving correlation aliases.
8. Evidence text cannot alter system/tool policy.
9. Invalid packets never reach T16.
