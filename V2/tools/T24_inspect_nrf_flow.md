# T24 `inspect_nrf_flow` Implementation Specification

## 1. Purpose

`inspect_nrf_flow` performs a bounded, lazy investigation of NRF NF-management, discovery, status, deregistration, and SCP delegated-discovery behavior for one failed attempt.

It runs only when the initial model pass identifies a visible primary-flow symptom and requests NRF evidence through a schema-valid request.

## 2. Invocation Gate

Only `DependencyToolExecutor` may invoke T24. Required conditions:

- T16 initial pass, never final pass.
- Current failed attempt ID.
- Initial packet ID.
- NRF-specific reason code.
- Rationale citing one or more initial evidence IDs.
- Bounded frame window.
- At least one NF/service/consumer selector.
- Per-attempt request limit not exceeded.

The executor validates before constructing `NRFEventReader` capability.

## 3. Non-Goals

T24 must not:

- Scan all NRF traffic to look for anything unusual.
- Run automatically for every call failure.
- Treat every NRF error as causal.
- Read UDR partition.
- Return full unrelated NF profiles to a model.
- Trigger recursive model/tool passes.
- Override T12 directly; it returns evidence/candidates for reranking.

## 4. Python Tool Contract

```python
class InspectNRFFlowRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    request_id: UUID
    analysis_id: UUID
    initial_packet_id: UUID
    attempt_id: UUID
    reason_code: Literal[
        "DISCOVERY_FAILURE_SUSPECTED",
        "NF_REGISTRATION_OR_READINESS_SUSPECTED",
        "SCP_ROUTING_OR_SELECTION_SUSPECTED",
        "DEPENDENCY_TIMEOUT_SUSPECTED"
    ]
    rationale: str
    initial_evidence_ids: list[UUID]
    frame_start: int
    frame_end: int
    nf_type: str | None = None
    service_name: str | None = None
    nf_instance_id: str | None = None
    fqdn: str | None = None
    consumer_nf: str | None = None


class NRFInspectionResult(BaseModel):
    schema_version: Literal["2.0"]
    request_id: UUID
    attempt_id: UUID
    status: Literal["completed", "empty", "partial", "failed"]
    effective_window: FrameWindow
    selected_entities: list[NFEntityRef]
    transactions: list[NRFTransactionEvidence]
    lifecycle: BuildNFLifecycleResult | None
    discovery_chain: list[DiscoverySelectionStep]
    impact: AssessBackgroundImpactResult | None
    failure_candidates: list[FailureCandidate]
    full_evidence_refs: list[UUID]
    warnings: list[str]
    revision: str
```

## 5. Pre-Execution Request Validation

### Attempt and pass

- Attempt matches initial packet/current diagnosis target.
- Request originated from initial T16 result.
- Final-pass/replayed request is rejected.

### Evidence rationale

- Every cited evidence ID exists in initial packet.
- At least one cited record supports the selected reason category.
- Rationale text alone is insufficient.

### Window

- Intersects attempt dependency pre/post bounds.
- Clamp to configured maximum and capture bounds.
- Cannot be capture-wide.
- Includes pre-call area only as needed for lifecycle/recovery.

### Selectors

- Instance ID is strongest.
- Otherwise require combinations such as NF type + service, service + consumer, FQDN + service.
- Generic `NRF`/wildcard with no target is rejected.

## 6. Capability Construction

```python
class NRFReadCapability(BaseModel):
    request_id: UUID
    attempt_id: UUID
    frame_start: int
    frame_end: int
    selector_hash: str
    allowed_operations: set[str]
    expires_at: datetime
```

`NRFEventReader` checks capability on every query/result. Direct record IDs cannot escape selector/window scope.

## 7. NRF Transaction Types

Inspect scoped:

- NF registration/create/replace.
- NF profile update/patch.
- Heartbeat/status update.
- Deregistration/delete.
- Status subscription/notification.
- NF discovery query/response.
- SCP delegated-discovery/routing records with NRF semantics.
- Retries/timeouts/ProblemDetails for those operations.

## 8. Transaction Evidence Model

```python
class NRFTransactionEvidence(BaseModel):
    transaction_id: UUID
    operation: str
    request_frame: int | None
    response_frame: int | None
    method: str | None
    uri_template: str | None
    status: int | None
    nf_instance_id: str | None
    nf_type: str | None
    service_names: list[str]
    consumer_nf: str | None
    completion_state: str
    phase: str
    retry_group: UUID | None
    problem_cause: str | None
    evidence_ids: list[UUID]
```

Only fields relevant to selector/causal chain are returned in compact result.

## 9. Query Strategy

1. Query NRF index by exact instance/service/FQDN/consumer within effective window.
2. Add transactions referenced by selected records (request/response/retry/status notification).
3. Add lifecycle predecessor/recovery events needed by T22.
4. Add discovery criteria/results and selected endpoint chain.
5. Add bounded primary symptom references from initial packet.
6. Deduplicate by transaction/document/event ID.

Do not begin with an unfiltered time-range scan when selector indexes exist.

## 10. Lifecycle Analysis

Invoke T22 with selected events/window. Include pre-call startup records only to establish:

- Registration/readiness at attempt start.
- Failure recovery before call.
- Service suspension/unavailability.
- Stale cleanup pattern.
- Node/instance identity continuity.

Lifecycle remains scoped to selected NF/service entities.

## 11. Discovery and Selection Chain

```python
class DiscoverySelectionStep(BaseModel):
    step_id: UUID
    frame: int
    step_type: Literal[
        "discovery_request", "discovery_response", "candidate_returned",
        "candidate_selected", "request_sent", "selection_failed"
    ]
    consumer_nf: str | None
    requested_nf_type: str | None
    requested_service: str | None
    query_criteria: dict[str, JsonValue]
    candidate_entity_ids: list[UUID]
    selected_entity_id: UUID | None
    selected_endpoint: str | None
    outcome: str
    evidence_ids: list[UUID]
```

Correlate delegated discovery/SCP routing through headers/references/target-api-root and endpoint, with explicit confidence.

## 12. Discovery Failure Patterns

- HTTP error/no response to discovery.
- Successful response with zero matching instances for required criteria.
- Returned service suspended/unavailable.
- Stale endpoint returned/selected.
- Criteria mismatch (slice, DNN, service/version, PLMN) visible in request/result.
- Alternate healthy candidate exists but selection/routing fails.

Do not interpret an empty result without preserving query criteria.

## 13. Registration/Readiness Failure Patterns

- Registration/update failed and no recovery before attempt.
- Required service suspended/unavailable at attempt start.
- Repeated registration/heartbeat failure leading to unavailable state.
- Instance deregistered before selection with no replacement.
- Startup cleanup 404 recovered before attempt (benign/unrelated candidate evidence).

## 14. SCP Delegated Discovery

When SCP handles discovery:

- Identify consumer request and discovery target criteria.
- Trace NRF-facing request/response if captured.
- Trace selected producer endpoint/target-api-root.
- Distinguish SCP routing failure from NRF discovery failure.
- Preserve uncertainty when internal delegated steps are not visible.

Fault domain remains inconclusive when only consumer-SCP boundary is captured.

## 15. Bounded Expansion

One expansion maximum. Allowed only when first result proves:

- Registration/recovery pair crosses window edge.
- Discovery request/response pair crosses edge.
- Referenced status notification immediately outside edge.

Expansion request is generated deterministically, revalidated, clamped, and audited. It cannot expand to complete capture. No second expansion.

## 16. Background Impact

Invoke T23 with:

- Initial symptom evidence.
- Selected NRF transactions.
- T22 lifecycle/readiness.
- Discovery/selection chain.
- Optional dependency baseline.

Only `causal`/`contributing` events are adapted to T12-eligible candidates. `unrelated` remains reportable infrastructure history; `inconclusive` remains limitation/alternative according to policy.

## 17. Full Evidence Retrieval

Use T18 with NRF capability for exact selected transaction records. Retrieve only records required for:

- Lifecycle transition proof.
- Discovery criteria/result.
- Error/ProblemDetails.
- Endpoint selection/correlation.

Full profiles/bodies are not automatically inserted into model result; T15 receives compact masked summaries.

## 18. Result Masking

Before T15/provider boundary:

- Mask internal IP/FQDN according to policy while keeping stable aliases.
- Exclude authorization/cert headers.
- Reduce NF profiles to relevant type/service/status/endpoint alias.
- Exclude unrelated services/instances.
- Preserve frame/evidence IDs and cause/status.

## 19. Deterministic Revision and Persistence

Revision includes initial packet/request, validated/effective bounds, selector/capability, NRF source/index revisions, T21 phase, T22/T23 policy, and tool version.

```text
evidence/dependency/<request-id>/nrf/
  request_validation.json
  transactions.jsonl
  discovery_chain.jsonl
  lifecycle_*.json*
  background_impact.json
  inspection_result.json
  inspection_manifest.json
```

Manifest published last.

## 20. Failure Semantics

- Invalid/replayed/final-pass request: rejected before reader construction.
- No matching records: successful empty/inconclusive result.
- Selector ambiguity: bounded multiple entities with warning; no forced merge.
- Corrupt NRF artifact/index: evidence-integrity failure/partial.
- T22/T23 failure: partial inspection with missing stage warning when transactions remain useful.
- Expansion denied/fails: original bounded result remains partial.
- T18 full record unavailable: compact event may remain with lower confidence.
- Publication failure: fail inspection and do not pass result to T15.

## 21. Performance and Resource Requirements

- Indexed selector/window query.
- Default matched event cap and byte limits.
- One expansion maximum.
- No full-partition materialization.
- Record records scanned/matched/returned, entities, transactions, full lookups, expansion, bytes, latency, and peak memory.

## 22. Security and Privacy

- Capability created only after request validation.
- No direct model/primary access to NRF reader.
- Strict selector/window/operation checks per query/result.
- Full data local; provider gets T15 summaries.
- Audit accepted/rejected requests and records accessed.
- Treat NF profile/error text as untrusted.

## 23. Observability

Logs include request/attempt/reason, cited initial evidence, selector types/hash, requested/effective window, query counts, expansion, lifecycle/readiness, impact, status, and duration. No sensitive endpoints/profile content.

Metrics include requests accepted/rejected by reason, matched/empty/partial, expansions, lifecycle outcomes, discovery failure types, impact outcomes, bytes/latency, and access denials.

## 24. Proposed Python Code Structure

```text
V2/harness/dependency_tools/
  executor.py
  request_validator.py
  capability.py
V2/harness/dependency_tools/nrf/
  inspector.py
  query.py
  transactions.py
  lifecycle.py
  discovery.py
  delegated_discovery.py
  impact.py
  masking.py
  models.py
V2/harness/storage/
  nrf_reader.py
  dependency_store.py
```

## 25. Implementation Sequence

1. Define request/capability/transaction/discovery/result schemas.
2. Implement request validation and scoped reader.
3. Implement indexed transaction query/pairing.
4. Integrate T22 lifecycle/readiness.
5. Implement discovery/SCP chain and failure patterns.
6. Integrate T23/T18/masking.
7. Add bounded expansion, persistence, audit, and performance tests.

## 26. Tests

### 26.1 Request validation tests

- Valid instance/service/consumer selectors.
- Missing initial evidence, wrong attempt/packet, invalid reason.
- Wildcard/capture-wide/final-pass/replayed/duplicate request.
- Window clamp and per-attempt request limit.

### 26.2 Analysis tests

- No-instance discovery caused by failed registration.
- Cleanup 404 recovered before call.
- Required service suspended.
- Stale endpoint returned/selected.
- Alternate healthy candidate.
- Delegated discovery success/failure/partial visibility.
- Multiple matching instances and ambiguity.
- One justified expansion.

### 26.3 Safety/integration tests

- No NRF read before approval.
- Reader rejects record/window/selector escape.
- Full profile masked before T15.
- T23 unrelated/inconclusive not promoted improperly.
- T12 rerank uses causal/contributing result.
- Final model cannot request second NRF inspection.

## 27. Acceptance Criteria

T24 is complete when:

1. NRF evidence is accessed only after a valid initial model request.
2. Every query is bounded by attempt, window, selectors, and capability.
3. Registration/readiness/discovery/SCP chains are reconstructed with evidence/confidence.
4. Pre-call recovery and benign cleanup are distinguished from unresolved call dependencies.
5. Only T23 causal/contributing results become T12-eligible.
6. One justified bounded expansion is the maximum.
7. Full NRF data remains local and model summaries are masked/minimal.
8. Requests/results/access are immutable and auditable.
