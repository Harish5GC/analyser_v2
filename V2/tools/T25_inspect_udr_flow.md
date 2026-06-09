# T25 `inspect_udr_flow` Implementation Specification

## 1. Purpose

`inspect_udr_flow` performs a bounded, lazy investigation of UDR data-access transactions for one failed attempt. It determines whether an underlying UDR error, timeout, malformed response, retry exhaustion, or unavailable resource propagated through a visible consumer NF such as UDM, PCF, or NEF.

It runs only after the initial model pass requests UDR evidence based on a visible primary-flow symptom.

## 2. Invocation Gate

Only `DependencyToolExecutor` may invoke T25 after validating:

- Initial T16 pass and current failed attempt.
- Initial packet ID.
- UDR/subscriber-data reason code.
- Rationale citing initial packet evidence.
- Bounded frame window.
- Consumer/resource/operation or masked correlation selector.
- Request limit and privacy policy.

The executor constructs a scoped `UDREventReader` only after approval.

## 3. Non-Goals

T25 must not:

- Scan all subscriber data traffic for anomalies.
- Return complete subscription/authentication payloads to a model.
- Accept clear SUPI/GPSI as model-provided selector.
- Treat all UDR 4xx as call failures.
- Read NRF partition.
- Run automatically or recursively.
- Override deterministic ranking directly.

## 4. Python Tool Contract

```python
class InspectUDRFlowRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    request_id: UUID
    analysis_id: UUID
    initial_packet_id: UUID
    attempt_id: UUID
    reason_code: Literal[
        "SUBSCRIBER_DATA_FAILURE_SUSPECTED",
        "DEPENDENCY_TIMEOUT_SUSPECTED"
    ]
    rationale: str
    initial_evidence_ids: list[UUID]
    frame_start: int
    frame_end: int
    consumer_nf: str | None = None
    resource_or_operation: str | None = None
    masked_correlation_key: str | None = None


class UDRInspectionResult(BaseModel):
    schema_version: Literal["2.0"]
    request_id: UUID
    attempt_id: UUID
    status: Literal["completed", "empty", "partial", "failed"]
    effective_window: FrameWindow
    transactions: list[UDRTransactionEvidence]
    retry_summary: UDRRetrySummary
    consumer_chain: list[UDRConsumerPropagationStep]
    baseline: UDRBaselineComparison | None
    impact: AssessBackgroundImpactResult | None
    failure_candidates: list[FailureCandidate]
    full_evidence_refs: list[UUID]
    warnings: list[str]
    revision: str
```

## 5. Pre-Execution Request Validation

### Attempt/pass/evidence

- Current attempt and initial packet match.
- Request originated in initial pass.
- Cited initial evidence exists and shows subscriber-data/dependency symptom.
- Final-pass/replayed request rejected.

### Selectors

At least one:

- Consumer NF + resource/operation.
- Masked correlation key + consumer NF.
- Resource/operation + explicit context reference from initial evidence.

Generic `UDR`, wildcard URI, or capture-wide subscriber query is invalid.

### Privacy

- Clear SUPI/GPSI/authentication material in request is rejected/redacted; model should use masked key from initial packet.
- Resource selector is normalized URI template/data category, not arbitrary path traversal/query.

## 6. Capability Construction

```python
class UDRReadCapability(BaseModel):
    request_id: UUID
    attempt_id: UUID
    frame_start: int
    frame_end: int
    consumer_nf: str | None
    operation_hash: str | None
    masked_correlation_hash: str | None
    expires_at: datetime
```

Reader validates each query/result against capability. Direct event/record IDs cannot broaden scope.

## 7. UDR Operation Classification

Classify into bounded categories:

- Subscription/AM data.
- SM subscription/selection data.
- Policy data.
- Context/registration data.
- Exposure/application data.
- Authentication-related metadata (never secret vectors in model output).
- Unknown/other.

Operation identity uses method + normalized URI template + consumer + data category.

## 8. Transaction Model

```python
class UDRTransactionEvidence(BaseModel):
    transaction_id: UUID
    consumer_nf: str | None
    operation: str
    data_category: str
    request_frame: int | None
    response_frame: int | None
    method: str | None
    uri_template: str | None
    status: int | None
    completion_state: str
    problem_cause: str | None
    masked_correlation_key: str | None
    retry_group_id: UUID | None
    phase: str
    response_structure: UDRResponseStructureSummary | None
    evidence_ids: list[UUID]
```

`response_structure` contains required field presence/types/counts/checksum, not sensitive values.

## 9. Query Strategy

1. Query UDR index by consumer/operation/masked correlation within window.
2. Include paired request/response and retries.
3. Include bounded preceding/following recovery transaction for same scoped operation/context.
4. Include consumer-facing primary symptom links from initial packet.
5. Optionally select one prior successful equivalent UDR operation.
6. Deduplicate and enforce record/byte cap.

No unfiltered subscriber-wide scan.

## 10. Transaction Pairing

Pair by HTTP stream document/request-response, then correlation/context/operation. Group retries by consumer, operation, masked context, request signature, and bounded time.

Different subscriber/context or operation remains separate even if URI/consumer is similar.

## 11. Failure Patterns

- Unexpected 4xx/5xx and ProblemDetails.
- Request without response after visible timeout.
- HTTP reset/incomplete stream.
- Retry exhaustion.
- Malformed JSON/content type/schema-required structure.
- Resource not found/forbidden/conflict due to subscriber/context state.
- Consumer-visible failure propagated from UDR.
- Repeated transient failure followed by recovery.

4xx meaning is operation-specific; for example optional absent resource may be legal. Use operation policy and consumer behavior.

## 12. Response Structure Validation

Validate only allowlisted structural expectations:

- Required top-level fields/types.
- Non-empty required arrays/objects.
- JSON parse/content type.
- Supported-features/version consistency.
- ProblemDetails structure.

Never copy authentication vectors, keys, full policy/subscription objects, or clear identities into inspection summary.

## 13. Consumer Propagation Chain

```python
class UDRConsumerPropagationStep(BaseModel):
    step_id: UUID
    frame: int
    step_type: Literal[
        "consumer_request_to_udr", "udr_failure", "consumer_retry",
        "consumer_error_to_upstream", "consumer_recovery"
    ]
    consumer_nf: str | None
    operation: str | None
    status_or_cause: str | None
    evidence_ids: list[UUID]
    correlation_confidence: Literal["high", "medium", "low"]
```

The chain must connect underlying UDR transaction to initial primary symptom. Same consumer/time alone is insufficient without operation/context evidence.

## 14. Retry and Recovery

```python
class UDRRetrySummary(BaseModel):
    groups: list[UDRRetryGroup]
    recovered_before_attempt: bool
    recovered_before_failed_stage: bool
    terminal_exhaustion: bool
```

- Failed then successful equivalent operation before call/stage -> recovery/demotion.
- Repeated failure ending in consumer error -> exhaustion.
- Successful alternate data path/cache response may demote UDR failure if call progressed.

## 15. Baseline Comparison

Optionally compare one prior successful equivalent operation selected by:

- Same consumer.
- Same operation/data category.
- Same masked context when policy allows.
- Similar request structure/profile.
- Prior success and nearest frame.

Compare status, required response structure, retry count, and propagation outcome; never diff sensitive payload values.

## 16. Startup/Pre-Call Handling

UDR may be unavailable during NF startup before calls. Use T21 phase and bounded history:

- Pre-call failure followed by successful equivalent readiness/operation before attempt -> recovered/background.
- Failure remains unresolved and exact call operation later fails -> possible causal.
- Unrelated operation/consumer/subscriber -> unrelated.

UDR does not use NRF lifecycle state machine, but transaction/recovery state is sufficient for T23.

## 17. Bounded Expansion

One expansion maximum when:

- Request/response or retry/recovery pair crosses boundary.
- Consumer propagation event references a transaction just outside window.
- Prior successful equivalent is immediately outside and needed for comparison.

Expansion is deterministic, revalidated, clamped, audited, and cannot become capture-wide.

## 18. Background Impact

Invoke T23 using:

- Initial visible symptom.
- Selected UDR transactions/retries.
- Consumer propagation chain.
- Optional baseline.
- Recovery timing.

Only causal/contributing results become T12-eligible. Unrelated stays dependency history; inconclusive stays limitation/alternative.

## 19. Full Evidence Retrieval and Masking

T18 with UDR capability retrieves selected full transaction records locally. Before T15:

- Replace subscriber/context values with stable aliases.
- Remove authorization/authentication secrets.
- Reduce payload to structural field presence/count/type/checksum and relevant non-sensitive cause.
- Mask URI path identifiers.
- Exclude unrelated subscription fields.

Remote provider never receives full UDR payload.

## 20. Deterministic Revision and Persistence

Revision includes initial packet/request, validated/effective scope, UDR source/index revisions, operation policy, T21/T23 versions, masking policy, and tool version.

```text
evidence/dependency/<request-id>/udr/
  request_validation.json
  transactions.jsonl
  retry_summary.json
  consumer_chain.jsonl
  baseline.json
  background_impact.json
  inspection_result.json
  inspection_manifest.json
```

Manifest published last.

## 21. Failure Semantics

- Invalid clear-identity/broad/final/replayed request: reject before reader construction.
- No matching transactions: successful empty/inconclusive result.
- Ambiguous masked correlation: bounded alternatives with warning.
- Optional/not-found resource legal by operation policy: no failure candidate.
- Corrupt hidden artifact/index: evidence-integrity failure/partial.
- Payload parse/schema unavailable: status failure may remain; structure analysis inconclusive.
- T23/T18/expansion failure: partial result if useful transactions remain.
- Masking/publication failure: fail inspection; do not pass to T15.

## 22. Performance and Resource Requirements

- Indexed query by consumer/operation/masked key/window.
- Record/byte/payload materialization caps.
- One expansion and one baseline maximum.
- No full partition/subscriber scan.
- Record scanned/matched/returned transactions, retries, full lookups, expansion, bytes, masking, and latency.

## 23. Security and Privacy

- Scoped UDR capability only after validation.
- Clear subscriber/authentication/subscription data stays local.
- Mandatory masking before any provider-bound result.
- No payload values in logs/metrics.
- Audit request, selectors (hashed), accessed records, masking result, and denials.
- Treat all UDR body/error text as untrusted.

## 24. Observability

Logs include request/attempt/reason, cited initial evidence, consumer/operation category (non-sensitive), scope, counts, retry/recovery, propagation/impact, masking status, and duration.

Metrics include accepted/rejected requests, empty/partial, failure type/status, retry recovery/exhaustion, impact outcomes, baseline availability, masking failures, access denials, bytes, and latency.

## 25. Proposed Python Code Structure

```text
V2/harness/dependency_tools/
  executor.py
  request_validator.py
  capability.py
V2/harness/dependency_tools/udr/
  inspector.py
  query.py
  transactions.py
  operation_policy.py
  response_structure.py
  correlation.py
  retries.py
  baseline.py
  masking.py
  impact.py
  models.py
V2/harness/storage/
  udr_reader.py
  dependency_store.py
```

## 26. Implementation Sequence

1. Define request/capability/transaction/chain/result schemas.
2. Implement request privacy validation and scoped reader.
3. Implement transaction pairing/query/failure policy.
4. Add response structure, retry/recovery, and propagation chain.
5. Add baseline and bounded expansion.
6. Integrate T23/T18/masking/T15 adapter.
7. Add persistence/audit/performance/security tests.

## 27. Tests

### 27.1 Request validation tests

- Valid consumer/operation/masked-key combinations.
- Missing/wrong initial evidence, attempt, packet, reason.
- Clear SUPI/GPSI selector rejected.
- Wildcard/subscriber-wide/capture-wide/final/replayed request.
- Window clamp and request limit.

### 27.2 Analysis tests

- UDR 404/500 propagated through UDM/PCF/NEF.
- Legal optional resource not found.
- Timeout and retry recovery/exhaustion.
- Malformed response structure.
- Wrong subscriber/context excluded.
- Prior successful equivalent baseline.
- Pre-call outage recovered before attempt.
- One justified expansion.

### 27.3 Privacy/integration tests

- No UDR read before approval.
- Reader rejects scope escape/direct record bypass.
- Full payload never appears in T15/OpenRouter packet/logs.
- Authentication vectors/keys removed.
- T23 impact gates T12 rerank.
- Final model cannot request second UDR inspection.

## 28. Acceptance Criteria

T25 is complete when:

1. UDR evidence is accessed only after a valid initial model request.
2. Every query is bounded by attempt, window, consumer/operation/masked context.
3. Transactions, retries, response structure, and consumer propagation are evidence-linked.
4. Legal absent resources and recovered startup failures are not falsely promoted.
5. Sensitive subscriber/authentication/subscription data never crosses provider boundary.
6. Only T23 causal/contributing results become T12-eligible.
7. One justified bounded expansion and one baseline are maximums.
8. Requests/results/access/masking are immutable and auditable.
