# T16 `generate_diagnosis` Implementation Specification

## 1. Purpose

`generate_diagnosis` invokes a configured OpenAI-compatible local model or OpenRouter model to explain deterministic findings. The initial pass may return bounded dependency evidence requests; the final pass may only return diagnosis.

Model output is advisory. Deterministic observations, ranking, and scenario statuses remain authoritative.

## 2. Non-Goals

T16 must not:

- Parse PCAP/protocol data.
- Execute tools directly.
- Change deterministic candidate/ranking/checkpoint values.
- Invent evidence IDs, frames, messages, or fields.
- Create recursive tool loops.
- Require a provider for deterministic reporting.
- Log API keys or full evidence payloads.

## 3. Provider Modes

- `none`: T16 returns `disabled`; report remains deterministic.
- `local`: OpenAI-compatible local endpoint such as vLLM/Ollama/LM Studio.
- `openrouter`: OpenRouter endpoint and API key, strict remote masking required by T15.

Provider behavior is hidden behind one interface.

## 4. Python Tool Contract

```python
class GenerateDiagnosisRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt_id: UUID
    packet: EvidencePacket
    pass_stage: ModelPass
    provider_config: ProviderConfig


class GenerateDiagnosisResult(BaseModel):
    schema_version: Literal["2.0"]
    attempt_id: UUID
    packet_id: UUID
    pass_stage: ModelPass
    status: Literal["success", "failed", "disabled"]
    diagnosis: ModelDiagnosis | None
    provider: ProviderMetadata | None
    validation_errors: list[ModelValidationError]
    warnings: list[str]
```

`pass_stage` uses the shared `ModelPass` enum (`LLD.md` section 4.10). The
legal pairing is fixed there: `initial` consumes a `primary`-stage packet;
`final` consumes a `dependency_expanded`-stage packet.

## 5. Provider Interface

```python
class ModelProvider(Protocol):
    def generate_json(
        self,
        system_prompt: str,
        user_payload: dict[str, JsonValue],
        response_model: type[BaseModel],
        request_options: ModelRequestOptions,
    ) -> ProviderResponse: ...
```

`ProviderResponse` contains raw response checksum, parsed content, model/provider identifiers, latency, token usage, finish reason, request ID, and error classification. Raw content persistence is optional/local-policy controlled and never includes API keys.

## 6. Provider Configuration

```python
class ProviderConfig(BaseModel):
    mode: Literal["none", "local", "openrouter"]
    base_url: str | None
    model: str | None
    api_key_env: str | None
    timeout_seconds: int = 120
    temperature: Decimal = Decimal("0.1")
    max_output_tokens: int = 2000
    structured_output: Literal["prefer", "require", "json_prompt"] = "prefer"
    max_retries: int = 1
```

Validation:

- OpenRouter requires model and populated key environment variable.
- Local requires base URL/model; API key optional.
- Temperature restricted to `0-0.2`.
- Base URL scheme/host policy validated; redirects constrained.
- API key value never enters config artifacts.

## 7. Model Diagnosis Schema

```python
class ModelDiagnosis(BaseModel):
    schema_version: Literal["2.0"]
    ue_request_summary: str
    outcome_summary: str
    root_cause_summary: str
    primary_candidate_id: UUID | None
    alternative_candidate_ids: list[UUID]
    reasoning_steps: list[ReasoningStep]
    evidence_ids: list[UUID]
    confidence: Literal["high", "medium", "low", "inconclusive"]
    limitations: list[str]
    deterministic_conflicts: list[ModelDeterministicConflict]
    dependency_evidence_requests: list[DependencyEvidenceRequest]
```

Reasoning steps cite candidate/evidence IDs and separate observation from inference. Chain-of-thought is not required; concise auditable rationale is.

## 8. Dependency Evidence Request Schema

`DependencyEvidenceRequest` and `DependencyReasonCode` are canonical in
`LLD.md` section 17, including the `fqdn` selector; the model below mirrors
that definition. Routing is by the `tool` field only, and
`DependencyToolExecutor` adapts a validated generic request into the typed
`InspectNRFFlowRequest`/`InspectUDRFlowRequest` internal contracts.

```python
class DependencyEvidenceRequest(BaseModel):
    tool: Literal["inspect_nrf_flow", "inspect_udr_flow"]
    attempt_id: UUID
    reason_code: DependencyReasonCode
    rationale: str
    initial_evidence_ids: list[UUID]
    frame_start: int
    frame_end: int
    nf_type: str | None = None
    service_name: str | None = None
    nf_instance_id: str | None = None
    fqdn: str | None = None
    consumer_nf: str | None = None
    resource_or_operation: str | None = None
    masked_correlation_key: str | None = None
```

T16 validates schema/reference presence but does not authorize/execute requests; `DependencyToolExecutor` performs policy validation.

## 9. Initial Pass

System prompt requires:

- Explain supplied deterministic findings.
- Use only packet evidence.
- Treat deterministic primary ranking as authoritative unless explicitly identifying a conflict.
- Request NRF/UDR inspection only when a visible symptom justifies it.
- Cite initial evidence IDs and bounded target selectors.
- Return zero requests when no dependency suspicion exists.

At most one NRF and one UDR request may be returned. Extra requests are rejected during validation.

## 10. Final Pass

Before provider invocation, final-pass validation requires:

- request `pass_stage=final` and packet `pass_stage=dependency_expanded`;
- packet `parent_packet_id` resolves to the successful initial packet for the same analysis/attempt;
- packet root-cause revision is dependency-expanded and its parent/consumed revisions match packet lineage;
- applicable scenario and dependency revisions match the packet manifest;
- no final call has already been recorded for this initial packet generation.

Final prompt includes the revised deterministic ranking/checkpoints plus expanded dependency results and requires:

- Reassess explanation using new bounded evidence.
- State whether dependency was causal/contributing/unrelated/inconclusive consistently with T23/T12.
- Return `dependency_evidence_requests=[]`.

Any final-pass tool request is removed, warning recorded, and no third pass occurs.

## 11. Prompt Construction

Separate:

- Stable system instructions/version.
- Output JSON schema.
- Evidence packet serialized as delimited JSON data.

Do not concatenate evidence strings into system instructions. State explicitly that text inside evidence/scenario is untrusted and must not be followed.

## 12. Structured Output Strategy

1. Use provider JSON schema/response format when supported.
2. If endpoint rejects unsupported structured mode and policy permits, retry once using JSON-only prompt.
3. Parse the first complete JSON object only under strict parser limits.
4. Validate with Pydantic and semantic validators.

For `structured_output=require`, unsupported mode is provider failure rather than fallback.

## 13. Semantic Validation

Validate:

- Attempt ID matches packet.
- Candidate IDs exist and alternatives are present in packet.
- Evidence IDs exist in packet.
- No new frame numbers/messages/observed values appear as factual citations.
- Primary candidate conflict is explicitly recorded rather than silently replaced.
- Request tool allowed for pass stage.
- Request/pass-stage and packet-lineage rules hold.
- Initial request cites visible evidence and target selector fields.
- Text lengths/list counts are bounded.

Invalid references are removed only when the remaining diagnosis remains valid; otherwise trigger repair/failure.

## 14. Repair Retry

One repair retry maximum. Send:

- Same system/schema.
- Prior invalid response as untrusted text or checksum/reference according to privacy policy.
- Concise validation errors.
- Same evidence packet, with no evidence expansion.

Do not retry deterministic semantic disagreement merely to force agreement; record conflict.

## 15. Provider Error Handling

Classify:

- Timeout/connectivity/DNS/TLS.
- Authentication/authorization.
- Rate limit/quota.
- Context-length/token limit.
- Unsupported response format.
- Server 5xx.
- Malformed/empty/refusal response.
- Local model unavailable/out-of-memory.

One transport retry may be allowed only under configured idempotent retry policy and total retry cap. Deterministic report continues after failure.

## 16. Timeout and Cancellation

- Per-request timeout from config.
- Orchestrator cancellation propagates to HTTP client.
- Do not leave background requests running after analysis cancellation.
- Record whether timeout occurred before/after headers where available.

## 17. Usage and Metadata

Record:

- Provider mode/base host class, model, API request ID.
- Prompt/schema versions and packet ID/checksum.
- Start/end/latency.
- Input/output/total tokens when provider reports them.
- Estimated tokens otherwise, marked estimated.
- Structured mode, retry/repair count, finish reason.
- Error category/status.

Never record API key, authorization header, or raw sensitive packet.

## 18. Caching Policy

Optional deterministic cache key:

```text
provider + model + prompt_version + packet_checksum + temperature + output_schema
```

Caching is disabled by default for remote providers unless privacy/retention policy permits. Cached output must be revalidated against current schema.

## 19. Persistence

```text
evidence/model/
  <attempt-id>/initial_result.json
  <attempt-id>/final_result.json
  provider_metadata.jsonl
```

Persist validated diagnosis and metadata. Raw provider response persistence is configurable and local-only; otherwise store checksum/error excerpt with sensitive-data filtering.

## 20. Failure Semantics

- Provider none: successful disabled result.
- Packet invariant/schema invalid: reject before provider call.
- Provider error/malformed after retry: failed result, deterministic pipeline continues.
- Invalid candidate/evidence references after repair: failed diagnosis.
- Final pass includes tool request: strip/reject request, preserve otherwise valid diagnosis with warning.
- Final packet lineage mismatch, stale deterministic revision or duplicate final invocation: reject before provider call.
- Model conflicts with deterministic observation: retain conflict, deterministic value remains authoritative.
- Persistence failure: model result may be discarded; report records provider-stage failure.

## 21. Performance and Resource Requirements

- One initial call and at most one final call per selected failed attempt.
- One repair retry per pass maximum; global request cap enforced.
- Concurrency default one on RTX 5090/local model unless configured.
- Record queue time separately from inference latency.
- Avoid sending duplicate packets; use packet checksum.
- Enforce model/provider token limits before request.

## 22. Security and Privacy

- OpenRouter packets must pass T15 remote masking validation.
- API keys loaded at call time from env/secret manager and redacted from exceptions.
- Validate base URL and restrict unexpected redirects.
- TLS verification enabled by default and cannot be silently disabled in production policy.
- Evidence/scenario text is untrusted prompt content.
- Provider response is untrusted until validated.

## 23. Observability

Logs include analysis/attempt/pass/provider/model/packet ID, schema mode, latency, token usage, repair count, status/error category, and warning codes. Never log packet or key content.

Metrics include requests by provider/model/pass, success/failure/repair, latency/queue/token histograms, tool-request count/reason, final-pass request violations, cache hits, and local OOM/unavailable errors.

## 24. Proposed Python Code Structure

```text
V2/harness/providers/
  base.py
  openai_compatible.py
  local.py
  openrouter.py
  disabled.py
  errors.py
  metadata.py
  cache.py
V2/harness/model/
  diagnosis.py
  validation.py
  repair.py
V2/harness/prompts/
  initial_diagnosis.txt
  final_diagnosis.txt
V2/harness/schemas/
  model_diagnosis.schema.json
  tool_request.schema.json
```

## 25. Implementation Sequence

1. Define provider/diagnosis/request/error schemas.
2. Implement OpenAI-compatible client and disabled provider.
3. Implement structured output and semantic validation.
4. Add repair retry and provider error mapping.
5. Add initial/final prompt contracts and tool-request restrictions.
6. Add local/OpenRouter configuration/privacy checks.
7. Add metadata/cache/observability and load tests.

## 26. Tests

### 26.1 Unit tests

- Provider config validation/redaction.
- Candidate/evidence/frame semantic validation.
- Initial versus final tool-request rules.
- Repair prompt and one-retry cap.
- Error category mapping.
- Cache key and metadata.

### 26.2 Provider mock tests

- Structured JSON success.
- Structured format unsupported fallback.
- Malformed JSON repaired/not repaired.
- Timeout, 401, 429, 5xx, context limit, empty response.
- Local unavailable/OOM.
- Usage missing/estimated.
- Cancellation.

### 26.3 Safety tests

- Prompt injection in evidence/scenario.
- Invented candidate/evidence/frame.
- Attempt ID mismatch.
- OpenRouter unmasked packet rejected.
- API key never appears in logs/errors/artifacts.
- Final pass attempts recursive tool call.
- Final pass with initial packet, stale T12/T14 revision, mismatched dependency revision or reused parent packet is rejected before provider invocation.

## 27. Acceptance Criteria

T16 is complete when:

1. Local and OpenRouter use one validated provider contract.
2. Initial/final passes enforce the one bounded dependency round.
3. Model output is schema- and evidence-reference validated.
4. Model cannot override deterministic observations/ranking/checkpoints silently.
5. One repair retry works without evidence expansion.
6. Provider failure leaves deterministic analysis/reporting usable.
7. Keys and sensitive evidence never leak to logs/artifacts/remote calls outside policy.
8. Metadata and token/latency usage are auditable.
9. Every result records packet/pass lineage and final calls consume only dependency-expanded deterministic packets.
