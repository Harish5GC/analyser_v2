# T06 `find_http_failures` Implementation Specification

## 1. Purpose

`find_http_failures` detects explicit HTTP/SBI failures, incomplete HTTP/2 transactions, malformed responses, retry exhaustion, and dependency symptoms in primary HTTP events assigned to one procedure attempt.

T06 emits failure candidates. It does not choose the final root cause; T12 performs ranking.

## 2. Non-Goals

T06 must not:

- Read NRF or UDR partitions or indexes.
- Claim that NRF/UDR caused a failure before T24/T25 inspection.
- Treat every 4xx/5xx as call-related.
- Treat a recovered retry as a terminal failure automatically.
- Infer a missing response for valid one-way notification/callback patterns.
- Rank candidates across protocols.
- Send data to a model.

## 3. Access and Ownership Boundary

T06 receives:

- One `ProcedureAttempt`.
- Attempt-assigned HTTP2 events from `PrimaryEventReader`.
- T21 capture-phase intervals.
- Versioned SBI operation policy.

It returns candidates, retry groups, and dependency suspicions. It cannot construct `NRFEventReader` or `UDREventReader`.

## 4. Python Tool Contract

```python
class FindHTTPFailuresRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt: ProcedureAttempt
    event_ids: list[UUID]
    capture_phases: CapturePhaseReader
    operation_policy_version: str


class FindHTTPFailuresResult(BaseModel):
    schema_version: Literal["2.0"]
    attempt_id: UUID
    candidates: list[FailureCandidate]
    retry_groups: list[HTTPRetryGroup]
    dependency_suspicions: list[DependencySuspicion]
    inspected_event_count: int
    warnings: list[DetectorWarning]
```

## 5. Failure Candidate Contract

T06 populates the common candidate model with HTTP-specific observations:

```python
class HTTPFailureObserved(BaseModel):
    document_id: UUID
    tcp_stream: int | None
    http2_stream_id: int | None
    method: str | None
    uri: str | None
    uri_template: str | None
    api_name: str | None
    operation_id: str | None
    consumer_nf: str | None
    producer_nf: str | None
    request_frame: int | None
    response_frame: int | None
    status: int | None
    completion_state: str
    problem_details: ProblemDetailsSummary | None
    retry_group_id: UUID | None
```

Every candidate records detector rule ID/version, explicitness, score inputs, phase, relevance, source event/evidence IDs, and any downstream/cleanup flag.

## 6. SBI Operation Policy

Expected behavior is table-driven:

```python
class HTTPOperationPolicy(BaseModel):
    operation_id: str
    method: str
    uri_template: str
    expected_statuses: set[int]
    one_way: bool = False
    response_timeout_seconds: Decimal
    retryable_statuses: set[int]
    terminal_statuses: set[int]
    idempotent: bool
    redirect_allowed: bool
    required_response_content_types: set[str]
```

Unknown operations use generic HTTP semantics and lower confidence. Vendor-specific policies are separately versioned.

## 7. HTTP Status Detection

### 7.1 4xx

Emit an explicit candidate when the response is unexpected for the operation. Extract `ProblemDetails` and invalid parameters. Classify likely consumer/request errors separately from producer/resource-state errors, but do not assume fault ownership solely from status class.

### 7.2 5xx

Emit an explicit server/dependency candidate. Preserve status, producer/consumer, retry-after/overload headers, and ProblemDetails. A later successful retry may demote the candidate to recovered warning.

### 7.3 Unexpected 2xx/3xx

Emit when the operation policy excludes the status or required body/Location semantics are absent. Redirect is a failure only when disallowed, looping, malformed, or ultimately unsuccessful.

### 7.4 Informational responses

1xx does not complete the transaction. Preserve it as transaction metadata, not a standalone failure unless protocol behavior is invalid.

## 8. ProblemDetails Extraction

Extract when present:

- `status`, `cause`, `title`, `detail`, `instance`.
- Invalid parameters and supported features.
- Vendor extension keys as bounded summaries.
- Body parse state and full evidence reference.

Status mismatch between HTTP header and body is an anomaly candidate. Malformed ProblemDetails is retained as evidence and does not erase the HTTP status failure.

## 9. Missing Response and Completion State

Candidate rules:

- `request_only`: candidate only after policy timeout elapsed within capture visibility.
- `reset`: explicit transport candidate with reset frame/cause when available.
- `truncated_capture`: warning/inconclusive unless independent failure evidence exists.
- `incomplete`: evaluate capture boundary and timeout.
- `response_only`: anomaly with lower confidence unless request is outside capture.

One-way notification/callback operations do not require a response when policy says `one_way=true`.

## 10. Body and Content Validation

Detect:

- Invalid JSON when JSON is required.
- Malformed multipart boundary/part metadata.
- Missing mandatory ProblemDetails or operation response fields when policy defines them.
- Content-Type mismatch.
- Body truncated by capture/decoder limits.

Validation is schema-light in V2.1: check required structural fields, not complete 3GPP OpenAPI conformance. Vendor schema validation may be added later.

## 11. Retry Grouping

```python
class HTTPRetryGroup(BaseModel):
    retry_group_id: UUID
    attempt_id: UUID
    operation_signature: str
    event_ids: list[UUID]
    statuses: list[int | None]
    endpoints: list[str]
    first_frame: int
    last_frame: int
    outcome: Literal["recovered", "exhausted", "incomplete", "not_a_retry"]
    retry_count: int
    rationale_codes: list[str]
```

Group using normalized operation, request signature, consumer, correlation/context ID, and bounded time. Exclude changing transaction identity when it indicates a new procedure attempt.

- Failed attempts followed by success: mark recovered; retain warning candidate only if delay/side effect matters.
- Repeated terminal failure/no response: emit retry-exhaustion candidate.
- Endpoint alternation: record alternate-NF selection behavior.
- Identical loops exceeding policy: emit routing/retry-loop anomaly.

## 12. Redirect and Routing Loops

Track normalized Location/target-api-root transitions. Emit a loop candidate when an endpoint/URI state repeats without success, redirects exceed configured count, or routing returns to a prior target.

SCP proxy hops are not redirects unless represented by HTTP semantics; ordinary forwarding headers alone do not imply a loop.

## 13. Attempt Association

T06 accepts only events already assigned or explicitly linked to the attempt. It validates association using:

- SM context/correlation references.
- UE/session graph identity.
- PDU session/PTI scope.
- Profile stage compatibility.
- Parent/child attempt links.

Timestamp overlap alone cannot satisfy association. If T04 assignment is low-confidence, the candidate inherits an ambiguity penalty and warning.

## 14. Capture Phase and Relevance

Phase and relevance are separate:

- `attempt_related`: exact/strong attempt link.
- `dependency_related`: visible primary dependency chain without direct UE identifier.
- `startup_background`: pre-attempt platform/lifecycle activity.
- `concurrent_background`: overlaps an active interval without supported link.
- `post_call_background`: after attempt terminal.
- `unresolved_infrastructure`: visible primary infrastructure state unresolved at attempt start.

An event inside `attempt_active` remains background unless correlation/stage evidence links it.

## 15. Dependency Suspicion Contract

```python
class DependencySuspicion(BaseModel):
    suspicion_id: UUID
    attempt_id: UUID
    dependency_type: Literal["NRF", "UDR"]
    reason_code: Literal[
        "DISCOVERY_FAILURE_SUSPECTED",
        "NF_REGISTRATION_OR_READINESS_SUSPECTED",
        "SCP_ROUTING_OR_SELECTION_SUSPECTED",
        "SUBSCRIBER_DATA_FAILURE_SUSPECTED",
        "DEPENDENCY_TIMEOUT_SUSPECTED"
    ]
    initial_evidence_ids: list[UUID]
    target_hints: dict[str, str]
    rationale: str
    confidence: Literal["medium", "low"]
```

Suspicion can be emitted only from visible primary evidence, such as a UDM-facing data error, no-NF-available response, delegated-routing symptom, or upstream timeout. It is not a hidden-flow candidate and cannot be ranked as NRF/UDR root cause.

## 16. Cleanup and Downstream Classification

HTTP release/delete operations after the attempt terminal are marked cleanup when they remove contexts created by the failed procedure. A cleanup failure may be reported as a secondary operational issue but receives a ranking penalty.

A later UE-facing HTTP/NAS effect is downstream when an earlier candidate directly explains it through correlation and stage ordering.

## 17. Detector Scoring Inputs

Recommended base inputs:

- Unexpected 5xx: `0.90`.
- Unexpected 4xx: `0.85`.
- Explicit ProblemDetails cause: `+0.05`.
- Request timeout after visible window: `0.75`.
- Reset: `0.80` when call-related.
- Retry exhausted: `+0.05`.
- Recovered retry: substantial recovery penalty.
- Low-confidence assignment/incomplete capture: penalty.

T06 stores individual score terms. T12 owns final cross-protocol ranking.

## 18. Output and Persistence

T06 results normally feed the in-memory diagnostic aggregation and are persisted by the common candidate store:

```text
normalized/diagnostics/
  failure_candidates.jsonl
  retry_groups.jsonl
  dependency_suspicions.jsonl
```

Candidate UUIDs are deterministic from attempt ID + detector rule + source event(s).

## 19. Failure Semantics

- Unknown attempt/event: validation error.
- Non-primary event supplied: reject and emit access-boundary warning.
- Unknown operation policy: continue generic detection with lower confidence.
- Malformed normalized body summary: emit warning and use status/completion evidence.
- Missing full evidence reference: evidence-integrity warning; candidate may remain with reduced confidence.
- Detector internal exception for one event: quarantine event, continue, mark partial.

## 20. Performance and Resource Requirements

- O(HTTP events in selected attempt).
- Build retry groups using indexed operation signatures.
- Do not load full bodies unless a bounded structural check requires T18.
- Typical attempt should complete in milliseconds.
- Record events inspected, groups formed, full lookups, elapsed time, and peak temporary bytes.

## 21. Security and Privacy

- Primary reader capability only.
- Do not log URIs containing subscriber IDs without masking.
- Authorization/cookie/certificate headers are never candidate summaries.
- Body excerpts are excluded; candidates cite evidence IDs.
- Treat ProblemDetails and body text as untrusted data.

## 22. Observability

Logs include detector rule, event/candidate ID, status/completion class, phase, relevance, retry outcome, and warning code.

Metrics include candidates by category/status, missing responses, resets, recovered/exhausted retries, background candidates, dependency suspicions, unknown operations, and detector latency.

## 23. Proposed Python Code Structure

```text
V2/harness/analysis/
  primary_http.py
  http_operation_policy.py
  problem_details.py
  http_completion.py
  retries.py
  routing_loops.py
  dependency_suspicion.py
V2/harness/models/
  failures.py
  http.py
V2/harness/config/
  http_operations.yaml
```

## 24. Implementation Sequence

1. Define HTTP observed/retry/suspicion models.
2. Implement generic status and completion detection.
3. Implement ProblemDetails/body structural parsing.
4. Add operation policy and expected-status handling.
5. Add retry grouping and redirect/routing-loop detection.
6. Add phase/relevance and cleanup/downstream flags.
7. Add dependency suspicion and access-boundary tests.

## 25. Tests

### 25.1 Unit tests

- 4xx, 5xx, unexpected 2xx/3xx, and ProblemDetails mismatch.
- Request-only, response-only, reset, truncated, and one-way notification.
- JSON/multipart/content-type anomalies.
- Retry grouping, recovery, exhaustion, and new-attempt separation.
- Redirect/endpoint loop.
- Candidate UUID and score terms.
- Phase versus relevance.
- Dependency suspicion reason/target hints.

### 25.2 Integration tests

- SBI failure followed by NAS reject.
- Multiple endpoint retries ending in success/failure.
- Background primary HTTP error during a UE call.
- Capture starts before request or ends before timeout.
- UDM-facing error causing UDR suspicion without UDR access.
- No-NF-available symptom causing NRF suspicion without NRF access.

### 25.3 Negative tests

- Recovered retry is not terminal root candidate.
- Timestamp overlap alone does not associate background event.
- One-way notification does not produce missing-response error.
- Direct NRF/UDR reader/import access fails architectural test.

## 26. Acceptance Criteria

T06 is complete when:

1. HTTP status, completion, retry, body, and routing anomalies are detected deterministically.
2. Every candidate cites its stream/event evidence and detector rule.
3. Operation-specific expected statuses and one-way behavior are supported.
4. Recovered retries and cleanup are distinguished from terminal failures.
5. Phase does not substitute for attempt correlation.
6. Dependency suspicions cite primary symptoms but never claim hidden causality.
7. NRF/UDR partitions are inaccessible to T06.
8. Candidate score inputs are explicit for T12.
