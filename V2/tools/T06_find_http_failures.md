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
- The shared attempt-scoped `DetectionContext` (`LLD.md` section 11), which
  carries capture bounds, the T21 phase reader, reference-point/SBI visibility,
  assignment confidence and the resolved SBI operation policy handle.

It returns candidates, retry groups, and dependency suspicions. It cannot construct `NRFEventReader` or `UDREventReader`.

## 4. Python Tool Contract

```python
class FindHTTPFailuresRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt: ProcedureAttempt
    attempts_revision: str
    primary_reader: PrimaryEventReader
    event_ids: list[UUID]
    context: DetectionContext
    enabled_capabilities: set[CapabilityName] = Field(default_factory=set)
    run_dir: Path
    diagnostics_dir: Path
    max_issue_samples_per_code: int = 20
    fsync_outputs: bool = True


class FindHTTPFailuresResult(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    attempt_id: UUID
    status: Literal["success", "partial", "failed"]
    revision: str
    manifest: ArtifactDescriptor
    artifacts: list[ArtifactDescriptor]
    candidates: list[FailureCandidate]
    retry_groups: list[HTTPRetryGroup]
    dependency_suspicions: list[DependencySuspicion]
    inspected_event_count: int
    warning_counts: dict[str, int]
    elapsed_ms: int
    issues: list[DetectorWarning]
```

`DetectorWarning` aliases shared `Issue`. T06 validates the attempt ID,
analysis ID, T04 revision, `DetectionContext` attempt/analysis IDs, capture
bounds, phase-reader revision and resolved-policy-set revision before reading
events. Every requested event must be an accepted T04 assignment and resolve
through the injected primary reader to the same T02/T04 lineage.

`diagnostics_dir` resolves inside the run root. The final invocation path is
`normalized/diagnostics/<attempt-id>/T06`; absolute/traversal/symlink paths are
fatal. T06 receives no generic event store, evidence browser, NRF/UDR reader or
dependency index.

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

`uri` is never persisted when it contains a sensitive path/query value;
`uri_template` and masked target aliases are the persisted form. Candidate
`observed` embeds this typed projection, not arbitrary headers or body text.

Every candidate records detector rule ID/version, explicitness, score inputs, phase, relevance, source event/evidence IDs, and any downstream/cleanup flag.

Per the `FailureCandidate` ownership table (`LLD.md` section 4.6): T06 assigns
`severity` from its versioned rule table, resolves `capture_phase` through
`context.phase_reader`, sets `relevance` per section 14, persists every score
term, and always publishes `call_impact="inconclusive"` — only T23 produces
other impact values. Published candidates are immutable. Evidence cited by a
candidate is minted through the evidence registry (`LLD.md` section 24) at
detection time.

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

The operation-policy table arrives as a resolved, checksummed handle in
`context.policies` (configuration resolver, `LLD.md` section 29); T06 never
loads policy files from a bare version string.

Policy payload validation rejects duplicate operation IDs/signatures,
noncanonical URI templates, invalid status codes, negative timeouts, overlap
between contradictory terminal/retry rules, executable predicates and
unknown schema fields. Exact method/template matches outrank generic patterns;
ambiguous equal-specificity matches emit `T06_OPERATION_POLICY_AMBIGUOUS` and
use generic semantics rather than arbitrary ordering.

### 6.1 Transaction assembly algorithm

1. Load only assigned HTTP2 events and sort by `(frame,event_id)`.
2. Group request/response/informational/reset records by T02 document/stream
   identity. Validate one request and at most one terminal response per
   transaction; preserve duplicates as anomalies.
3. Resolve operation policy from normalized method/template/API/operation ID.
4. Derive completion state from persisted T02 fields and capture bounds. T06
   does not reassemble HTTP/2 or parse T01 decoder trees.
5. Build a deterministic transaction ID from T06 revision, attempt ID,
   document/stream key and first event ID.
6. Evaluate status, ProblemDetails, completion, content and routing rules in
   registered rule-ID order; deduplicate candidates with the same semantic
   rule and source-event set.

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

When the `http_structural_validation` capability is enabled and the resolved
operation policy declares structural requirements, validate only T02-retained
semantic fields, parse state, content type and bounded metadata. Complete 3GPP
OpenAPI validation is outside this capability. T06 never opens full bodies;
missing semantics remain evidence limitations for T19/T20 rather than a reason
to broaden access.

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

Retry grouping sorts transactions by first frame and requires the same
attempt/profile-compatible operation signature plus exact/strong correlation.
The configured policy supplies retry window/count and identity-change rules.
Group IDs use T06 revision, attempt ID, operation signature and first request
event ID. Endpoint/URI values in the signature are masked/template values.

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

Suspicion IDs use T06 revision, attempt ID, reason code and sorted initial
evidence IDs. Target hints are allowlisted masked FQDN/NF/service/correlation
aliases; `rationale` is a registered template rendered from reason codes, not
untrusted body text. Equal suspicions merge evidence; contradictory target
hints remain separate.

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

### 17.1 Candidate construction algorithm

For every matched detector rule:

1. Select the anchor frame defined by the rule (terminal response, reset,
   timeout deadline or request frame).
2. Mint an immutable evidence record (`http_transaction`,
   `http_completion_anomaly` or `http_retry_group`) through the shared registry
   from sorted primary source events/refs and T06 revision scope.
3. Build all shared `ScoreTerm` rows: one base term plus explicit bonuses and
   penalties for ProblemDetails, retry exhaustion/recovery, assignment
   confidence, capture boundary, cleanup/downstream and relevance.
4. Sum/clamp canonical decimals to `[0,1]`; set severity from the resolved rule
   table, phase through `context.phase_reader`, relevance through section 14
   and `call_impact="inconclusive"`.
5. Mint the candidate ID as UUIDv5 over analysis ID, T06 revision, attempt ID,
   rule ID, sorted source event IDs and semantic occurrence.
6. Sort candidates by frame, detector rule priority and candidate UUID.

Every evidence ID must resolve through T18 before T15, including
`provider=none` runs. A duplicate evidence identity with divergent content is
`RUN_EVIDENCE_INTEGRITY` and fails publication.

## 18. Output and Persistence

T06 publishes one immutable per-attempt detector generation:

```text
normalized/diagnostics/<attempt-id>/T06/
  failure_candidates.jsonl
  retry_groups.jsonl
  dependency_suspicions.jsonl
  http_failures_manifest.json
staging/T06-<attempt-id>-<uuid>/
```

The common diagnostic aggregator consumes these descriptors after T06-T08
complete; parallel detectors never append to one shared file.

T06 revision inputs are T04/attempt payload revision, sorted event IDs and T02
parent revision, T21 phase-reader revision, `DetectionContext` visibility and
assignment confidence, resolved operation/scoring policy checksums, enabled
behavior capabilities, tool/schema version and output-affecting limits.

Descriptors use shared schemas with types `http_failure_candidates`,
`http_retry_groups`, `dependency_suspicions` and `http_failures_manifest`,
verifiable counts, T04 manifest parent checksum and T06 revision. Empty JSONL
files are still published.

The manifest records lineage/policy/capability/config identities, status,
inspected/transaction/retry/candidate/suspicion/warning counts, artifacts,
sampled issues and timing/peak temporary bytes.

### 18.1 Runner and publication validation

```python
def find_http_failures(req: FindHTTPFailuresRequest) -> FindHTTPFailuresResult:
    lineage = validate_detector_request(req, tool="T06")
    policies = validate_http_policies(req.context.policies)
    revision = build_t06_revision(req, lineage, policies)
    if existing := find_existing_detector_result(req.run_dir, req.attempt.attempt_id,
                                                  "T06", revision):
        return load_validated_result(existing)
    staging = make_detector_staging(req.run_dir, "T06", req.attempt.attempt_id)
    events = load_assigned_primary_events(req, lineage)
    transactions = assemble_http_transactions(events, req, policies)
    groups = build_retry_groups(transactions, req, policies)
    candidates, suspicions, evidence, issues = evaluate_http_rules(
        transactions, groups, req, policies, revision)
    descriptors = write_and_validate_t06(staging, candidates, groups, suspicions,
                                         evidence, revision, lineage)
    manifest = build_validate_t06_manifest(req, descriptors, candidates, groups,
                                           suspicions, issues, revision)
    publish_detector_generation(staging, evidence, manifest_last=True)
    return result_from_manifest(manifest)
```

Before publication prove unique IDs; assigned-primary source membership;
resolvable evidence; candidate score=sum(terms), phase/relevance/severity
ownership and `call_impact="inconclusive"`; retry event uniqueness/order;
suspicion reason/target allowlists; no clear sensitive URI/header/body data;
same-revision descriptors/counts/checksums; and manifest-last publication.

## 19. Failure Semantics

- Unknown attempt/event: validation error.
- Non-primary event supplied: reject and emit access-boundary warning.
- Mixed/stale T02/T04/T21 lineage, incompatible policy, path escape or
  descriptor mismatch: fatal with no T06 manifest.
- Unknown operation policy: continue generic detection with lower confidence.
- Malformed normalized body summary: emit warning and use status/completion evidence.
- Missing full evidence reference: evidence-integrity warning; candidate may remain with reduced confidence.
- Detector internal exception for one event: quarantine event, continue, mark partial.

Unknown operation policy, represented capture truncation, recovered retry and
dependency suspicion are valid results and do not alone make status partial.
Partial means a recoverable event/rule was skipped or evidence was lost.
Fatal failure preserves prior revisions and publishes no manifest.

## 20. Performance and Resource Requirements

- O(HTTP events in selected attempt).
- Build retry groups using indexed operation signatures.
- Do not load full bodies. Structural checks use only bounded T02-retained
  semantic metadata under the named capability/policy.
- Typical attempt should complete in milliseconds.
- Record events inspected, groups formed, full lookups, elapsed time, and peak temporary bytes.

## 21. Security and Privacy

- Primary reader capability only.
- Do not log URIs containing subscriber IDs without masking.
- Authorization/cookie/certificate headers are never candidate summaries.
- Body excerpts are excluded; candidates cite evidence IDs.
- Treat ProblemDetails and body text as untrusted data.
- T06 evidence records reference only assigned primary events. Direct IDs,
  generic indexes, cursors or selector expansion cannot reach NRF/UDR because
  no dependency capability/reader is present.

## 22. Observability

Logs include detector rule, event/candidate ID, status/completion class, phase, relevance, retry outcome, and warning code.

Metrics include candidates by category/status, missing responses, resets, recovered/exhausted retries, background candidates, dependency suspicions, unknown operations, and detector latency.

Minimum registered codes are `T06_UNKNOWN_OPERATION`,
`T06_OPERATION_POLICY_AMBIGUOUS`, `T06_MALFORMED_BODY_SUMMARY`,
`T06_MISSING_EVIDENCE_REF`, `T06_EVENT_QUARANTINED`,
`T06_TRANSACTION_CONFLICT` and `T06_OUTPUT_INVARIANT_FAILED`; access/evidence
violations use shared `RUN_ACCESS_BOUNDARY`/`RUN_EVIDENCE_INTEGRITY`.

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
8. Add deterministic revision, per-attempt persistence and manifest validation.

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
- Policy ambiguity/validation and structural-capability gating.
- Evidence/candidate/retry/suspicion ID and decimal score determinism.
- Descriptor/manifest/count validation.

### 25.2 Integration tests

- SBI failure followed by NAS reject.
- Multiple endpoint retries ending in success/failure.
- Background primary HTTP error during a UE call.
- Capture starts before request or ends before timeout.
- UDM-facing error causing UDR suspicion without UDR access.
- No-NF-available symptom causing NRF suspicion without NRF access.
- T18 resolves every emitted evidence ID before T15 in provider-none mode.
- Identical rerun returns the same revision; policy/context change creates a
  sibling generation.

### 25.3 Negative tests

- Recovered retry is not terminal root candidate.
- Timestamp overlap alone does not associate background event.
- One-way notification does not produce missing-response error.
- Direct NRF/UDR reader/import access fails architectural test.
- Direct NRF/UDR IDs, indexes, cursors and selector expansion cannot be cited
  as T06 evidence.
- Stale T04/T21 revision, unassigned event, corrupt descriptor, executable
  policy payload and symlink escape publish no manifest.
- Sensitive URI/query/header/body values do not appear in artifacts/issues/logs.

### 25.4 Golden tests

- Stable candidates, score terms, evidence IDs, retry groups, suspicions,
  descriptors and manifest for fixed status/timeout/reset/retry/loop fixtures.
- Golden normalization removes generated timings only, not source frames,
  ordering, scores, phase/relevance or evidence IDs.

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
9. Every evidence ID resolves before T15 and every published artifact passes
   section 18.1 validation.
10. Revision-pinned per-attempt output is immutable and safe under parallel
    T06-T08 execution.

## 27. Mechanical Implementation Checklist

1. Define request/result/HTTP observation/retry/suspicion models with shared
   Issue, candidate, evidence, descriptor and revision schemas.
2. Register T06 issue and evidence record types.
3. Validate attempt, assigned event IDs, T02/T04/T21 lineage and context IDs.
4. Validate run-relative per-attempt T06 paths and create staging only.
5. Validate resolved operation/scoring policy payload/checksums.
6. Build T06 revision and return an existing identical generation when valid.
7. Load only accepted primary HTTP2 events in deterministic order.
8. Assemble transactions from T02 document/stream/completion metadata.
9. Resolve exact/generic operation policies with ambiguity handling.
10. Evaluate status and ProblemDetails mismatch rules.
11. Evaluate completion/reset/truncation/one-way timeout rules.
12. Evaluate capability-gated bounded structural metadata rules.
13. Build deterministic retry groups and routing/redirect loops.
14. Resolve attempt association, capture phase, relevance and cleanup flags.
15. Build explicit score terms and immutable primary candidates.
16. Mint revision-scoped evidence and verify no divergent duplicates.
17. Build primary-evidence-only dependency suspicions with masked hints.
18. Write candidate/retry/suspicion files including empty outputs.
19. Validate IDs, membership, scoring, privacy, descriptors and counts.
20. Build manifest with full counters and sampled issues.
21. Publish evidence/data then manifest last; preserve sibling generations.
22. Add unit/integration/negative/security/golden tests from section 25.
