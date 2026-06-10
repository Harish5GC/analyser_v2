# T10 `get_attempt_timeline` Implementation Specification

## 1. Purpose

`get_attempt_timeline` returns a bounded, ordered, evidence-linked semantic timeline for one attempt. It supports internal diagnostics, reports, model evidence, and interactive investigation without loading complete decoder trees.

## 2. Non-Goals

T10 must not:

- Diagnose or rerank failures.
- Include events from unrelated attempts because they are nearby in time.
- Return unbounded full bodies/protocol trees.
- Read NRF/UDR partitions unless their completed T24/T25 inspection results are explicitly supplied as dependency timeline items.
- Change detector labels or attempt assignments.

## 3. Inputs and Boundary

- T04 attempt and event assignments.
- T06-T09 candidate/stage/retry results.
- Primary event reader.
- Optional completed dependency inspection results for expanded/final views.

Initial timeline mode is primary-only. Dependency-expanded mode receives result objects, not hidden readers.

## 4. Python Tool Contract

```python
class GetAttemptTimelineRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    attempt_id: UUID
    attempt: ProcedureAttempt
    attempts_revision: str
    primary_reader: PrimaryEventReader
    request_result: UERequestResult
    http_result: FindHTTPFailuresResult
    nas_ngap_result: FindNASNGAPFailuresResult
    pfcp_result: FindPFCPFailuresResult
    missing_result: DetectMissingTransitionsResult
    dependency_results: list[DependencyInspectionResult] = Field(default_factory=list)
    run_dir: Path
    timelines_dir: Path
    cursor_policy: ResolvedPolicy
    masking_policy: ResolvedPolicy
    mode: Literal["internal", "model", "report", "dependency_expanded"]
    protocols: set[str] | None = None
    labels: set[str] | None = None
    frame_start: int | None = None
    frame_end: int | None = None
    time_start: Decimal | None = None
    time_end: Decimal | None = None
    limit: int | None = None
    cursor: str | None = None
    include_children: bool = True
    max_issue_samples_per_code: int = 20
    fsync_outputs: bool = True


class AttemptTimelineResult(BaseModel):
    schema_version: Literal["2.0"]
    attempt_id: UUID
    mode: TimelineMode
    query_id: UUID
    revision: str
    manifest: ArtifactDescriptor
    timeline_artifact: ArtifactDescriptor
    items: list[TimelineItem]
    total_matching: int
    returned: int
    truncated: bool
    next_cursor: str | None
    issues: list[Issue]
```

T10 validates that T05-T09 results are published for this attempt and share the
same T02/T04 lineage. `dependency_results` must be empty unless mode is
`dependency_expanded`; every result must be completed/partial, same-attempt,
lineage-valid output from T24/T25. No hidden reader or dependency index is
accepted.

Hard maxima are internal 50, model 20, report 100 and dependency-expanded 50.
Resolved configuration/request `limit` may lower but never raise these maxima;
model is always clamped to 20. Paths resolve inside the run root under
`normalized/diagnostics/<attempt-id>/T10`.

## 5. Timeline Item Model

```python
class TimelineItem(BaseModel):
    item_id: UUID
    attempt_id: UUID
    child_attempt_id: UUID | None
    event_id: UUID | None
    candidate_id: UUID | None
    checkpoint_id: UUID | None
    source_kind: Literal[
        "event", "transition", "retry", "candidate", "terminal_effect",
        "stage_result", "dependency_result"
    ]
    synthetic: bool = False
    frame: int
    timestamp: Decimal | None
    deadline_timestamp: Decimal | None = None
    sort_ordinal: int
    protocol: str
    direction: str
    stage_id: str | None
    message: str
    label: Literal[
        "expected", "anomalous", "failure", "retry", "cleanup",
        "terminal", "missing_transition", "dependency_evidence"
    ]
    outcome: str | None
    identifiers: dict[str, str]
    evidence_ids: list[UUID]
    full_record_available: bool
    summary_attributes: dict[str, JsonValue]
```

`label` is the closed eight-value `TimelineLabel` from LLD section 13.1.
Adding a ninth label requires a schema/policy revision, renderer support and
golden tests; runtime configuration cannot add labels. Messages and summary
attributes use registered templates/allowlisted fields and are masked by mode.

Summaries contain allowlisted semantic fields only. Full data is accessed through T18.

## 6. Item Sources

- Primary canonical events assigned by T04.
- T04 state transitions and retries.
- T06 HTTP candidates/retry groups.
- T07 NAS/NGAP candidates and terminal effects.
- T08 PFCP transactions/consistency candidates.
- T09 missing-stage results.
- Optional T24/T25 result summaries in dependency-expanded mode.

Synthetic missing-transition items use the expected deadline/anchor frame and are clearly marked as synthetic diagnostic items with no fabricated packet frame.

### 6.1 Item construction algorithm

1. Load accepted T04 assignments and primary events in `(frame,event_id)`
   order; validate same-attempt lineage and evidence references.
2. Project event, transition and retry items with registered message templates.
3. Overlay T06-T08 candidates/groups/effects/checks and T09 stage/suppression
   results by their IDs/evidence, never by summary-text matching.
4. Deduplicate a source event shared with a child attempt into one item and add
   relationship/secondary labels in `summary_attributes`.
5. For a synthetic missing/deadline item, set `frame` to the real anchor /
   predecessor frame, `synthetic=true`, and `deadline_timestamp` to the
   calculated deadline when available. Never invent a packet frame at the
   deadline.
6. In dependency-expanded mode, project only supplied validated inspection
   result summaries and their evidence IDs; do not resolve hidden events.
7. Apply label precedence, mode masking, filters, compression, ordering and
   pagination in that order.

Every item has at least one source ID (`event_id`, `candidate_id`,
`checkpoint_id` or evidence ID). `full_record_available=true` only when all
required evidence refs resolve through T18 for the same revision.

## 7. Ordering

Sort key:

1. Frame number.
2. Same-frame semantic ordinal: trigger/request, outer NGAP/transport,
   embedded NAS, SBI/PFCP, transitions/retries, candidates/effects and synthetic
   checkpoint evidence.
3. Valid source timestamp as a secondary audit tie-break only; timestamp never
   reverses frame order.
4. Source kind, source ordinal and item UUID.

Synthetic timeout/missing items sort at their real anchor frame with a semantic
ordinal after the predecessor evidence and retain the calculated deadline in
`deadline_timestamp` and summary attributes.

## 8. Label Resolution

Label precedence:

1. Explicit failure candidate.
2. Terminal effect.
3. Missing transition.
4. Retry.
5. Cleanup.
6. Detector anomaly.
7. Expected stage/event.

One packet/event can carry multiple internal labels, but the timeline item exposes one primary label plus secondary flags in `summary_attributes`.

## 9. Attempt Scope

Include:

- Events owned by the attempt.
- Explicitly linked child attempt events when requested.
- Shared parent/child trigger/terminal records once, with relationship metadata.
- Dependency result items only for the same attempt.

Exclude:

- Nearby unassigned/background packets; T19 provides context.
- Events assigned only to another attempt.
- Hidden NRF/UDR traffic without completed inspection result.

## 10. Filtering

Filters are applied before pagination:

- Protocol set.
- Primary label set.
- Frame or time window, not both unless consistent.
- Child inclusion.
- Mode-specific field masking.

Invalid filter combinations are rejected. Empty result is valid.

Frame/time bounds are intersected with attempt bounds and cannot broaden child
or dependency scope. If both frame and time bounds are supplied, every item
must satisfy both and the ranges must overlap the attempt. Protocol and label
values are validated against registered enums before any read.

## 11. Pagination and Cursor

T10 uses the shared `CursorEnvelope` (`LLD.md` section 30) with
`scope="attempt_timeline"`. `subject` contains attempt ID, mode, canonical
query/filter hash and include-children/dependency-result revision bindings;
`page` contains offset, effective limit, result revision and count hint.
`artifact_revision` is this timeline query revision and `run_revision` pins the
run manifest. Signing/expiry/replay policy comes from the resolved cursor
policy; raw last-sort keys and unsigned offsets are forbidden.

Validation rechecks analysis/scope/subject/query/policy/result/run revisions,
expiry, signature, nonce/replay policy and effective hard limit before reading.
A cursor cannot change filters, mode, child inclusion, dependency results or
masking policy and cannot grant access to another attempt.

Pagination must not skip/duplicate same-frame items.

## 12. Model Timeline Compression

Model mode keeps:

- Trigger/request.
- State transitions.
- First/relevant retries.
- Primary and alternative candidate evidence.
- Terminal effect.
- First baseline divergence marker when supplied.

It removes repetitive successful keepalive/routine events and compresses retry groups into one item while preserving frames/count/status sequence.

Compression never removes evidence referenced by the primary candidate or failed scenario checkpoint.

Mandatory item set is trigger/request, primary/alternative candidate evidence,
terminal effect, first causal missing transition and supplied failed checkpoint
evidence. Retry/expected routine items are grouped by stable signature and
their complete frames/status/evidence lists retained in one item. If mandatory
content still cannot fit 20 items after legal grouping, model-mode construction
fails deterministically with `T10_MODEL_MANDATORY_OVERFLOW`; it never silently
drops mandatory evidence. Nonessential details may be shortened before item
removal.

## 13. Report Timeline

Report mode may include more events but remains bounded. It should show human-readable procedure stages and exact frames while avoiding raw trees/bodies.

Timeline messages describe observed events, profile checkpoints and detector
candidate evidence. They do not state final diagnostic conclusions; root-cause
and scenario conclusions remain owned by T12/T14/T17.

## 14. Deterministic Item IDs

Packet-backed item ID:

```text
UUIDv5(timeline_revision + attempt_id + source_kind + event_id + label + stage_id)
```

Synthetic item ID:

```text
UUIDv5(timeline_revision + attempt_id + candidate_id/checkpoint_id/stage_id + synthetic_type)
```

### 14.1 Revision and persistence

Canonical query hash includes attempt/result parent revisions, mode, normalized
filters, effective hard-clamped limit, child inclusion, dependency-result
revisions, cursor/masking policy checksums and timeline schema/tool version.
`query_id = UUIDv5(analysis_id, query_hash)` and the T10 revision is the shared
revision-envelope digest over those inputs.

```text
normalized/diagnostics/<attempt-id>/T10/<query-id>/
  timeline.jsonl
  timeline_manifest.json
staging/T10-<query-id>-<uuid>/
```

Descriptors have types `attempt_timeline` and `attempt_timeline_manifest`,
verifiable counts, T04 parent checksum and T10 revision. The manifest records
all parent revisions (T04-T09 and optional T24/T25), mode/query/filter hashes,
masking/cursor policy identities, total/returned/truncation counts, label/source
counts, artifacts, sampled issues and timings. Identical queries return the
existing immutable generation; changed filters/parents create a sibling query
directory.

`timeline.jsonl` stores the complete filtered/compressed ordered result set for
this query revision. `AttemptTimelineResult.items` is the requested page;
`total_matching` equals timeline rows and `returned` equals page length. The
cursor page offset therefore cannot be affected by later source changes because
those changes create a new T10 revision.

Before publication validate unique item IDs; source/evidence resolution;
attempt/child/dependency scope; closed labels; frame-primary ordering;
synthetic anchor/deadline semantics; mode masking and hard caps; mandatory
model evidence retention; filter-before-page counts; descriptor/checksum/count
agreement; and no cursor or sensitive-value persistence. Publish timeline then
manifest last.

## 15. Failure Semantics

- Unknown attempt: validation error.
- Missing/failed/stale T05-T09 parent result, mixed lineage, invalid dependency
  result, incompatible cursor/masking policy or path escape: fatal with no T10
  manifest.
- Missing assigned event: partial result with integrity warning.
- Candidate references unknown event: include candidate summary with warning; fail if evidence cannot be resolved for major conclusion.
- Invalid/stale cursor: validation error.
- Dependency result for another attempt: reject.
- Timeline exceeds internal safety limit before pagination: stream/sort using index; do not load all items unnecessarily.
- Mandatory model evidence cannot fit the hard 20-item cap after legal grouping:
  fail model-mode query with `T10_MODEL_MANDATORY_OVERFLOW`.

An empty filtered page, truncation, valid compression and omitted routine items
are successful query outcomes. Missing noncritical evidence yields partial;
major conclusion evidence-integrity failure is fatal. Prior query revisions are
never overwritten.

## 16. Performance and Resource Requirements

- Query attempt/event/candidate indexes; no full-capture scan.
- O(items matching attempt + sort), with source files already frame ordered where possible.
- Cache immutable timeline revision results.
- Record total/returned items, compression ratio, query latency, cursor errors, and evidence-resolution warnings.

## 17. Security and Privacy

- Mask subscriber and endpoint values according to mode.
- Model mode never includes raw bodies, authorization headers, or full identifiers.
- Treat message/detail text as untrusted.
- Cursor is opaque/authenticated and contains no sensitive values.
- Internal/report modes still mask policy-declared values unless an authorized
  local surface explicitly permits a local display mask. Model and dependency-
  expanded modes never expose clear identifiers, raw bodies or credentials.
- T10 never receives NRF/UDR readers. Dependency items come only from validated
  T24/T25 result objects and cannot be expanded into hidden events.

## 18. Observability

Logs include analysis/attempt, mode, filters, total/returned counts, truncation, cursor use, and warning code.

Metrics include timeline query latency, item counts by mode/label, compression ratio, pagination count, and stale cursor failures.

Minimum registered codes are `T10_PARENT_RESULT_MISSING`,
`T10_EVIDENCE_UNRESOLVED`, `T10_ITEM_SOURCE_INVALID`,
`T10_MODEL_MANDATORY_OVERFLOW`, `T10_CURSOR_INVALID`, `T10_CURSOR_EXPIRED`,
`T10_CURSOR_SCOPE_MISMATCH` and `T10_OUTPUT_INVARIANT_FAILED`; shared
authorization/integrity conditions use `RUN_ACCESS_BOUNDARY` and
`RUN_EVIDENCE_INTEGRITY`.

## 19. Proposed Python Code Structure

```text
V2/harness/analysis/
  timeline.py
  timeline_labels.py
  timeline_compression.py
  timeline_cursor.py
V2/harness/models/
  evidence.py
V2/harness/storage/
  timeline_cache.py
```

## 20. Implementation Sequence

1. Define item/result/cursor schemas.
2. Implement primary event and transition timeline.
3. Add candidate/retry/missing-stage overlays.
4. Add deterministic ordering and pagination.
5. Add model/report compression modes.
6. Add dependency-expanded result items and caching.
7. Add revision-pinned query artifacts and shared authenticated cursors.

## 21. Tests

### 21.1 Unit tests

- Same timestamp/frame ordering and embedded NAS ordering.
- Label precedence and secondary flags.
- Parent/child deduplication.
- Filters before pagination.
- Cursor authentication/query/revision mismatch.
- Model compression retention rules.
- Deterministic item IDs.
- Hard mode limits, especially model limit values above/below 20.
- Closed eight-label validation and frame-primary timestamp disagreement.
- Synthetic anchor/deadline semantics and mandatory-overflow behavior.
- Revision/query hash, descriptor and manifest determinism.

### 21.2 Integration tests

- Attempt with HTTP retry, PFCP failure, NAS reject, cleanup.
- Missing-transition synthetic item.
- Two overlapping attempts with no leakage.
- Dependency-expanded NRF/UDR result.
- Large attempt paginated across same-frame events.
- Missing evidence reference warning.
- Every packet/candidate/checkpoint evidence ID resolves through T18 before
  T15 in provider-none mode.
- Identical query rerun returns the same revision; filter/parent/policy change
  creates a sibling query.

### 21.3 Negative tests

- Background neighboring packets excluded.
- Hidden NRF/UDR data cannot enter initial timeline.
- Invalid cursor cannot access another attempt.
- Tampered/expired/cross-scope/cross-query/cross-revision/replayed cursor is
  rejected without reading a page.
- Dependency-expanded result from another attempt or stale lineage is rejected.
- Model limit request above 20 still returns at most 20; mandatory overflow
  fails rather than dropping evidence.
- Sensitive identifiers/bodies/credentials and cursor signing material do not
  appear in artifacts/issues/logs.

### 21.4 Golden tests

- Byte-stable item ordering/labels/sources/evidence, compressed model timeline,
  report timeline, dependency projection, descriptors and manifest.
- Multi-page same-frame fixture has no duplicates/omissions and a regenerated
  cursor over the same query returns the same subsequent items.

## 22. Acceptance Criteria

T10 is complete when:

1. Timeline order is deterministic and semantically useful.
2. Every packet-backed item resolves to complete evidence.
3. Attempt boundaries prevent unrelated-event leakage.
4. Internal/model/report modes apply correct bounded limits.
5. Pagination is stable without duplicates or omissions.
6. Compression retains all primary/scenario evidence.
7. Hidden dependency data appears only through completed inspection results.
8. Model mode is hard-clamped to 20 and preserves mandatory candidate /
   checkpoint evidence or fails deterministically.
9. The closed eight-label taxonomy and frame-primary ordering are enforced.
10. Shared authenticated cursors cannot broaden scope or cross query/revision.
11. Every immutable query artifact passes section 14.1 validation and publishes
    manifest last.

## 23. Mechanical Implementation Checklist

1. Import shared timeline/issue/revision/descriptor/cursor/masking models.
2. Register T10 issue codes and validate cursor/masking policy handles.
3. Validate attempt and published T05-T09 parent revisions/lineage.
4. Validate optional T24/T25 result status, attempt and lineage; accept no
   hidden readers.
5. Normalize filters, child flag and effective hard-clamped mode limit.
6. Build query hash, query ID and T10 revision; return an identical existing
   query generation when valid.
7. Load accepted attempt/child primary events through indexes only.
8. Project event/transition/retry items with allowlisted masked summaries.
9. Overlay T06-T09 candidates/effects/checks/stages by IDs/evidence.
10. Project only validated dependency result summaries in expanded mode.
11. Deduplicate shared parent/child sources and apply one primary label plus
    secondary flags.
12. Build synthetic missing/deadline items with real anchor frames and separate
    deadline timestamps.
13. Apply mode masking and closed-label validation.
14. Apply filters before compression/pagination.
15. Compress model mode by stable groups while preserving mandatory evidence.
16. Fail if mandatory content cannot fit the hard 20-item cap.
17. Sort by frame-primary semantic order and deterministic UUID ties.
18. Validate or mint shared authenticated cursor envelopes bound to query /
    policy/result/run revisions.
19. Write timeline JSONL and manifest under immutable query directory.
20. Validate source/evidence/scope/order/limit/privacy/count/checksum invariants.
21. Publish timeline then manifest last and preserve sibling queries.
22. Add unit/integration/negative/security/golden tests from section 21.
