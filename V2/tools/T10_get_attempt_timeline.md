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


class AttemptTimelineResult(BaseModel):
    schema_version: Literal["2.0"]
    attempt_id: UUID
    mode: str
    items: list[TimelineItem]
    total_matching: int
    returned: int
    truncated: bool
    next_cursor: str | None
    warnings: list[str]
```

Default limits: internal 50, model 20, report 100, dependency-expanded 50 unless configured lower.

## 5. Timeline Item Model

```python
class TimelineItem(BaseModel):
    item_id: UUID
    attempt_id: UUID
    child_attempt_id: UUID | None
    event_id: UUID | None
    candidate_id: UUID | None
    frame: int
    timestamp: Decimal | None
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

## 7. Ordering

Sort key:

1. Timestamp when available.
2. Frame number.
3. Same-frame protocol nesting order: outer transport/NGAP before embedded NAS unless profile semantics require request-before-container display.
4. Source ordinal/event ID for deterministic tie break.

Synthetic timeout/missing items sort at their calculated deadline and retain anchor evidence.

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

## 11. Pagination and Cursor

Cursor payload contains:

- Analysis/attempt ID.
- Query/filter hash.
- Last sort key.
- Timeline revision checksum.
- Expiry/version.

It is authenticated with a local key. A cursor from another query, attempt, revision, or analysis is rejected.

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

## 13. Report Timeline

Report mode may include more events but remains bounded. It should show human-readable procedure stages and exact frames while avoiding raw trees/bodies.

## 14. Deterministic Item IDs

Packet-backed item ID:

```text
UUIDv5(attempt_id + event_id + label + stage_id)
```

Synthetic item ID:

```text
UUIDv5(attempt_id + candidate_id/stage_id + synthetic_type)
```

## 15. Failure Semantics

- Unknown attempt: validation error.
- Missing assigned event: partial result with integrity warning.
- Candidate references unknown event: include candidate summary with warning; fail if evidence cannot be resolved for major conclusion.
- Invalid/stale cursor: validation error.
- Dependency result for another attempt: reject.
- Timeline exceeds internal safety limit before pagination: stream/sort using index; do not load all items unnecessarily.

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

## 18. Observability

Logs include analysis/attempt, mode, filters, total/returned counts, truncation, cursor use, and warning code.

Metrics include timeline query latency, item counts by mode/label, compression ratio, pagination count, and stale cursor failures.

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

## 21. Tests

### 21.1 Unit tests

- Same timestamp/frame ordering and embedded NAS ordering.
- Label precedence and secondary flags.
- Parent/child deduplication.
- Filters before pagination.
- Cursor authentication/query/revision mismatch.
- Model compression retention rules.
- Deterministic item IDs.

### 21.2 Integration tests

- Attempt with HTTP retry, PFCP failure, NAS reject, cleanup.
- Missing-transition synthetic item.
- Two overlapping attempts with no leakage.
- Dependency-expanded NRF/UDR result.
- Large attempt paginated across same-frame events.
- Missing evidence reference warning.

### 21.3 Negative tests

- Background neighboring packets excluded.
- Hidden NRF/UDR data cannot enter initial timeline.
- Invalid cursor cannot access another attempt.

## 22. Acceptance Criteria

T10 is complete when:

1. Timeline order is deterministic and semantically useful.
2. Every packet-backed item resolves to complete evidence.
3. Attempt boundaries prevent unrelated-event leakage.
4. Internal/model/report modes apply correct bounded limits.
5. Pagination is stable without duplicates or omissions.
6. Compression retains all primary/scenario evidence.
7. Hidden dependency data appears only through completed inspection results.
