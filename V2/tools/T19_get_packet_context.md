# T19 `get_packet_context` Implementation Specification

## 1. Purpose

`get_packet_context` retrieves bounded packets/events before and after an issue so investigators can inspect causal context not assigned to the same attempt or protocol transaction.

It first uses retained T01/T02 evidence and invokes T20 only when the requested detail is not already available.

## 2. Non-Goals

T19 must not:

- Return an unbounded capture slice.
- Alter attempt assignments or root-cause ranking.
- Treat nearby packets as causally related.
- Execute arbitrary tshark filters/options.
- Bypass NRF/UDR partition access policy.
- Send raw context directly to a model.

## 3. Caller and Access Boundary

Callers include deterministic investigation, T15 bounded evidence planning, T24/T25 inspectors, and local operator workflows. Each call carries an evidence capability controlling accessible partitions and detail.

Primary callers may see neighboring primary/raw packet metadata but cannot retrieve hidden NRF/UDR semantic records unless an approved dependency capability scopes them.

## 4. Python Tool Contract

```python
class GetPacketContextRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    caller_capability: EvidenceCapability
    anchor: ContextAnchor
    window: ContextWindow
    protocol_filter: ValidatedProtocolFilter | None = None
    detail: Literal["summary", "full_protocol", "raw_packet"] = "summary"
    page_size_bytes: int = 1_000_000
    max_packets: int = 200
    cursor: str | None = None


class PacketContextResult(BaseModel):
    schema_version: Literal["2.0"]
    query_id: UUID
    effective_anchor: ContextAnchor
    effective_window: ContextWindow
    packets: list[ContextPacket]
    artifact: ArtifactDescriptor
    source_mode: Literal["retained", "targeted_redecode", "mixed"]
    total_matching: int
    truncated: bool
    next_cursor: str | None
    warnings: list[str]
```

## 5. Anchor Model

Exactly one anchor is required:

```python
class ContextAnchor(BaseModel):
    frame: int | None = None
    timestamp: Decimal | None = None
    event_id: UUID | None = None
    evidence_id: UUID | None = None
    candidate_id: UUID | None = None
```

Logical IDs resolve through T18 indexes to one or more frames. Ambiguous multi-frame anchors require policy-defined primary frame or explicit request refinement.

## 6. Window Model

Exactly one window mode:

```python
class ContextWindow(BaseModel):
    frames_before: int | None = 20
    frames_after: int | None = 20
    seconds_before: Decimal | None = None
    seconds_after: Decimal | None = None
```

Defaults: 20 frames before/after. Clamp to configured maximum frames, seconds, packets, and bytes. Any clamp is returned explicitly.

## 7. Context Packet Model

```python
class ContextPacket(BaseModel):
    frame: int
    timestamp: Decimal | None
    src: Endpoint | None
    dst: Endpoint | None
    protocols: list[str]
    summary: str
    detail: JsonValue | None
    event_ids: list[UUID]
    attempt_ids: list[UUID]
    correlation: Literal[
        "selected_attempt", "other_attempt", "unassigned", "unknown"
    ]
    partition: str | None
    evidence_ids: list[UUID]
    source_ref: CompactSourceRef
```

Packets unrelated to the selected attempt remain visible and are clearly labelled; proximity does not imply relevance.

## 8. Retained-Evidence Resolution

1. Resolve anchor/frame range through frame/time indexes.
2. Read raw packet-level artifacts when configured and sufficient.
3. Add normalized event/attempt/correlation metadata.
4. Use T18 for requested complete protocol records already retained.
5. Identify missing protocol tree/detail requiring T20.

Do not run T20 when retained evidence already satisfies the request.

## 9. Detail Modes

### Summary

Frame/time/endpoints/protocols/short semantic summary and correlation only.

### Full protocol

Complete selected protocol trees/records for packets in the bounded page, subject to capability and byte pagination.

### Raw packet

Raw tshark packet representation or bytes metadata, local/admin-only by default. Model-facing paths cannot request this mode.

## 10. Protocol Filter

`ValidatedProtocolFilter` is an allowlisted AST, for example:

```python
class ValidatedProtocolFilter(BaseModel):
    protocols: set[str]
    frame_predicates: list[SafePredicate]
    endpoint_predicates: list[SafePredicate]
```

Raw display-filter strings from user/model are not executed. T19 may translate validated filters into T20 request structures.

## 11. Partition and Dependency Policy

- Raw packet summaries may reveal protocol presence but must not expose hidden NRF/UDR semantic content to primary/model callers.
- Full NRF/UDR records require approved dependency capability and must remain within selector/window scope.
- T24/T25 may request context around selected dependency transactions.
- Context artifact records capability/scope used.

## 12. T20 Fallback Decision

Call T20 only when:

- Requested protocol tree was not retained by T01.
- Raw packet detail requested but no raw artifact exists.
- Decode-as is required for the bounded window.
- Required field is absent from retained tree and caller is authorized.

Generated T20 query uses the clamped frame/time range and validated protocol/filter fields. Caller cannot append arbitrary arguments.

## 13. Derived Context Artifact

```text
evidence/context/<query-id>/
  query.json
  packets.jsonl
  context_manifest.json
```

Manifest records:

- Source PCAP/decoder/normalization checksums.
- Anchor/window requested and effective.
- Filter/detail/capability hash.
- Retained versus T20 sources and their artifact IDs.
- Packet/byte counts, pagination, warnings, timing, checksums.

Publish query/result/manifest atomically, manifest last.

## 14. Query Identity and Caching

Query ID/cache key includes source checksum, anchor, effective window, filter, detail, capability scope, and tool version. Identical authorized query can reuse immutable artifact.

Cache cannot be reused under broader capability/detail without revalidation.

## 15. Pagination

Sort by frame/timestamp. Cursor contains query/artifact revision, last frame/ordinal/byte position, detail, capability, and expiry, authenticated locally.

Same-frame multi-record packets are not skipped/duplicated. Larger windows require continuation, not automatic limit increase.

## 16. Failure Semantics

- Invalid/multiple anchors or windows: validation error.
- Anchor not found: successful empty/not-found result with warning according to selector type.
- Requested window outside capture: clamp and warn; fully outside yields empty.
- Protocol filter invalid: reject before lookup/T20.
- Access violation: deny/audit.
- Retained artifact integrity failure: do not return exact content; fail/partial.
- T20 failure: return retained portion with partial warning when useful.
- Invalid cursor: validation error.
- Publication failure: fail derived artifact.

## 17. Performance and Resource Requirements

- Frame/time index lookup, no full-capture scan.
- Stream result and artifact writes.
- Enforce maximum packets/bytes before full tree materialization.
- Cache identical queries.
- Record packets/bytes scanned/returned, retained/T20 fraction, cache hit, and latency.

## 18. Security and Privacy

- Capability/partition/detail enforcement.
- Safe filters only; no shell commands.
- Path-safe immutable artifacts.
- Raw packet mode local/admin policy.
- Do not log endpoints/identities/content.
- Derived artifacts inherit source retention/security policy.

## 19. Observability

Logs include query/caller/anchor type/effective window/filter protocols/detail/source mode/counts/clamps/access/T20 status/duration.

Metrics include queries by detail/source mode, window sizes, clamp rate, T20 fallback rate/failure, bytes, pagination, cache hit, access denials, and latency.

## 20. Proposed Python Code Structure

```text
V2/harness/evidence/
  packet_context.py
  context_anchor.py
  context_window.py
  context_filter.py
  context_merge.py
  pagination.py
V2/harness/storage/
  frame_index.py
  context_store.py
```

## 21. Implementation Sequence

1. Define anchor/window/filter/packet/result schemas.
2. Implement frame/time resolution and retained summary mode.
3. Add full-protocol T18 integration and correlation labels.
4. Add safe T20 fallback.
5. Add artifacts/cache/pagination/capability enforcement.
6. Add raw mode/security/performance tests.

## 22. Tests

### 22.1 Unit tests

- All anchor types and ambiguity.
- Frame/time windows and boundary clamps.
- Filter AST validation.
- Correlation labels.
- Pagination across same-frame records.
- Cache/capability key.

### 22.2 Integration tests

- Context around HTTP/PFCP/NAS/NGAP failure.
- Unassigned and other-attempt neighboring packets.
- Retained full detail available.
- Missing detail invokes T20.
- T20 partial failure returns retained portion.
- Dependency-scoped NRF/UDR context.
- Large context paginated.

### 22.3 Negative tests

- Arbitrary display filter rejected.
- Primary caller cannot retrieve hidden dependency semantics.
- Raw packet mode denied to model caller.
- Cursor cannot broaden detail/window/capability.

## 23. Acceptance Criteria

T19 is complete when:

1. Context is bounded, reproducible, and frame/time ordered.
2. Unrelated packets remain labelled rather than implicitly correlated.
3. Retained evidence is preferred over re-decode.
4. T20 fallback uses only validated bounded queries.
5. Partition/detail capabilities prevent hidden-data leakage.
6. Every derived context artifact records complete provenance/checksums.
7. Large results paginate without changing requested scope.
