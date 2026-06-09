# T18 `lookup_full_evidence` Implementation Specification

## 1. Purpose

`lookup_full_evidence` resolves compact event, evidence, candidate, attempt, frame, stream, NGAP, or PFCP selectors to complete immutable T01/T20 protocol records.

It is the standard forensic lookup path when normalized summaries omit a field or a report/model conclusion requires complete source detail.

## 2. Non-Goals

T18 must not:

- Modify source/full artifacts.
- Run tshark; T20 performs re-decode.
- Return the entire capture without bounded selectors/pagination.
- Send full output directly to a model.
- Bypass NRF/UDR access boundaries for primary callers.
- Interpret or diagnose retrieved records.

## 3. Caller Capabilities

Caller role controls accessible partitions/detail:

- `primary_internal`: primary records referenced by primary events/candidates.
- `dependency_nrf`: only records selected by approved T24 request.
- `dependency_udr`: only records selected by approved T25 request.
- `report_evidence`: records already cited by report result.
- `admin_local`: explicitly authorized local forensic lookup.

Provider/model callers never receive raw T18 output; T15 builds masked bounded evidence.

## 4. Python Tool Contract

```python
class LookupFullEvidenceRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    caller_capability: EvidenceCapability
    selectors: EvidenceSelectors
    detail: Literal["metadata", "semantic_full", "raw_full"] = "semantic_full"
    field_paths: list[str] = Field(default_factory=list)
    page_size_bytes: int = 1_000_000
    max_records: int = 100
    cursor: str | None = None


class LookupFullEvidenceResult(BaseModel):
    schema_version: Literal["2.0"]
    query_id: UUID
    records: list[FullEvidenceRecord]
    total_matches: int
    returned_records: int
    returned_bytes: int
    truncated: bool
    next_cursor: str | None
    warnings: list[str]
```

## 5. Selector Model

```python
class EvidenceSelectors(BaseModel):
    event_ids: list[UUID] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(default_factory=list)
    attempt_ids: list[UUID] = Field(default_factory=list)
    candidate_ids: list[UUID] = Field(default_factory=list)
    record_ids: list[UUID] = Field(default_factory=list)
    frame: int | None = None
    frame_start: int | None = None
    frame_end: int | None = None
    timestamp: Decimal | None = None
    seconds_before: Decimal | None = None
    seconds_after: Decimal | None = None
    tcp_stream: int | None = None
    http2_stream_id: int | None = None
    amf_ue_ngap_id: str | None = None
    ran_ue_ngap_id: str | None = None
    pfcp_sequence: int | None = None
    seid: str | None = None
    protocol: str | None = None
```

At least one selector is required. Broad range selectors are clamped/rejected by capability/policy.

## 6. Full Evidence Record

```python
class FullEvidenceRecord(BaseModel):
    record_id: UUID
    protocol: str
    partition: str
    frame_start: int
    frame_end: int
    timestamp_start: Decimal | None
    timestamp_end: Decimal | None
    metadata: dict[str, JsonValue]
    content: JsonValue | None
    raw_content: JsonValue | None
    source: ArtifactLocation
    checksum_verified: bool
    field_path_results: list[FieldPathResult]
    warnings: list[str]
```

HTTP content preserves ordered duplicate headers and body segments; NGAP/NAS preserves complete trees/repeated IEs; PFCP preserves complete IE trees and heartbeat records.

## 7. Logical ID Resolution

Resolution chain examples:

- Event ID -> T02 event -> `SourceRef` -> T01 document/JSONL record.
- Evidence ID -> evidence index -> source event/record refs.
- Candidate ID -> T06-T12 candidate -> evidence IDs -> records.
- Attempt ID -> T04 event assignments -> records, subject to bounds/capability.
- Frame -> frame index -> all records/events on frame.

Every step validates analysis ID and revision/checksum.

## 8. Protocol-Specific Lookup

### HTTP/2

Use stream index/document UUID. TCP + HTTP2 stream selector must map to one or explicit multiple documents when capture restart/ambiguity exists. Return full request/response headers/body/completion metadata.

### NGAP/NAS

Use message index by record/frame/UE IDs. Embedded NAS field-path results preserve parent NGAP record reference.

### PFCP

Use message index by record/frame/sequence/SEID with endpoint scope. Sequence or SEID alone may match multiple records and requires pagination/context.

## 9. Field Path Filtering

Field paths use a safe allowlisted JSON pointer-like syntax:

- No arbitrary code/expressions.
- Bounded depth and result count.
- Repeated values returned as ordered lists.
- Missing path returns explicit not-found result.

Filtering changes response content only; source record remains complete/immutable.

## 10. Integrity Verification

Before returning content:

- Verify artifact descriptor/path remains within run directory.
- Verify artifact or collection-index checksum according to policy/cache.
- Verify HTTP document checksum/size from stream index.
- Verify record ID/frame matches index.
- Verify derived T20 artifact provenance/source checksum.

Checksum verification may be cached by inode/size/mtime plus manifest revision, but mismatch invalidates cache and fails the record.

## 11. Partition Access Enforcement

- Primary capability cannot resolve `nrf`/`udr` partition event/record IDs even if supplied directly.
- NRF/UDR capability includes approved request ID, attempt ID, selector/window scope, and expiry.
- T18 validates every resolved record against that scope.
- Admin local bypass requires explicit policy/audit and is never available to model execution.

This enforcement occurs after each selector expansion, not only at request parsing.

## 12. Pagination

Pagination is byte and record bounded. Cursor contains:

- Analysis/query/capability hash.
- Selector and field-path hash.
- Artifact/record/byte position.
- Source revision/checksum.
- Expiry/version.

Cursor is authenticated. It cannot be reused with broader detail or another capability.

For one very large record, pagination can return metadata plus content chunks/field subsets while preserving ability to retrieve the complete record locally.

## 13. Size and Materialization Limits

- `metadata`: no bodies/trees.
- `semantic_full`: complete parsed protocol object subject to paginated serialization.
- `raw_full`: raw tshark/document representation, local-only by default.

Bound JSON nesting, string/body chunk, total page bytes, and record count. Limits never alter source artifacts.

## 14. Query ID and Audit

Query ID UUIDv5/random policy includes analysis, capability, selector hash, detail, and revision. Persist audit metadata, not necessarily returned content:

```text
evidence/lookup/lookup_audit.jsonl
```

Audit records caller/tool, query scope, records/bytes returned, access denials, checksum status, timing, and warnings without sensitive values.

## 15. Failure Semantics

- No selector/invalid combination: validation error.
- Selector finds no record: successful empty result.
- Selector ambiguous: return bounded matches or require narrower selector according to policy.
- Capability/partition/window violation: access denied and audited.
- Artifact missing/checksum mismatch/index inconsistency: evidence-integrity error; do not return unverified content as exact evidence.
- Invalid/stale cursor: validation error.
- One corrupt record in multi-record result: omit/fail record, mark partial; major evidence callers may treat as fatal.

## 16. Performance and Resource Requirements

- Index-based lookup; no directory/full-file scan for normal queries.
- HTTP direct document reads.
- JSONL byte-offset indexes where available; otherwise bounded line lookup.
- Stream serialization/pagination for large records.
- Cache verified artifact metadata and parsed small indexes.
- Record lookup latency, bytes read/returned, records, cache hits, checksum time, and access denials.

## 17. Security and Privacy

- Strict path traversal/symlink escape prevention.
- Caller capability and partition scope required.
- Full/raw data local-only unless transformed by T15.
- Audit access to sensitive/full evidence.
- Treat JSON trees/strings as untrusted and enforce parser limits.
- No absolute paths in returned portable result; use relative artifact IDs.

## 18. Observability

Logs include query/caller capability, selector types, partition/protocol, records/bytes, detail mode, cursor, checksum/access result, and duration. No content values.

Metrics include queries by caller/protocol/detail, empty/ambiguous, bytes, pagination, integrity failures, access denials, cache hits, and latency.

## 19. Proposed Python Code Structure

```text
V2/harness/evidence/
  lookup.py
  selectors.py
  field_paths.py
  pagination.py
  capability.py
  audit.py
V2/harness/storage/
  evidence_repository.py
  artifact_index.py
  frame_index.py
  stream_index.py
  jsonl_offset_index.py
V2/harness/models/
  evidence.py
```

## 20. Implementation Sequence

1. Define selector/result/capability/cursor schemas.
2. Implement event/evidence/candidate/record resolution.
3. Implement protocol-specific readers and integrity checks.
4. Add field-path filtering and large-record pagination.
5. Add partition/window capability enforcement.
6. Add audit/cache/performance/security tests.

## 21. Tests

### 21.1 Unit tests

- Every selector type and combination validation.
- Logical ID resolution chain.
- HTTP duplicate headers/body segments.
- NGAP repeated IEs/embedded NAS paths.
- PFCP sequence/SEID ambiguity.
- Field paths/repeated/missing/depth limits.
- Cursor authentication/revision/detail/capability mismatch.
- Checksum cache invalidation.

### 21.2 Integration tests

- Resolve every major report evidence ID.
- Large HTTP body/tree pagination.
- T20-derived artifact lookup.
- Missing/corrupt/tampered artifact.
- Primary access denied to NRF/UDR.
- Approved T24/T25 capability returns only scoped records.
- Admin local audit.

### 21.3 Negative tests

- Path traversal/symlink escape.
- Direct record ID cannot bypass partition scope.
- Cursor cannot broaden query/detail.
- Full output cannot be sent directly to provider caller.

## 22. Acceptance Criteria

T18 is complete when:

1. Every valid event/evidence/candidate/report reference resolves to immutable source detail.
2. Duplicate/repeated protocol values remain lossless and ordered.
3. Integrity is verified before evidence is treated as exact.
4. Large records are fully retrievable through bounded pagination.
5. Primary callers cannot access hidden NRF/UDR records.
6. Approved dependency callers remain within validated attempt/window/selectors.
7. Lookup is index-based, audited, and path-safe.
8. T18 never modifies source or invokes tshark/model services.
