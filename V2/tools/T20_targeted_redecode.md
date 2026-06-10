# T20 `targeted_redecode` Implementation Specification

## 1. Purpose

`targeted_redecode` extracts a protocol-correct, resource-bounded slice from
the retained source PCAP and runs tshark against that slice when T01 artifacts
do not contain a required protocol tree, field, decode-as interpretation, or
raw packet detail.

It creates immutable derived evidence with complete command/query provenance.
It distinguishes bounded result size, bounded decoder work and source-access
cost; it never describes an `editcap` scan as source-size-independent random
access.

## 2. Non-Goals

T20 must not:

- Re-decode the full capture by default.
- Accept arbitrary shell commands or raw tshark argument arrays.
- Replace/modify T01 artifacts.
- Diagnose or normalize results automatically.
- Bypass NRF/UDR capability scope.
- Send output directly to a model.

## 3. Invocation Boundary

T20 is called by trusted harness components such as T19/T18/dependency inspectors after a validated need is established. Model output cannot call T20 directly.

The request includes caller capability and the orchestrator validates concurrency/resource policy.

## 4. Python Tool Contract

```python
class TargetedRedecodeRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    caller_capability: EvidenceCapability
    selection: RedecodeSelection
    display_filter: SafeDisplayFilter | None
    protocol_trees: list[AllowedProtocolTree] = Field(default_factory=list)
    fields: list[AllowedField] = Field(default_factory=list)
    decode_as: list[ValidatedDecodeAs] = Field(default_factory=list)
    output_mode: Literal["json_tree", "fields", "raw_packet_json"] = "json_tree"
    source_access_requirement: Literal["allow_scan", "require_indexed"] = "allow_scan"
    timeout_seconds: int


class TargetedRedecodeResult(BaseModel):
    schema_version: Literal["2.0"]
    query_id: UUID
    status: Literal["success", "empty", "failed"]
    artifact: ArtifactDescriptor | None
    manifest: ArtifactDescriptor | None
    tshark_version: str
    arguments_redacted: list[str]
    access_plan: RedecodeAccessPlan
    record_count: int
    output_bytes: int
    elapsed_ms: int
    warnings: list[str]
```

## 5. Selection Model

Exactly one bounded selection mode:

```python
class RedecodeSelection(BaseModel):
    frame_start: int | None = None
    frame_end: int | None = None
    time_start: Decimal | None = None
    time_end: Decimal | None = None
    explicit_frames: list[int] = Field(default_factory=list)
```

Limits:

- Positive/in-capture values.
- Maximum frame span, time span, explicit frame count, estimated packet/byte count.
- Dependency capability additionally clamps to approved request window.

The selection describes target packets, not the complete decode slice. The
context planner may expand it only as required for correct protocol
dissection. Returned evidence is filtered back to target packets while context
packets remain represented in provenance.

### 5.1 Three independent bounds

```python
class RedecodeBounds(BaseModel):
    max_result_records: int
    max_result_bytes: int
    max_slice_packets: int
    max_slice_bytes: int
    max_decoder_seconds: int
    max_source_scan_bytes: int

class RedecodeAccessPlan(BaseModel):
    mode: Literal["indexed_extract", "scan_preslice", "full_scan_fallback"]
    target_selection: RedecodeSelection
    context_frame_ranges: list[FrameWindow]
    context_reason_codes: list[str]
    source_index_revision: str | None
    context_planner_version: str
    source_bytes_scanned: int | None
    source_packets_scanned: int | None
    source_scan_accounting: Literal["measured", "conservative_upper_bound", "unknown"]
    slice_packets: int
    slice_bytes: int
    source_frame_map_checksum: str
```

The bounds have different meanings:

- **Result bounds** limit records/bytes published and returned to the caller.
- **Decoder bounds** limit packets/bytes in the extracted slice plus tshark
  CPU/wall time and memory. A small result does not imply small decoder work.
- **Source-scan bounds** limit work required to locate/copy source packets.
  `scan_preslice` with `editcap` is O(source position) for frame/time lookup;
  it reduces tshark dissection but not the scan needed to create the slice.

`require_indexed` fails before execution when a validated T01 packet-access
index is unavailable or cannot service the source format. `allow_scan` may use
`scan_preslice` when policy permits its worst-case scan cost. A
`full_scan_fallback` is explicit, separately authorized, records unbounded
source-dissection cost relative to the target, and is disabled by default.
When a scan backend cannot report exact bytes read, admission uses the retained
source size as a conservative upper bound against `max_source_scan_bytes`.
Post-run accounting records `conservative_upper_bound` or `unknown`, never a
fabricated zero.

### 5.2 Protocol context expansion

The planner expands the target selection before extraction:

- TCP/HTTP2 includes the TCP segments needed for reassembly and begins at a
  validated HPACK state checkpoint or the connection's first required header
  state. If neither fits the slice bounds, the request fails; T20 must not
  return a plausibly parsed but state-corrupt HTTP/2 result.
- SCTP/NGAP includes every DATA chunk needed to reassemble selected messages,
  relevant stream/association context and preceding fragments. Fragmented
  messages are indivisible extraction units.
- IPv4/IPv6 fragmented datagrams include all fragments required for
  reassembly, regardless of the selected upper-layer protocol.
- Decode-as state, interface metadata and pcapng section/interface blocks
  required to interpret selected packets are included in the slice.
- PFCP/UDP packets need no earlier transaction packets for dissection, but IP
  fragments and requested request/response context are still included.

Context expansion is deterministic and reason-coded. It may cross the target
frame/time boundary but never the caller capability boundary. If required
context is outside capability scope, absent from the capture, or exceeds a
hard bound, T20 returns a registered failure/inconclusive issue rather than
silently decoding without context.

## 6. Safe Filter Representation

```python
class SafeDisplayFilter(BaseModel):
    expression: FilterExpression

class FilterExpression(BaseModel):
    op: Literal["and", "or", "not", "eq", "ne", "exists", "in"]
    field: AllowedFilterField | None
    value: JsonScalar | list[JsonScalar] | None
    children: list["FilterExpression"] = Field(default_factory=list)
```

The harness compiles this AST to tshark display-filter text. User/model-provided raw strings are not accepted. Fields/operators/value types are allowlisted and escaped by compiler.

## 7. Protocol Trees and Fields

Allowed protocol tree enum includes configured values such as frame, eth, ip, ipv6, tcp, udp, sctp, http2, json, ngap, nas-5gs, pfcp. Exact tshark names are version-mapped.

Field mode uses allowlisted explicit fields. Unknown fields are rejected before execution after checking tshark field registry/version cache.

## 8. Decode-As Rules

```python
class ValidatedDecodeAs(BaseModel):
    selector: Literal["tcp.port", "udp.port", "sctp.port"]
    value: int
    protocol: AllowedDecodeAsProtocol
```

Values must be valid ports and protocol combinations. No arbitrary `-d` text. HTTP2 broad all-port decode is allowed only under explicit configured policy and bounded selection.

## 9. Command Construction

Use `subprocess.Popen`/`exec.CommandContext` with argument lists, never a
shell. Execution has two stages.

### 9.1 Slice extraction

Preferred indexed extraction reads packet blocks through T01's validated
packet-access index and writes a minimal valid pcap/pcapng containing required
section/interface metadata and the ordered context packet set.

Without an index, use `editcap` as a scan-and-copy backend:

```text
editcap -r <retained-pcap> <staging-slice> <context-frame-ranges>
editcap -A <start-time> -B <end-time> <retained-pcap> <staging-slice>
```

The wrapper validates the installed editcap version and builds arguments from
typed ranges. It records that this mode scans from the source start/position
and must not claim random-access complexity. Time selection requires resolving
the source-frame mapping by the packet index or a bounded metadata scan.

The extractor writes a protected staging `source_frame_map.jsonl` mapping each
slice-local frame to source frame, timestamp, interface and packet/block
identity. This map is checksummed and is the only authority for restoring
source references after slice-local frame numbers are reassigned.

### 9.2 Tshark dissection

Tshark reads only the completed slice:

```text
tshark -r <staging-slice>
       -Y <compiled-safe-display-filter>
       -T json
       -J <validated-tree-list>
       --no-duplicate-keys
       <validated-decode-as-args>
```

The target selection is applied using the protected source-frame map, not by
assuming slice-local `frame.number` equals the source frame. The display filter
contains only the independently requested safe predicates. Output paths are
controlled by T20, not the caller.

## 10. Source PCAP Validation

Before execution:

- Resolve retained PCAP from run manifest, never request path.
- Validate path inside run directory.
- Verify size/checksum against T01/run manifest.
- Resolve and validate the optional packet-access index descriptor/checksum
  before selecting indexed mode.
- Reject symlink escape or changed source.
- Verify tshark and selected extractor executable/version policy.

## 11. Process Management

- Start in its own process group/session.
- Apply timeout/cancellation and terminate child tree.
- Bound stderr capture and redact paths/sensitive filter values.
- Stream stdout to staging; do not buffer entire output.
- Enforce output byte/record limit while reading.
- Create slice/map/output under a query-owned staging directory with restrictive
  permissions and no caller-selected names.
- On extraction, limit, timeout or publication failure, terminate children,
  close files and remove slice/map/output staging. Cleanup failure is recorded
  and retried by run cleanup; staging is never treated as retained evidence.

## 12. Output Validation

- Validate JSON array/JSONL shape according to mode.
- Restore source frame references through the source-frame map and verify every
  returned target record falls in the requested selection.
- Reject missing, duplicate, reordered or checksum-invalid map entries.
- Confirm requested tree/field presence statistics.
- Record parse warnings.
- Empty valid output becomes `status=empty`, not failure.

## 13. Artifact Layout

```text
evidence/redecode/<query-id>/
  query.json
  output.jsonl
  stderr.txt                 optional bounded/redacted
  redecode_manifest.json
```

The temporary slice and source-frame map are not retained evidence. Their
checksums, dimensions and mapping checksum are persisted in the manifest.
Write under staging, publish output/query, then manifest last. Original
decoded artifacts remain untouched.

## 14. Provenance Manifest

Records:

- Query/tool schema/version and caller capability/scope hash.
- Source PCAP relative path/checksum/size.
- Source packet-access index path/revision/checksum when used.
- Access mode and honest source packets/bytes scanned, or `unknown` when the
  backend cannot measure them; unknown must not be reported as zero.
- Target selection, expanded context ranges, expansion reason codes and denied
  context.
- Extractor identity/version/arguments/exit status.
- Staging slice checksum/size/packet count/format and source-frame-map
  checksum/entry count, even though both are removed after publication.
- tshark path identity/version.
- Structured request and compiled redacted arguments.
- Exact unredacted arguments in protected local audit artifact if policy permits.
- Start/end/elapsed/exit code/termination reason.
- Output checksum/size/record count/schema.
- Requested/observed field/tree statistics.
- Warnings/errors.

## 15. Derived Evidence Registration

On success/empty:

- Register artifact in evidence repository.
- Create `SourceRef` values for output records.
- Link parent source checksum and query ID.
- Update derived evidence index atomically.

T02 is not rerun globally. Callers may normalize selected derived records through a bounded adapter if needed, preserving derived provenance.

## 16. Idempotency and Cache

Query ID/cache key includes source checksum, source index revision or explicit
scan mode, extractor/tshark versions, context-planner version and expanded
context ranges, all three bound sets, selection/filter/trees/fields/decode-as,
output mode, capability scope, and tool version.

Identical successful query can reuse immutable artifact after checksum validation. Failed queries are not cached as successful; short-lived failure throttling may apply.

## 17. Capability and Partition Enforcement

- Primary capability may query only approved primary/context protocols/frames.
- Dependency capability is limited to its approved attempt/window/target scope.
- T20 filter/tree output may include neighboring protocol fields; post-validation/redaction must enforce capability before returning/registering caller-visible refs.
- Admin local broad queries require explicit audit and still obey hard resource limits.

## 18. Failure Semantics

- Invalid selection/filter/tree/field/decode-as: reject before starting process.
- Source missing/checksum mismatch: evidence-integrity failure.
- Required index absent/invalid under `require_indexed`: fail without scanning.
- Required HTTP2/SCTP/fragment context absent, unauthorized or over limit:
  fail/inconclusive with a reason code; do not perform context-deficient decode.
- Extractor/tshark unavailable or version unsupported: failure.
- No packets: successful empty artifact/manifest.
- Nonzero exit, timeout, cancellation, output limit, malformed JSON: failure; discard staging.
- Missing requested field/tree with successful tshark: success/empty or warning according to request intent.
- Publication/index registration failure: failure and rollback derived registration.

## 19. Performance, Resource, and Concurrency Requirements

- Default maximum one T20 process per analysis and configurable global limit.
- Enforce and report result, decoder and source-scan limits independently.
- `indexed_extract` target is O(index lookup + selected/context bytes).
- `scan_preslice` is O(source position/size scanned) plus O(slice dissection);
  it is not source-size independent even when the selected window is tiny.
- `full_scan_fallback` is O(source size dissection) and has no bounded-read
  performance claim.
- Queue requests rather than overloading local machine/model pipeline.
- Record queue time and execution time separately.
- Avoid broad `tcp.port==0-65535,http2` except explicit bounded policy.
- Benchmark early, middle and late windows separately and label access mode,
  source size, scan bytes, slice bytes and decoder time.

## 20. Security Requirements

- No shell invocation or arbitrary args.
- Allowlisted AST/fields/trees/decode-as only.
- Path-safe source/output.
- Process environment minimized; no API keys passed.
- File permissions inherit trusted evidence policy.
- Treat tshark output/stderr as untrusted and bound lengths/nesting.
- Audit every invocation and denial.

## 21. Observability

Logs include query/caller/selection size/protocol trees/field count/tshark version/queue/execution/status/record/byte counts/error code. No sensitive filter values or output content.

Metrics include requests by caller/mode, cache hit, queue/extraction/dissection
latency, timeout/failure/empty, source scan/slice/result sizes, context
expansion, denied queries, cleanup failures, extractor version and tshark
version.

## 22. Proposed Python Code Structure

```text
V2/harness/evidence/
  targeted_redecode.py
  redecode_models.py
  filter_ast.py
  filter_compiler.py
  field_registry.py
  decode_as.py
  context_planner.py
  packet_index_reader.py
  slice_extractor.py
  source_frame_map.py
  tshark_process.py
  redecode_manifest.py
  derived_registration.py
V2/harness/storage/
  redecode_store.py
```

## 23. Implementation Sequence

1. Define selection/filter/field/decode-as/result/manifest schemas.
2. Implement safe validation/compiler, source/index integrity checks and the
   three-bound accounting model.
3. Implement protocol context planning and indexed/editcap extraction with a
   source-frame map.
4. Implement slice-only tshark process streaming and independent limits.
5. Add output validation/atomic artifacts/provenance/staging cleanup.
6. Add evidence registration/cache/capability enforcement.
7. Add queue/concurrency/observability/security tests.

## 24. Tests

### 24.1 Unit tests

- Selection exclusivity/range clamps.
- Independent result/decoder/source-scan limit precedence.
- Deterministic TCP/HTTP2, SCTP/NGAP and IP-fragment context expansion.
- Context unavailable/over-limit/capability-denied behavior.
- Slice-local to source-frame mapping and tamper rejection.
- Filter AST compilation/escaping/operator/type validation.
- Tree/field/decode-as allowlists.
- Query ID/cache key.
- Argument construction without shell.
- Output frame-bound validation.
- Manifest/provenance/source refs.

### 24.2 Process tests

- Successful frame/time/explicit-frame queries.
- Indexed extraction and scan-preslice paths produce equivalent source refs.
- Scan-preslice reports nonzero/unknown scan work, never random-access cost.
- Empty result.
- Decode-as success/failure.
- Timeout/cancellation/process-tree termination.
- Nonzero exit/malformed/oversized output.
- Bounded/redacted stderr.
- Unsupported tshark version/field.
- Extractor failure and staging cleanup on every pre-publication failure.

### 24.3 Security tests

- Shell metacharacter/filter injection.
- Arbitrary field/tree/option/path.
- Symlink/path traversal/source tampering.
- Capability/window/partition escape.
- Concurrent request limit.

### 24.4 Integration tests

- T19 fallback recovers missing protocol tree.
- T18 resolves derived evidence.
- T24/T25 scoped re-decode.
- Identical query cache reuse.
- Source checksum change invalidates cache.
- HTTP/2 dynamic-table/reassembly case requiring packets before the target.
- SCTP fragmented NGAP and fragmented IP datagram recovery.
- Early and late equal-size windows in a large capture, recording scan and
  dissection costs separately; source-size-independent latency is required
  only for validated `indexed_extract` mode.

## 25. Acceptance Criteria

T20 is complete when:

1. Every tshark invocation reads a completed bounded slice or an explicitly
   authorized/recorded full-scan fallback and uses typed allowlisted input.
2. Shell/path/argument injection is impossible through the public contract.
3. Source PCAP integrity is verified before execution.
4. Timeout/cancellation/output limits terminate the full process tree and discard partial staging.
5. Derived artifacts are immutable, checksummed, and fully provenance-linked.
6. Original T01 artifacts are never changed.
7. Capability/window scope prevents hidden-data or capture-wide escalation.
8. T18/T19 can resolve/reuse successful derived evidence.
9. Result, decoder and source-scan bounds are separately enforced and reported.
10. HTTP2/TCP, SCTP/NGAP and IP-fragment context is preserved or the request
    fails explicitly; context-deficient output is never published as valid.
11. Every output source reference maps through a checksummed slice-to-source
    frame map.
12. Slice/map staging is removed after success/failure while complete source,
    slice, index, command and output provenance remains in the manifest.
