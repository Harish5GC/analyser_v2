# T20 `targeted_redecode` Implementation Specification

## 1. Purpose

`targeted_redecode` runs tshark against a narrowly bounded region of the retained source PCAP when T01 artifacts do not contain a required protocol tree, field, decode-as interpretation, or raw packet detail.

It creates immutable derived evidence with complete command/query provenance.

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
    timeout_seconds: int


class TargetedRedecodeResult(BaseModel):
    schema_version: Literal["2.0"]
    query_id: UUID
    status: Literal["success", "empty", "failed"]
    artifact: ArtifactDescriptor | None
    manifest: ArtifactDescriptor | None
    tshark_version: str
    arguments_redacted: list[str]
    record_count: int
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

Use `subprocess.Popen`/`exec.CommandContext` with argument list, never shell. Example internal construction:

```text
tshark -r <retained-pcap>
       -Y <compiled-safe-filter-and-selection>
       -T json
       -J <validated-tree-list>
       --no-duplicate-keys
       <validated-decode-as-args>
```

Selection is compiled into frame/time predicates and combined with display filter. Output path is controlled by T20, not caller.

## 10. Source PCAP Validation

Before execution:

- Resolve retained PCAP from run manifest, never request path.
- Validate path inside run directory.
- Verify size/checksum against T01/run manifest.
- Reject symlink escape or changed source.
- Verify tshark executable/version policy.

## 11. Process Management

- Start in its own process group/session.
- Apply timeout/cancellation and terminate child tree.
- Bound stderr capture and redact paths/sensitive filter values.
- Stream stdout to staging; do not buffer entire output.
- Enforce output byte/record limit while reading.
- On limit/time failure, terminate and discard staging unless explicit future partial policy exists.

## 12. Output Validation

- Validate JSON array/JSONL shape according to mode.
- Count records and verify every returned frame falls in requested selection.
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

Write under staging, publish output/query, then manifest last. Original decoded artifacts remain untouched.

## 14. Provenance Manifest

Records:

- Query/tool schema/version and caller capability/scope hash.
- Source PCAP relative path/checksum/size.
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

Query ID/cache key includes source checksum, tshark version, selection/filter/trees/fields/decode-as/output mode, capability scope, and tool version.

Identical successful query can reuse immutable artifact after checksum validation. Failed queries are not cached as successful; short-lived failure throttling may apply.

## 17. Capability and Partition Enforcement

- Primary capability may query only approved primary/context protocols/frames.
- Dependency capability is limited to its approved attempt/window/target scope.
- T20 filter/tree output may include neighboring protocol fields; post-validation/redaction must enforce capability before returning/registering caller-visible refs.
- Admin local broad queries require explicit audit and still obey hard resource limits.

## 18. Failure Semantics

- Invalid selection/filter/tree/field/decode-as: reject before starting process.
- Source missing/checksum mismatch: evidence-integrity failure.
- tshark unavailable/version unsupported: failure.
- No packets: successful empty artifact/manifest.
- Nonzero exit, timeout, cancellation, output limit, malformed JSON: failure; discard staging.
- Missing requested field/tree with successful tshark: success/empty or warning according to request intent.
- Publication/index registration failure: failure and rollback derived registration.

## 19. Performance, Resource, and Concurrency Requirements

- Default maximum one T20 process per analysis and configurable global limit.
- CPU/time/output/range limits.
- Queue requests rather than overloading local machine/model pipeline.
- Record queue time and execution time separately.
- Avoid broad `tcp.port==0-65535,http2` except explicit bounded policy.

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

Metrics include requests by caller/mode, cache hit, queue/execution latency, timeout/failure/empty, range/output size, denied queries, and tshark version.

## 22. Proposed Python Code Structure

```text
V2/harness/evidence/
  targeted_redecode.py
  redecode_models.py
  filter_ast.py
  filter_compiler.py
  field_registry.py
  decode_as.py
  tshark_process.py
  redecode_manifest.py
  derived_registration.py
V2/harness/storage/
  redecode_store.py
```

## 23. Implementation Sequence

1. Define selection/filter/field/decode-as/result/manifest schemas.
2. Implement safe validation/compiler and source integrity checks.
3. Implement context-aware tshark process streaming/limits.
4. Add output validation/atomic artifacts/provenance.
5. Add evidence registration/cache/capability enforcement.
6. Add queue/concurrency/observability/security tests.

## 24. Tests

### 24.1 Unit tests

- Selection exclusivity/range clamps.
- Filter AST compilation/escaping/operator/type validation.
- Tree/field/decode-as allowlists.
- Query ID/cache key.
- Argument construction without shell.
- Output frame-bound validation.
- Manifest/provenance/source refs.

### 24.2 Process tests

- Successful frame/time/explicit-frame queries.
- Empty result.
- Decode-as success/failure.
- Timeout/cancellation/process-tree termination.
- Nonzero exit/malformed/oversized output.
- Bounded/redacted stderr.
- Unsupported tshark version/field.

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

## 25. Acceptance Criteria

T20 is complete when:

1. Every tshark invocation is bounded and generated from typed allowlisted input.
2. Shell/path/argument injection is impossible through the public contract.
3. Source PCAP integrity is verified before execution.
4. Timeout/cancellation/output limits terminate the full process tree and discard partial staging.
5. Derived artifacts are immutable, checksummed, and fully provenance-linked.
6. Original T01 artifacts are never changed.
7. Capability/window scope prevents hidden-data or capture-wide escalation.
8. T18/T19 can resolve/reuse successful derived evidence.
