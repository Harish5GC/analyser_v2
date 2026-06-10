# T01 `decode_capture` Implementation Specification

## 1. Purpose

`decode_capture` is the first harness tool. It validates and retains a PCAP,
runs the existing Go/tshark decoders, writes complete protocol artifacts under
the canonical `decoder/` run tree, and returns a validated decoder manifest to
Python.

The tool performs decoding only. It must not:

- Diagnose a call failure.
- Filter or classify NRF and UDR traffic.
- Build UE attempts or correlate subscribers.
- Produce model evidence.
- Invoke a model provider.

NRF/UDR partitioning occurs later in `normalize.partition_router` so the decoder output remains complete and protocol-neutral.

## 2. Current Implementation Baseline

The existing Go implementation is the starting point:

- `AnalyseCapture.go` dispatches `http2`, `ngap`, `pfcp`, and `analyze` commands.
- `runAnalyze` runs the three decoders concurrently.
- `http2_decoder.go` reconstructs conversations by `tcp.stream:http2.streamid`, writes temporary NDJSON, and converts it to aggregate full and lean JSON maps.
- `ngap_decoder.go` writes full and lean JSON arrays.
- `pfcp_decoder.go` writes a JSON array.

The current implementation is not yet compliant with this specification because it:

- Uses fixed output filenames in the current working directory.
- Does not produce a machine-readable decoder manifest.
- Does not checksum retained artifacts.
- Stores all HTTP/2 conversations in aggregate JSON maps instead of one document per stream.
- Uses `map[string]string` for HTTP headers, which collapses duplicate headers.
- Stores only request-side frame/time/address metadata for an HTTP conversation.
- Does not explicitly represent reset, truncation, request-only, or response-only completion states.
- Uses destructive lean/sanitize behavior while producing files named as full output.
- Drops PFCP heartbeat messages.
- Does not retain streamed raw tshark packet records.
- Couples the `analyze` command to provider execution.

## 3. Ownership Boundary

### 3.1 Python wrapper owns

- Input validation.
- Creation of the analysis UUID and isolated run directory.
- Copying or filesystem-reflinking the source PCAP into `source/capture.pcap`. Hard links are disabled by default because later modification of the original would violate evidence immutability.
- Starting the Go binary with an argument array, never through a shell.
- Process-group timeout and cancellation.
- Reading and validating `decoder_manifest.json`.
- Verifying artifact existence, size, checksum, schema version, and safe paths.
- Converting Go status into harness `success`, `partial`, or `failed`.

### 3.2 Go decoder owns

- Verifying that tshark is executable and reporting its version.
- Running HTTP/2, NGAP/NAS, and PFCP tshark jobs.
- Streaming tshark output without loading the complete capture output into memory.
- Retaining raw packet-level decoder records.
- Reconstructing complete HTTP/2 stream documents.
- Writing full NGAP/NAS and PFCP message records.
- Writing protocol indexes and the decoder manifest.
- Optionally writing a packet-access index for T20 indexed extraction when
  enabled by run policy.
- Atomic artifact publication and checksums.
- Minting its own decode revision from source checksum, command options,
  decoder/tshark versions and published artifact descriptors.

## 4. Python Tool Contract

```python
class DecodeCaptureRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    retained_pcap_path: Path
    run_dir: Path
    decoder_binary: Path
    timeout_seconds: int = 600
    protocols: set[Literal["http2", "ngap", "pfcp"]] = Field(
        default_factory=lambda: {"http2", "ngap", "pfcp"}
    )
    retain_raw_packets: bool = True
    build_packet_access_index: bool = False
    enabled_capabilities: set[CapabilityName] = Field(default_factory=set)
    policy_versions: dict[str, str] = Field(default_factory=dict)


class DecodeCaptureResult(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    status: Literal["success", "partial", "failed"]
    revision: str
    source: ArtifactDescriptor
    manifest: ArtifactDescriptor
    protocols: dict[str, ProtocolDecodeResult]
    artifacts: list[ArtifactDescriptor]
    collections: list[CollectionDescriptor]
    decoder_version: str
    tshark_version: str
    started_at: datetime
    completed_at: datetime
    elapsed_ms: int
    warnings: list[DecodeWarning]
```

The wrapper returns only after manifest, descriptor and artifact validation. It
must not infer successful decoding merely from process exit code.
`build_packet_access_index=true` is legal only when the resolved run enables
`bounded_targeted_redecode`; otherwise the request is rejected before invoking
Go. Declared `policy_versions` are copied into the decode revision envelope so
later consumers can reject mixed-generation inputs.

`DecodeWarning` is a type alias of the shared `Issue` model with T01-owned
issue codes. T01 protocol statuses remain local to this tool; T17 maps them to
run/report `success`, `partial` or `failed`.

## 5. Go Command Contract

Target command:

```bash
5g_call decode <retained-pcap> \
  --analysis-id <uuid> \
  --output-dir <run-dir>/decoder \
  --protocol all \
  --format v2 \
  --retain-raw=true \
  --packet-access-index=false
```

Supported options:

```text
decode PCAP
  --analysis-id UUID          required
  --output-dir PATH           required; must not already contain published output
  --protocol VALUE            all|http2|ngap|pfcp; repeatable
  --format VALUE              v2 only for this contract
  --retain-raw BOOL           default true
  --packet-access-index BOOL  default false; build T20 frame/time/offset index
  --parallel BOOL             default true
  --tshark PATH               default resolved from PATH
```

The Python wrapper owns the wall-clock timeout. The Go process must handle termination by stopping child tshark processes and leaving no published partial files.

### 5.1 Exit codes

- `0`: requested decoding completed; inspect manifest for `success` or `partial`.
- `2`: invalid command arguments.
- `3`: source PCAP unreadable or unsupported.
- `4`: every requested protocol decoder failed.
- `5`: output or manifest publication failed.
- `6`: tshark unavailable.

An absent protocol is not a decoder failure. It is recorded as `absent` in the manifest.

## 6. Output Layout

```text
run/
  source/
    capture.pcap
    source_manifest.json
  decoder/
    decoder_manifest.json
    raw/
      http2.packets.jsonl
      ngap.packets.jsonl
      pfcp.packets.jsonl
    full/
      http2/
        streams/
          <stream-document-uuid>.json
        stream_index.jsonl
      ngap/
        messages.jsonl
        message_index.jsonl
      pfcp/
        messages.jsonl
        message_index.jsonl
    indexes/
      packet_access_index.bin       optional
      packet_access_index.json      optional descriptor
  staging/
```

Every completed or incomplete HTTP/2 stream is a separate JSON document. The filename is a UUIDv4 generated when the stream state is first created. Transport identity remains inside the document and index; the UUID filename must not replace `tcp.stream` or `http2.streamid` as evidence.

NGAP and PFCP remain JSONL because each line is already an independently addressable message record. They may move to separate UUID documents later without changing the Python repository interface.

## 7. Atomic Write and Descriptor Rules

- Create all outputs under `staging/T01-<uuid>/`.
- Write an individual HTTP document to `<uuid>.json.tmp`, flush, close, and rename to `<uuid>.json`.
- Write indexes, descriptors and manifest to temporary files and publish with `os.Rename` only after successful close.
- Promote completed files or collections from staging into `decoder/` only
  after checksums, byte sizes, record counts and collection member indexes
  validate.
- Publish `decoder/decoder_manifest.json` last.
- A manifest may reference only already-published artifacts.
- The Python wrapper treats a run without a valid manifest as failed.
- On cancellation, remove staging files but never alter an earlier completed run.
- Every `relative_path` is run-root relative, uses the `decoder/` or `source/`
  namespace, and is rejected if absolute, contains `..`, crosses a symlink, or
  resolves outside the run root.
- The final `DecodeCaptureResult.revision` is the T01 `RevisionEnvelope`
  digest over source descriptor, command options, enabled capabilities,
  decoder/tshark identities, policy versions and artifact/collection
  descriptors. Callers never mint this revision on T01's behalf.

## 8. HTTP/2 Stream Identity

The reconstruction key is:

```text
tcp.stream + ":" + http2.streamid
```

The stream document also records endpoint addresses and ports. If tshark stream numbering is missing, the decoder must not invent a high-confidence key. It writes a warning and may use a lower-confidence tuple key containing source, destination, ports, first frame, and HTTP/2 stream ID.

```python
class HTTP2StreamIndexEntry(BaseModel):
    document_id: UUID
    relative_path: str
    tcp_stream: int | None
    http2_stream_id: int | None
    original_key: str | None
    first_frame: int
    last_frame: int
    request_frame: int | None
    response_frame: int | None
    method: str | None
    uri: str | None
    status: int | None
    src_ip: str | None
    dst_ip: str | None
    completion_state: str
    sha256: str
    byte_size: int
```

`stream_index.jsonl` is the lookup mechanism. Consumers must not scan the stream-document directory to find a transaction.

## 9. HTTP/2 Full Document Schema

```json
{
  "schema_version": "2.0",
  "document_id": "uuid",
  "protocol": "HTTP2",
  "transport": {
    "tcp_stream": 12,
    "http2_stream_id": 37,
    "original_key": "12:37",
    "client": {"ip": "10.0.0.1", "port": 38122},
    "server": {"ip": "10.0.0.2", "port": 80}
  },
  "request": {
    "start_frame": 100,
    "end_frame": 102,
    "start_time_epoch": "1770000000.123456789",
    "end_time_epoch": "1770000000.125000000",
    "headers": [
      {"name": ":method", "value": "POST", "frame": 100},
      {"name": "content-type", "value": "application/json", "frame": 100}
    ],
    "method": "POST",
    "uri": "http://nf.example/service/resource",
    "body": {
      "byte_length": 123,
      "sha256": "hex",
      "content_type": "application/json",
      "segments": [
        {"frame": 102, "raw_hex": "..."}
      ],
      "decoded_json": {}
    }
  },
  "response": {
    "start_frame": 110,
    "end_frame": 111,
    "start_time_epoch": "1770000000.223456789",
    "end_time_epoch": "1770000000.225000000",
    "headers": [
      {"name": ":status", "value": "500", "frame": 110}
    ],
    "status": 500,
    "body": {
      "byte_length": 80,
      "sha256": "hex",
      "content_type": "application/problem+json",
      "segments": [
        {"frame": 111, "raw_hex": "..."}
      ],
      "decoded_json": {}
    }
  },
  "completion": {
    "state": "complete",
    "request_end_stream": true,
    "response_end_stream": true,
    "rst_stream": false,
    "capture_truncated": false,
    "warnings": []
  },
  "source_frames": [100, 102, 110, 111]
}
```

### 9.1 Header requirements

- Preserve header order.
- Preserve duplicate header names as separate entries.
- Preserve pseudo-headers.
- Never remove authorization or 3GPP SBI headers from full output.
- Masking occurs only when model evidence is built.

### 9.2 Body requirements

- Preserve all body segments with source frame references.
- Preserve original bytes as hex or another lossless encoding.
- Store decoded JSON as an additional representation, not as a replacement for original bytes.
- Preserve multipart part metadata and every part body.
- Record malformed JSON or multipart parsing as warnings without dropping bytes.
- Avoid duplicating a very large assembled body when segment bytes already provide lossless retention; store checksum and length regardless.

### 9.3 Completion states

- `complete`.
- `request_only`.
- `response_only`.
- `reset`.
- `truncated_capture`.
- `incomplete`.

All live states must be flushed at end-of-capture. Incomplete streams are evidence, not decoder errors.

## 10. NGAP/NAS Full Output

`messages.jsonl` contains one independently valid JSON object per observed NGAP packet.

Required fields:

- Record UUID.
- Frame number and absolute Unix-epoch decimal timestamp with source
  precision metadata.
- Source/destination IP and SCTP metadata.
- Complete tshark NGAP tree.
- Complete embedded NAS tree when tshark exposes it.
- Decode warnings.
- Raw packet record reference.

The full writer must not strip PER blocks or unknown IEs. Key cleanup and semantic extraction belong to normalization. A derived compatibility/lean file may be produced only when explicitly requested and must never replace full output.

## 11. PFCP Full Output

`messages.jsonl` contains one independently valid JSON object per observed PFCP packet.

Required fields:

- Record UUID.
- Frame number and absolute Unix-epoch decimal timestamp with source
  precision metadata.
- Source/destination IP and UDP ports.
- Complete tshark PFCP tree.
- Message type, sequence number, SEID, and response linkage when available.
- Decode warnings.
- Raw packet record reference.

Heartbeat requests and responses must remain in full output. Normalization may mark them as routine and omit them from first-pass model evidence, but T01 must not delete them.

T01 preserves PFCP message type, cause and response-linkage fields as observed
by tshark. It does not emit diagnostic confidence and must not translate
unknown or unsupported PFCP outcomes into `inconclusive`; that mapping belongs
to T08/T12.

## 12. Raw Packet Retention

When `--retain-raw=true`, each protocol decoder writes one raw tshark packet object per JSONL line before semantic reconstruction or sanitation. The raw artifact must preserve the tshark-emitted tree and source frame.

If one packet belongs to more than one requested protocol filter, retaining it in more than one raw protocol file is acceptable. The manifest records resulting sizes and checksums.

## 13. Decoder Manifest

`decoder_manifest.json` is the authoritative Go result.

```json
{
  "schema_version": "2.0",
  "analysis_id": "uuid",
  "status": "success",
  "revision": "sha256:...",
  "enabled_capabilities": ["jsonl_run_store", "canonical_artifact_revisions"],
  "policy_versions": {},
  "decoder": {
    "name": "5g_call",
    "version": "build-version",
    "go_version": "go1.x",
    "tshark_version": "TShark ..."
  },
  "source": {
    "relative_path": "source/capture.pcap",
    "sha256": "hex",
    "byte_size": 123456
  },
  "protocols": {
    "http2": {
      "status": "success",
      "input_packets": 1000,
      "records_written": 250,
      "incomplete_records": 2,
      "elapsed_ms": 1000,
      "warnings": []
    },
    "ngap": {
      "status": "absent",
      "input_packets": 0,
      "records_written": 0,
      "elapsed_ms": 500,
      "warnings": []
    },
    "pfcp": {
      "status": "success",
      "input_packets": 200,
      "records_written": 200,
      "elapsed_ms": 700,
      "warnings": []
    }
  },
  "artifacts": [],
  "collections": [],
  "started_at": "2026-06-10T00:00:00.000000000Z",
  "completed_at": "2026-06-10T00:00:01.200000000Z",
  "elapsed_ms": 1200
}
```

Protocol status values:

- `success`: records were decoded and all required artifacts published.
- `absent`: no matching protocol packets were observed.
- `partial`: some records were written but tshark, parsing, or publication produced recoverable errors.
- `failed`: no usable artifact was produced because the decoder failed.
- `not_requested`.

Every artifact entry includes:

- Relative path under the run directory.
- Artifact type and protocol.
- Format and schema version.
- SHA-256.
- Byte size.
- Record count.
- Creation stage.
- Parent source checksum.
- T01 revision when published.

For collections containing many HTTP stream documents, the manifest describes
the collection and its index rather than duplicating every document entry.
`stream_index.jsonl` must contain each document checksum, byte size, record
count where applicable and media/schema type. The `CollectionDescriptor`
contains member count, checksum over ordered index entries, parent source
checksum and revision. Python validates the index and every referenced
document before the collection is accepted.

Manifest timestamps are generated RFC 3339 UTC values with `Z`. Packet and
protocol record timestamps remain absolute Unix-epoch decimal strings with
source precision preserved. Manifest JSON uses canonical serialization for
revision input: sorted object keys, Decimal-as-string and stable list order.

Absolute host paths must not be written to portable manifests or reports.

### 13.1 Optional packet-access index

When `--packet-access-index=true`, and only when the
`bounded_targeted_redecode` capability is enabled, T01 performs one streaming
pass over the retained, materialized capture and publishes a versioned index
usable by T20. The index is an optimization and evidence-access artifact, not
a replacement for the source PCAP.

Each packet entry records at least source frame number, timestamp, packet/block
offset and length, captured/original length, pcapng section/interface identity
and the metadata-block key required to reconstruct a valid slice. The
descriptor records source checksum/size/format, index schema/version, entry
count, first/last frame/time, index checksum/size, construction timing and
whether source-size-independent extraction is supported. T20 may claim
source-size-independent extraction only when this descriptor says the index is
complete and reconstruction-capable.

For pcapng, extraction must also copy required section header, interface
description and other interpretation-critical blocks. An index that cannot
reconstruct these blocks is not advertised as T20-capable. Compressed input is
first materialized as the immutable retained capture; offsets always address
that retained file and never the caller's compressed source.

Index construction is atomic and manifest-last like every other T01 artifact.
Index failure does not invalidate otherwise usable protocol decode when the
index was optional: mark the index artifact failed/absent and the overall T01
result partial with a registered warning. When run policy requires indexed
T20 access, index failure is a critical T01 failure.

## 14. Failure Semantics

- Unreadable PCAP: fail before starting protocol jobs.
- `decoder/` already contains a published decode generation: reject with exit
  `2` (re-runs create a new run directory or sibling run; published
  generations are immutable per `LLD.md` section 25).
- tshark unavailable: fail the command.
- One protocol absent: continue; mark `absent`.
- One protocol fails while another succeeds: publish valid artifacts and mark overall `partial`.
- All requested protocols fail: overall `failed`, nonzero exit.
- Individual malformed packet: record warning and continue when stream alignment remains valid.
- Output disk full or atomic rename failure: fail publication; never publish a manifest referencing missing data.
- Timeout/cancellation: Python marks the tool failed or partial only if a complete, valid manifest was already published.

## 15. Performance and Resource Requirements

- Stream tshark output; do not load complete packet arrays or aggregate conversation maps into memory.
- Keep only active HTTP/2 stream state in memory.
- Write each HTTP stream document once when complete or once at end-of-capture.
- Do not create a temporary NDJSON file followed by a second aggregate conversion pass.
- Compute artifact checksums while writing where practical.
- Run protocol jobs concurrently by default, with a serial mode for constrained storage.
- Bound stderr capture and warning counts.
- Avoid opening one file per active stream; open the UUID document only when publishing the completed state.
- Packet-access indexing is one O(source size) streaming pass with bounded
  memory. Record its independent elapsed time, bytes read, entries written,
  output bytes and throughput so its cost is not hidden inside protocol decode.

The user-observed current baseline is approximately 3,500 packets/second. On the same host and reference capture, the initial V2 implementation should target the same throughput and must record packets/second, elapsed time, peak RSS, stream count, and artifact count. A regression greater than 20% requires investigation before acceptance.

Separate stream files add filesystem operations. The implementation minimizes this cost by performing one atomic write per completed stream rather than writing every packet directly to its document.

## 16. Security Requirements

- Invoke tshark with `exec.CommandContext` and an argument array.
- Never concatenate a user-provided display filter into a shell command.
- Resolve and validate the output directory before writing.
- Reject output paths that escape the assigned run directory.
- Use file permissions no broader than `0640` by default and directories no broader than `0750`.
- Do not log body contents, authorization headers, API keys, or subscriber identifiers.
- Treat PCAP and decoder output as untrusted input.
- Enforce configurable maximum record/body sizes while preserving an evidence warning and raw reference when a parsed representation cannot be materialized.

## 17. Proposed Go Code Structure

```text
AnalyseCapture.go              legacy command compatibility during migration
decode_command.go              v2 decode CLI parsing and orchestration
decode_config.go               validated command configuration
decoder_manifest.go            manifest models and publication
artifact_writer.go             staging, atomic rename, checksum, counts
packet_access_index.go          optional pcap/pcapng frame/time/block-offset index
tshark_runner.go               context-aware tshark process wrapper
http2_decoder.go               packet parsing and stream-state reconstruction
http2_stream_writer.go         UUID document and stream-index publication
ngap_decoder.go                full NGAP/NAS message streaming
pfcp_decoder.go                full PFCP message streaming
version.go                     build and schema version metadata
```

Suggested internal interfaces:

```go
type ProtocolDecoder interface {
    Name() string
    Decode(ctx context.Context, cfg DecodeConfig, sink ArtifactSink) ProtocolResult
}

type ArtifactSink interface {
    WriteJSONDocument(relativePath string, value any) (Artifact, error)
    OpenJSONL(relativePath string) (JSONLWriter, error)
    PublishIndex(relativePath string, records <-chan any) (Artifact, error)
}

type HTTP2StreamWriter interface {
    Publish(ctx context.Context, stream HTTP2StreamDocument) (HTTP2StreamIndexEntry, error)
}
```

## 18. Proposed Python Code Structure

```text
V2/harness/decoder/
  runner.py                 DecodeCaptureRequest -> DecodeCaptureResult
  command.py                safe Go argument construction
  manifest.py               Pydantic manifest models
  validation.py             path, checksum, count and schema validation
  errors.py                 typed fatal/partial decoder errors
```

Only `runner.py` is exposed to `orchestrator.py`. Downstream normalization receives validated artifact descriptors, not arbitrary paths from subprocess output.

## 19. Required Changes by Existing Go File

### `AnalyseCapture.go`

- Add the `decode` command and structured option parsing.
- Remove model invocation from the decoder path.
- Retain old protocol commands temporarily as compatibility wrappers.
- Replace fixed filenames with paths derived from validated `--output-dir`.
- Write protocol result status instead of exiting on the first protocol failure.

### `http2_decoder.go`

- Replace aggregate map conversion with direct UUID stream-document publication.
- Preserve duplicate and ordered headers.
- Preserve full request and response frame/time/address metadata.
- Preserve raw body segments and decoded representations.
- Track reset and incomplete states.
- Flush remaining states at EOF.
- Write `stream_index.jsonl`.
- Tee raw packet records when configured.

### `ngap_decoder.go`

- Write full message JSONL instead of one aggregate array.
- Preserve the original full tree and embedded NAS without destructive stripping.
- Move lean/PER stripping to later normalization or an explicit compatibility output.
- Write record UUIDs and message index entries.
- Tee raw packet records when configured.

### `pfcp_decoder.go`

- Write full message JSONL instead of one aggregate array.
- Retain heartbeat messages and fields removed by the current sanitizer.
- Move semantic key cleanup to normalization.
- Write record UUIDs and message index entries.
- Tee raw packet records when configured.

## 20. Tests

### 20.1 Unit tests

- Command construction uses an argument array and writes to `decoder/`, never
  legacy fixed filenames or shell-expanded paths.
- Decode request validation rejects `build_packet_access_index=true` without
  the `bounded_targeted_redecode` capability.
- Duplicate HTTP header preservation.
- Request and response body segmentation.
- Multipart body with JSON and binary parts.
- Request-only, response-only, reset, and EOF-incomplete streams.
- UUID filename and original stream-key index mapping.
- IPv4 and IPv6 endpoints.
- NGAP embedded NAS retention.
- PFCP heartbeat retention.
- Atomic writer cleanup after failure.
- Manifest checksum and record-count generation.
- ArtifactDescriptor and CollectionDescriptor validation: relative paths,
  media/schema type, parent source checksum, child member checksums, record
  counts and symlink/traversal rejection.
- Decode revision determinism for identical source checksum, command options,
  capabilities, decoder/tshark versions and artifact descriptors.
- Canonical timestamps: generated manifest times are RFC 3339 UTC; packet
  times are Unix-epoch decimal strings with source precision metadata.
- Classic pcap and multi-interface pcapng packet-access index entries.
- Index descriptor/source checksum and pcapng metadata-block reconstruction.
- PFCP unknown/unsupported message state is preserved as observed data and is
  never converted to diagnostic `inconclusive` by T01.

### 20.2 Integration tests

- All three protocols present.
- Each protocol independently absent.
- One protocol decoder fails while others succeed.
- Truncated capture.
- Large capture with many concurrent HTTP/2 streams.
- Cancellation and timeout.
- Paths containing spaces.
- Corrupt or unreadable PCAP.
- Manifest tampering detected by Python validation.
- T20 indexed extraction of early/middle/late frame and time windows.
- T20 request on a run without a T20-capable packet-access descriptor falls
  back to the documented scan-preslice path or fails closed according to T20
  policy; T01 does not advertise unsupported random access.
- Optional index failure yields partial T01; required index failure is fatal.
- Re-decode into a run with a published T01 revision is rejected without
  mutating the existing `decoder/` tree.
- Performance comparison against the current approximately 3,500 packets/second baseline.

## 21. Acceptance Criteria

T01 is complete when:

1. It runs through one stable Go `decode` command.
2. It writes only inside the assigned run directory using the canonical
   `source/`, `decoder/` and `staging/` tree.
3. Every HTTP/2 stream has a UUID-named full JSON document and index entry.
4. Duplicate headers, original body bytes, frame references, and incomplete streams are retained.
5. Full NGAP/NAS and PFCP records are streamed without lean filtering or heartbeat removal.
6. Raw packet-level artifacts are retained when configured.
7. A manifest reports protocol status, counts, versions, capabilities,
   policy versions, timings, warnings, checksums, sizes, artifacts,
   collections and the T01 revision.
8. Python validates every referenced artifact before normalization begins.
9. Partial protocol failure does not destroy usable outputs.
10. No NRF/UDR filtering, diagnosis, or model invocation occurs in T01.
11. Performance is benchmarked against the current decoder on the same capture and host.
12. When enabled, the packet-access index is immutable, source-checksummed,
    pcap/pcapng reconstruction-capable and independently benchmarked.
13. Descriptor validation rejects absolute paths, traversal, symlink escapes,
    checksum drift, record-count mismatch and missing/extra collection
    members.
14. Identical inputs and resolved options produce byte-identical T01
    revisions and manifest descriptor content across supported machines.
