# T02 `normalize_events` Implementation Specification

## 1. Purpose

`normalize_events` converts validated T01 decoder artifacts into stable, versioned canonical events used by all later tools. It also routes HTTP/2 events into `primary`, `nrf`, or `udr` partitions and builds indexes that resolve every normalized event back to complete retained evidence.

T02 is the compatibility boundary between tshark/decoder output and the diagnostic harness. Decoder schema changes should be absorbed here without changing attempt, diagnostic, model, or report contracts.

## 2. Non-Goals

T02 must not:

- Correlate records into a UE identity graph.
- Segment procedure attempts.
- Decide whether a response is a call failure.
- Rank root causes.
- Remove NRF, UDR, heartbeat, startup, or successful traffic from retained data.
- Send evidence to a model.
- Re-run tshark except through an explicit later T20 request.

Routing an event to `nrf` or `udr` is an access-control classification, not a diagnosis.

## 3. Upstream and Downstream Contracts

### 3.1 Required upstream state

- T01 completed with `success` or `partial`.
- `decoder_manifest.json` passed schema, path, checksum, and artifact-count validation.
- Source PCAP and decoder artifacts remain immutable.
- The run owns empty staging paths for normalized output.

### 3.2 Downstream consumers

- T03-T21 consume `PrimaryEventReader` or primary-derived artifacts.
- T24 consumes `NRFEventReader` only after request validation.
- T25 consumes `UDREventReader` only after request validation.
- T18 resolves `SourceRef` values back to T01 artifacts.

No downstream consumer should parse T01 decoder trees directly.

## 4. Python Tool Contract

```python
class NormalizeEventsRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    decoder_result: DecodeCaptureResult
    normalized_dir: Path
    indexes_dir: Path
    config: NormalizationConfig


class NormalizationConfig(BaseModel):
    canonical_schema_version: Literal["2.0"] = "2.0"
    partition_rules_version: str
    max_materialized_body_bytes: int = 2_000_000
    max_warning_samples_per_code: int = 20
    fail_on_unknown_schema_version: bool = True
    retain_routine_pfcp_heartbeats: bool = True
    fsync_outputs: bool = True


class NormalizeEventsResult(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    status: Literal["success", "partial", "failed"]
    manifest: ArtifactDescriptor
    artifacts: list[ArtifactDescriptor]
    event_count: int
    partition_counts: dict[Literal["primary", "nrf", "udr"], int]
    protocol_counts: dict[str, int]
    source_record_counts: dict[str, int]
    unknown_field_counts: dict[str, int]
    warning_counts: dict[str, int]
    elapsed_ms: int
    warnings: list[NormalizationWarning]
```

The Python call returns only after output files, indexes, counts, and checksums have been validated.

## 5. Canonical Event Contract

The persisted event model is defined in `../LLD.md` section 4.2 and is extended with normalization metadata:

```python
class CanonicalEvent(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    event_id: UUID
    analysis_id: UUID
    protocol: Literal["HTTP2", "NGAP", "NAS", "PFCP"]
    partition: Literal["primary", "nrf", "udr"]
    partition_reason: str
    partition_confidence: Literal["high", "medium", "low"]
    frame: int
    timestamp: Decimal | None
    src: Endpoint | None
    dst: Endpoint | None
    direction: Literal[
        "UE_TO_NETWORK", "NETWORK_TO_UE", "NF_TO_NF", "UNKNOWN"
    ]
    message_type: str
    procedure: str | None
    outcome: Literal["request", "success", "failure", "notification", "unknown"]
    identifiers: EventIdentifiers
    attributes: dict[str, JsonValue]
    raw_refs: list[SourceRef]
    warnings: list[str] = Field(default_factory=list)
```

### 5.1 Event ID generation

Event IDs must be reproducible for the same source artifact and normalizer version:

```text
UUIDv5(
  analysis_id,
  source_artifact_sha256 + record_id + semantic_subrecord_type + ordinal
)
```

An outer NGAP record and each embedded NAS PDU receive distinct event IDs.

### 5.2 Source references

Each `SourceRef` must contain:

- Decoder artifact relative path and SHA-256.
- Source record/document UUID.
- Frame number.
- JSON path or JSONL line/byte offset.
- Optional field path.
- Optional raw-packet reference.

Normalized values never replace the source value. A conversion warning is recorded when parsing changes representation.

## 6. Input Artifact Readers

T02 uses protocol-specific streaming readers:

```python
class DecoderArtifactReader(Protocol):
    protocol: str

    def iter_records(
        self, descriptor: ArtifactDescriptor
    ) -> Iterator[DecoderRecord]: ...


class ProtocolNormalizer(Protocol):
    protocol: str

    def normalize(self, record: DecoderRecord) -> Iterator[CanonicalEvent]: ...
```

Readers must:

- Reject an unsupported artifact schema version.
- Validate record/document UUID and required metadata.
- Preserve the artifact's original order.
- Report malformed records with location and continue only when stream alignment is recoverable.
- Never load all HTTP/2 documents or a complete JSONL artifact into memory.

## 7. Normalization Pipeline

1. Validate request paths are inside the run directory.
2. Revalidate T01 manifest schema and artifact descriptors.
3. Create a staging output directory.
4. Open complete and partition JSONL writers.
5. Process artifacts in deterministic protocol/path order.
6. Normalize each source record into zero or more canonical events.
7. Route each event through the partition router.
8. Append the event to `events.jsonl` and exactly one partition file.
9. Update frame, time, protocol, stream, identifier, NRF, and UDR indexes.
10. Close writers and validate event/index counts.
11. Compute checksums and publish artifacts atomically.
12. Publish `normalization_manifest.json` last.

Re-running T02 for the same analysis is idempotent when source checksums, configuration, and normalizer version match. Otherwise, the existing completed output must not be overwritten; the caller creates a new derived normalization revision.

## 8. HTTP/2 Normalization

### 8.1 Required extraction

- TCP stream, HTTP/2 stream ID, and stream document UUID.
- Request/response start and end frames/timestamps.
- Method, full URI, URI template, path parameters, query parameters.
- Ordered duplicate headers and selected normalized header lookup.
- HTTP status and expected operation status set.
- `ProblemDetails` fields.
- Request/response completion state and reset information.
- Body content type, size, checksum, parse state, JSON pointer candidates, and multipart metadata.
- SBI API/service name, version, resource, consumer, producer, target-api-root, callback/notification role.
- Correlation IDs, SM context references, charging IDs, NF IDs, and masked subscriber candidates.

### 8.2 Event emission

A complete request/response stream normally emits one HTTP2 event containing both directions. Request-only, response-only, reset, and truncated streams also emit one event with explicit completion state.

Notifications are classified from operation metadata and direction; absence of a response does not automatically make a one-way notification a timeout.

### 8.3 Body handling

- Parse decoded JSON only when T01 marked it available and within configured size.
- Preserve JSON pointer paths for extracted semantic values.
- Do not duplicate full bodies into normalized events.
- Store summaries and `SourceRef`; T18 retrieves complete bodies.
- Malformed JSON/multipart emits a parse warning and retains body checksum/length.

## 9. NGAP and NAS Normalization

### 9.1 NGAP event

Extract:

- Procedure code/name and initiating/successful/unsuccessful outcome.
- AMF/RAN UE NGAP IDs.
- Cause category/value.
- PDU session resource list items.
- TAI, CGI, GUAMI, PLMN, location, handover type, and target identifiers.
- Transport-layer addresses, TEIDs, and QFI values where present.
- SCTP stream/association metadata.

### 9.2 Embedded NAS events

Emit one NAS event per `NAS_PDU_tree` or `pDUSessionNAS_PDU_tree`, inheriting outer frame/time/endpoints and adding a source path to the embedded tree.

Extract when visible:

- 5GMM/5GSM message type.
- Registration type and follow-on request.
- Service request type.
- PDU session ID and PTI.
- DNN, S-NSSAI, PDU type, SSC mode, QoS rules/flows.
- GUTI/SUCI/SUPI/GPSI/PEI candidates.
- Reject cause, authentication/security indicators, emergency/access type.

Encrypted or undecoded NAS emits a semantic placeholder with `nas_visibility=encrypted_or_unparsed`; it is not silently dropped.

## 10. PFCP Normalization

Extract:

- Message type/name, sequence, request/response role, response reference.
- CP/UP SEID and node identity.
- Cause and offending IE.
- PDR/FAR/QER/URR/BAR identifiers and operation.
- F-TEID, outer-header creation/removal, UE IP, QFI, forwarding action.
- DNN/network instance and S-NSSAI when available.
- Heartbeat/recovery timestamp metadata.

PFCP heartbeats remain normalized by default and receive `attributes.routine=true`. Later evidence builders may omit them unless relevant.

## 11. Value Normalization Rules

- Frames: positive integer.
- Epoch timestamps: `Decimal` string with source precision retained.
- Numeric protocol values: parsed integer plus optional original text label.
- IP addresses: canonical textual form; preserve original value in source.
- PLMN: normalized MCC/MNC with MNC-length metadata when known.
- DNN/FQDN/header names: comparison-normalized lowercase plus original display value.
- URI: preserve original; generate a separately normalized URI template.
- Hex/binary identifiers: lowercase hex without separators plus original reference.
- Empty string and absent field remain distinct.

Failed conversion leaves the semantic value `None`, preserves source reference, and emits `VALUE_PARSE_FAILED`.

## 12. Partition Router

### 12.1 NRF partition

High-confidence rules include:

- `nnrf-nfm` or `nnrf-disc` API identity.
- NRF status notifications.
- Explicit target/producer NF type `NRF`.
- SCP delegated-discovery records exposing NRF discovery semantics.

### 12.2 UDR partition

High-confidence rules include:

- `nudr-dr` API identity.
- Explicit target/producer NF type `UDR`.
- Endpoint mapped to UDR through configured or observed NF identity with supporting API semantics.

### 12.3 Ambiguity

Hostnames containing `nrf` or `udr` alone are not sufficient. Ambiguous records remain `primary`, carry `partition_confidence=low`, and emit `AMBIGUOUS_DEPENDENCY_PARTITION` so they are not accidentally hidden from first-pass analysis.

Partition rules are table-driven, versioned, and recorded in the manifest.

## 13. Index Design

```text
indexes/frame_index.jsonl
indexes/time_index.jsonl
indexes/protocol_index.json
indexes/stream_index.jsonl
indexes/identifier_index.jsonl
indexes/nrf_index.jsonl
indexes/udr_index.jsonl
```

Index entries contain event ID, partition, frame/time, source record, and only the fields needed for bounded lookup. Sensitive values use keyed local hashes in general indexes; clear values remain in trusted event/source records.

The frame index supports multiple events for one frame. The time index uses sorted buckets plus exact event timestamps. Index publication must be deterministic.

## 14. Output Layout and Manifest

```text
normalized/
  events.jsonl
  primary_events.jsonl
  nrf_events.jsonl
  udr_events.jsonl
  normalization_manifest.json
indexes/
  frame_index.jsonl
  time_index.jsonl
  protocol_index.json
  stream_index.jsonl
  identifier_index.jsonl
  nrf_index.jsonl
  udr_index.jsonl
```

The manifest records:

- Analysis and canonical schema versions.
- T01 manifest checksum.
- Normalizer build/version and partition-rules version.
- Source artifact checksums and processed record counts.
- Event counts by protocol, partition, message type, and warning code.
- Output descriptors with checksum, size, and record count.
- Start/end time, elapsed time, and peak RSS when available.
- Status and sampled warnings.

## 15. Atomicity and Recovery

- Write to `normalized/.staging-<uuid>/` and `indexes/.staging-<uuid>/`.
- Flush and close each JSONL writer before checksum.
- Validate each event against the persisted schema while writing or in a final streaming pass.
- Publish data files, then indexes, then manifest.
- If publication fails, remove staging and leave no valid manifest.
- A valid prior revision is never modified.

## 16. Failure Semantics

- Invalid request/path/schema: fatal T02 failure.
- T01 checksum mismatch: fatal evidence-integrity failure.
- One malformed record with recoverable JSONL alignment: warning and partial status.
- Unsupported source artifact version: fail that protocol; overall partial when others remain useful.
- Unknown protocol field: count/warn, not failure.
- Event validation failure: quarantine record reference, warn, and continue only below configured threshold.
- Index/data count mismatch: fatal publication failure.
- Disk full/rename/fsync failure: fatal.

Warning codes must include source artifact and record location without logging sensitive values.

## 17. Performance and Resource Requirements

- O(number of decoder records + emitted events).
- Memory bounded by one source record, one normalized event batch, and index buffers.
- Avoid repeated JSON parsing of HTTP documents.
- Batch JSONL writes and index flushes.
- Record records/second, events/second, bytes read/written, peak RSS, and per-protocol elapsed time.
- Initial target: no more than 25% overhead versus a checksum-and-schema scan of the same T01 artifacts.
- A million-event capture must not require a million-entry in-memory object graph.

## 18. Security and Privacy

- Treat decoder JSON as untrusted input.
- Reject path traversal and symlink escape from the run directory.
- Bound body/tree materialization and nesting depth.
- Do not log bodies, authorization headers, subscriber identifiers, or authentication data.
- Use a run-local keyed hash for sensitive index lookup where necessary.
- T02 output stays inside the local trusted boundary.

## 19. Observability

Structured log fields:

- `analysis_id`, `tool=T02`, `protocol`, `artifact_id`, `record_id`.
- `records_read`, `events_emitted`, `partition`, `warning_code`.
- `duration_ms`, `bytes_read`, `bytes_written`, `peak_rss_bytes`.

Metrics:

- Normalization throughput by protocol.
- Unknown/failed field conversion counts.
- Partition counts and ambiguous-routing count.
- Quarantined record count.
- Index publication duration.

## 20. Proposed Python Code Structure

```text
V2/harness/normalize/
  base.py                    common reader/normalizer protocols
  models.py                  decoder-record adapters
  http2.py                   HTTP stream normalization
  ngap.py                    NGAP event normalization
  nas.py                     embedded NAS normalization
  pfcp.py                    PFCP normalization
  values.py                  typed conversion helpers
  partition_router.py        versioned primary/NRF/UDR rules
  manifest.py                normalization manifest models
  runner.py                  T02 orchestration
V2/harness/storage/
  jsonl_store.py             atomic partition writers
  frame_index.py
  identifier_index.py
  nrf_index.py
  udr_index.py
```

Only `normalize.runner.normalize_events()` is exposed to the orchestrator.

## 21. Implementation Sequence

1. Define canonical and manifest schemas.
2. Implement atomic JSONL writer and source-reference builder.
3. Implement HTTP/2 normalizer and stream indexes.
4. Implement NGAP and embedded NAS normalizers.
5. Implement PFCP normalizer.
6. Implement versioned partition routing.
7. Implement indexes and manifest validation.
8. Add performance fixtures and compatibility tests for tshark/decoder versions.

## 22. Tests

### 22.1 Unit tests

- Deterministic event UUID generation.
- Every value normalization rule and parse failure.
- Ordered duplicate HTTP headers and malformed bodies.
- Request-only/reset/truncated HTTP streams.
- Multiple embedded NAS PDUs in one NGAP record.
- Encrypted/unknown NAS message.
- PFCP response pairing fields and retained heartbeat.
- NRF, UDR, delegated-discovery, and ambiguous partition rules.
- SourceRef JSON paths and offsets.
- Index entries for multiple events on one frame.
- Atomic writer rollback.

### 22.2 Integration tests

- All T01 artifact types present.
- T01 partial result with one protocol absent/failed.
- Unsupported artifact version.
- Corrupt JSONL record with recoverable continuation.
- Artifact checksum mismatch.
- Large capture with bounded memory.
- Re-run with identical inputs and changed configuration.
- Every normalized event resolves through T18 to full evidence.

### 22.3 Golden compatibility tests

Store canonical-event fixtures for supported T01 schema versions. Golden tests compare semantic fields and references, not JSON object key order.

## 23. Acceptance Criteria

T02 is complete when:

1. It streams every validated T01 artifact without loading the full capture output.
2. Every emitted event validates against canonical schema `2.0`.
3. Every event resolves to immutable full/raw evidence.
4. HTTP2, NGAP, NAS, and PFCP semantic fields required by later tools are retained.
5. NRF/UDR routing is versioned, conservative, and never based only on hostname substrings.
6. Primary analysis cannot read NRF/UDR partitions through T02 interfaces.
7. Unknown or malformed input is reported rather than silently discarded.
8. Counts, checksums, indexes, and event IDs are reproducible.
9. Partial protocol normalization preserves usable outputs and warnings.
10. No diagnosis, attempt correlation, model invocation, or destructive filtering occurs.
