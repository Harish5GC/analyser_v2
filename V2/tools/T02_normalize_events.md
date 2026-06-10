# T02 `normalize_events` Implementation Specification

## 1. Purpose

`normalize_events` converts validated T01 decoder artifacts into stable,
versioned canonical events used by all later tools. It also routes events into
`primary`, `nrf`, or `udr` partitions and builds indexes that resolve every
normalized event back to complete retained evidence.

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
- The section 29 resolver has supplied immutable protocol codepoint and
  partition-policy handles.

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
    run_dir: Path
    normalized_dir: Path
    indexes_dir: Path
    protocol_registry: ProtocolCodepointRegistry
    partition_policy: ResolvedPolicy
    enabled_capabilities: set[CapabilityName] = Field(default_factory=set)
    policy_versions: dict[str, str]
    config: NormalizationConfig


class NormalizationConfig(BaseModel):
    canonical_schema_version: Literal["2.0"] = "2.0"
    max_materialized_body_bytes: int = 2_000_000
    max_warning_samples_per_code: int = 20
    fail_on_unknown_schema_version: bool = True
    retain_routine_pfcp_heartbeats: bool = True
    fsync_outputs: bool = True


class NormalizeEventsResult(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: UUID
    status: Literal["success", "partial", "failed"]
    revision: str
    manifest: ArtifactDescriptor
    artifacts: list[ArtifactDescriptor]
    collections: list[CollectionDescriptor] = Field(default_factory=list)
    event_count: int
    partition_counts: dict[Literal["primary", "nrf", "udr"], int]
    protocol_counts: dict[str, int]
    source_record_counts: dict[str, int]
    unknown_field_counts: dict[str, int]
    warning_counts: dict[str, int]
    elapsed_ms: int
    issues: list[NormalizationWarning]
```

The Python call returns only after output files, indexes, descriptors, counts
and checksums have been validated. `NormalizationWarning` is a type alias of
the shared `Issue` model with T02-owned issue codes. T02 status values are
tool-local; T17 maps them into run/report status.

## 5. Canonical Event Contract

The persisted event model is defined in `../LLD.md` section 4.2. JSONL is the
physical format; `CanonicalEvent` is the logical schema. T02 owns partition
metadata through reserved `attributes` keys rather than creating a divergent
event class.

```python
class CanonicalEvent(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    event_id: UUID
    analysis_id: UUID
    protocol: Literal["NAS", "NGAP", "HTTP2", "PFCP"]
    frame: int
    timestamp: Decimal | None
    timestamp_precision: Literal[
        "seconds", "milliseconds", "microseconds", "nanoseconds", "unknown"
    ] = "unknown"
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
    partition: Literal["primary", "nrf", "udr"]
    validation_status: Literal["valid", "partial", "quarantined"]
    issues: list[Issue] = Field(default_factory=list)
```

T02 writes these reserved `attributes` keys for audit and routing:

- `t02.partition_reason`: selected partition rule/rationale.
- `t02.partition_confidence`: `high`, `medium` or `low`.
- `t02.source_record_type`: decoder record type used to create the event.
- `t02.protocol_registry_version`: protocol codepoint registry version.
- `t02.partition_policy_version`: partition policy version.

`validation_status="quarantined"` records are retained in the complete
`events.jsonl` and evidence indexes but are excluded from partition reader
outputs consumed by primary detectors or dependency inspectors.

### 5.1 Event ID generation

Event IDs must be reproducible for the same source artifact, T01 revision and
protocol registry. Partition policy, normalizer version and output descriptors
are T02 revision inputs; they do not change event IDs unless the semantic
record decomposition changes.

```text
UUIDv5(
  analysis_id,
  t01_revision + source_artifact_sha256 + record_id
  + semantic_subrecord_type + ordinal + protocol_registry_sha256
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
- Artifact SHA-256 and byte offset/length when available.

Normalized values never replace the source value. A conversion warning is recorded when parsing changes representation.

## 6. Input Artifact Readers

T02 uses protocol-specific streaming readers:

```python
class DecoderArtifactReader(Protocol):
    protocol: str

    def iter_records(
        self, descriptor: ArtifactDescriptor
    ) -> Iterator[DecoderRecord]: ...


class NormalizationContext(BaseModel):
    analysis_id: UUID
    t01_revision: str
    protocol_registry: ProtocolCodepointRegistry
    raw_refs: list[SourceRef]
    source_record_ordinal: int
    config: NormalizationConfig


class ProtocolNormalizer(Protocol):
    protocol: str

    def normalize(
        self, record: DecoderRecord, context: NormalizationContext
    ) -> Iterator[CanonicalEvent]: ...
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
3. Validate T01 revision lineage and source checksum against
   `decoder_result`.
4. Validate `ProtocolCodepointRegistry` and partition policy identity against
   `policy_versions`.
5. Create a staging output directory under `staging/T02-<uuid>/`.
6. Open complete and partition JSONL writers.
7. Process artifacts in deterministic protocol/path order.
8. Normalize each source record into zero or more canonical events.
9. Route each event through the partition router.
10. Append every event to `normalized/events/events.jsonl`.
11. Append non-quarantined events to exactly one partition file.
12. Update frame, time, protocol, stream, identifier, NRF, UDR and artifact
    indexes.
13. Close writers and validate event/index counts.
14. Compute checksums, descriptors and the T02 `RevisionEnvelope`.
15. Publish data files, indexes, descriptors and `normalization_manifest.json`
    atomically; publish manifest last.

Re-running T02 for the same analysis is idempotent when source checksums,
T01 revision, configuration, codepoint registry, partition policy and
normalizer version match. Otherwise, the existing completed output must not be
overwritten; T02 mints a new sibling normalization revision per the `LLD.md`
section 25 revision model. Each tool mints its own revision; callers never
mint on a tool's behalf.

### 7.1 Implementation blueprint

The runner should be implementable as this control flow, with helper methods
owning validation and serialization details:

```python
def normalize_events(req: NormalizeEventsRequest) -> NormalizeEventsResult:
    started = clock.now()
    validate_inside_run(req.run_dir, req.normalized_dir, req.indexes_dir)
    t01_manifest = load_and_validate_t01_manifest(req.decoder_result.manifest)
    validate_decoder_result_matches_manifest(req.decoder_result, t01_manifest)
    validate_revision_lineage(req.decoder_result.revision, t01_manifest)
    registry = validate_protocol_registry(req.protocol_registry, req.policy_versions)
    partition_policy = validate_partition_policy(req.partition_policy, req.policy_versions)

    existing = inspect_existing_normalization(req.run_dir, req.analysis_id)
    if existing and normalization_inputs_match(existing, req, t01_manifest, registry, partition_policy):
        return result_from_manifest(existing.manifest)
    publication = resolve_publication_target(req, existing)

    staging = make_unique_staging_dir(req.run_dir / "staging", prefix="T02-")
    paths = build_staged_paths(staging, publication.final_relative_layout)
    writers = open_event_writers(paths.events)
    indexes = open_index_builders(paths.indexes)
    counters = NormalizationCounters()
    seen_event_ids: set[UUID] = set()
    issues: list[Issue] = []

    for descriptor in sorted_t01_artifacts(t01_manifest):
        reader = reader_for(descriptor.artifact_type)
        source_record_ordinal = 0
        for record in reader.iter_records(descriptor):
            source_record_ordinal += 1
            counters.source_record_counts[record.record_type] += 1
            raw_refs = build_source_refs(descriptor, record)
            context = NormalizationContext(
                analysis_id=req.analysis_id,
                t01_revision=req.decoder_result.revision,
                protocol_registry=registry,
                raw_refs=raw_refs,
                source_record_ordinal=source_record_ordinal,
                config=req.config,
            )
            try:
                events = normalizer_for(record.protocol).normalize(record, context)
            except RecoverableRecordError as exc:
                issue = issue_from_record_error(exc, descriptor, record)
                issues.append(issue)
                counters.warning_counts[issue.code] += 1
                continue

            for event in events:
                event = attach_t02_lineage(event, descriptor, record, registry, partition_policy)
                routed = route_event(event, partition_policy)
                event = apply_partition_result(event, routed)
                event = validate_or_quarantine(event)

                if event.event_id in seen_event_ids:
                    raise FatalNormalizationError("duplicate event_id")
                seen_event_ids.add(event.event_id)

                writers.complete.write(event)
                indexes.add(event, descriptor, record)
                counters.event_count += 1
                counters.protocol_counts[event.protocol] += 1
                counters.count_issues(event.issues)
                issues.extend(sample_issues(event.issues, req.config.max_warning_samples_per_code))

                if event.validation_status == "quarantined":
                    counters.quarantined_count += 1
                    continue

                writers.partition[event.partition].write(event)
                counters.partition_counts[event.partition] += 1

    close_flush_fsync(writers, indexes, enabled=req.config.fsync_outputs)
    descriptors = build_descriptors(paths, parent=t01_manifest, counters=counters)
    validate_output_invariants(paths, descriptors, counters, seen_event_ids)
    revision = build_t02_revision(req, t01_manifest, descriptors, registry, partition_policy)
    manifest = build_normalization_manifest(req, t01_manifest, descriptors, counters, issues, revision, started)
    validate_manifest(manifest)
    publish_staged_tree(staging, publication.normalized_dir, publication.indexes_dir, manifest_last=True)
    return result_from_manifest(manifest)
```

`sorted_t01_artifacts()` sorts first by canonical protocol order
`HTTP2`, `NGAP`, `NAS`, `PFCP`, then by descriptor relative path, then by
artifact ID. Record order inside one artifact is always the decoder order.
`resolve_publication_target()` never overwrites an existing valid manifest: it
returns the existing result for identical inputs, or allocates a sibling
normalization revision for changed inputs. `sample_issues()` enforces
`max_warning_samples_per_code` while counters retain full counts.

### 7.2 Writer and counter invariants

Maintain these counters while writing, not by re-reading the full output at
the end:

- `event_count`
- `partition_counts["primary"|"nrf"|"udr"]`
- `protocol_counts["HTTP2"|"NGAP"|"NAS"|"PFCP"]`
- `source_record_counts[record_type]`
- `unknown_field_counts[field_or_code]`
- `warning_counts[issue_code]`
- `quarantined_count`

Before publication, T02 must prove these invariants with a streaming validation
pass over the staged files and indexes:

- `event_count == rows(normalized/events/events.jsonl)`.
- `partition_counts["primary"] == rows(normalized/events/primary_events.jsonl)`.
- `partition_counts["nrf"] == rows(normalized/events/nrf_events.jsonl)`.
- `partition_counts["udr"] == rows(normalized/events/udr_events.jsonl)`.
- `event_count >= sum(partition_counts.values())`; the difference equals
  `quarantined_count`.
- Every non-quarantined event appears in exactly one partition file.
- Every quarantined event appears only in `events.jsonl`.
- Every event ID is unique across complete and partition files.
- Every index entry references an existing event ID and source artifact
  descriptor.
- Every event `raw_refs[*].artifact_sha256` matches its descriptor checksum.
- Manifest counts match the validated counters, not just in-memory counters.

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

### 8.4 HTTP/2 normalizer algorithm

For each T01 HTTP/2 stream document:

1. Validate stream document UUID, TCP stream, HTTP/2 stream ID, frame list and
   source artifact reference.
2. Build one logical transaction event for the stream document. Do not emit a
   separate request event and response event unless T01 explicitly split one
   HTTP/2 stream into multiple logical transactions.
3. Set `frame` to the first request frame when present, otherwise the first
   response/data/reset frame.
4. Set `timestamp` to the first available transaction timestamp and preserve
   precision from the source record.
5. Extract `src`, `dst` and `direction` from decoded endpoint metadata. Use
   `NF_TO_NF` for SBI traffic when both sides are network functions; use
   `UNKNOWN` when endpoint roles are absent.
6. Resolve `message_type` from method plus URI template, for example
   `POST /nudr-dr/v2/subscription-data/{ueId}/...`. If no method or template
   is available, use `HTTP2_STREAM`.
7. Resolve `procedure` from operation metadata when available; otherwise use
   the SBI API/resource family.
8. Set `outcome`:
   - Operation metadata marks the stream as notification/callback:
     `notification`.
   - Otherwise, complete request/response with status `200..399`: `success`.
   - Otherwise, complete request/response with status `400..599`: `failure`.
   - Request-only, response-only, reset, truncated or status-missing streams:
     `unknown`.
9. Populate identifiers from correlation IDs, NF IDs, SM context references,
   charging IDs, masked subscriber candidates and stream IDs.
10. Populate attributes for HTTP method, status, URI template, SBI API/service,
    resource, producer/consumer NF type, target-api-root, completion state,
    reset reason and selected body summaries.
11. Preserve ordered duplicate headers in attributes or a referenced summary;
    normalized header lookup keys are lowercase and must not discard original
    header values.
12. Materialize body fields only through configured selectors and size limits.
    Store checksum, length, content type, parse state and JSON pointers; never
    copy full bodies into the event.
13. Add `raw_refs` for the stream document and every contributing frame/raw
    packet reference supplied by T01.
14. Route the event after normalization; HTTP/2 normalizers do not write
    partition fields directly.

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

NAS message and cause names are looked up only in the resolved
`ProtocolCodepointRegistry`; T02 must not carry a duplicate NAS codepoint
table. Unknown message codes emit `message_type="NAS_UNKNOWN_<code>"`,
preserve the raw code in `attributes.nas.raw_message_type`, and add a
registered warning only when the registry says the code should be known for
the selected release/profile.

Extract when visible:

- 5GMM/5GSM message type.
- Registration type and follow-on request.
- Service request type.
- PDU session ID and PTI.
- DNN, S-NSSAI, PDU type, SSC mode, QoS rules/flows.
- GUTI/SUCI/SUPI/GPSI/PEI candidates.
- Reject cause, authentication/security indicators, emergency/access type.

Encrypted or undecoded NAS emits a semantic placeholder with `nas_visibility=encrypted_or_unparsed`; it is not silently dropped.

### 9.3 NGAP/NAS normalizer algorithm

For each T01 NGAP record:

1. Emit one NGAP event for the outer PDU.
2. Set NGAP `message_type` from procedure code/name and PDU class through the
   resolved `ProtocolCodepointRegistry`.
3. Map initiating messages to `outcome="request"`, successful outcome PDUs to
   `success`, unsuccessful outcome PDUs to `failure`, and unknown classes to
   `unknown`.
4. Extract AMF/RAN UE NGAP IDs, cause, location, PDU session resources, TEIDs,
   QFIs, SCTP association/stream and endpoint metadata.
5. Add `raw_refs` to the outer NGAP tree and exact source field paths for
   extracted identifiers.
6. For every embedded `NAS_PDU_tree` or `pDUSessionNAS_PDU_tree`, emit one
   additional NAS event.
7. NAS child events inherit frame, timestamp, endpoints, direction and relevant
   NGAP identifiers from the outer event, then add NAS-specific identifiers
   such as PDU session ID, PTI, SUCI/SUPI/GUTI/GPSI/PEI candidates and cause.
8. Resolve NAS message and cause names only through
   `ProtocolCodepointRegistry`; there is no local fallback table.
9. Unknown NAS codepoints use `message_type="NAS_UNKNOWN_<code>"`, preserve
   `attributes.nas.raw_message_type`, and emit a warning only when the
   registry marks the codepoint as expected for the selected profile.
10. Encrypted or undecoded NAS emits a valid placeholder NAS event with
    `attributes.nas.visibility="encrypted_or_unparsed"` and
    `outcome="unknown"`.
11. NGAP and NAS events are routed to `primary` by contract after validation.

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

PFCP unknown or unsupported message/cause values remain observation values in
`message_type`, `outcome="unknown"` or PFCP-specific `attributes`. T02 does
not emit diagnostic `inconclusive`; that mapping belongs to T08/T12 when
evidence is evaluated.

### 10.1 PFCP normalizer algorithm

For each T01 PFCP record:

1. Emit one PFCP event per decoded PFCP message. Do not merge request/response
   pairs into a single event.
2. Resolve message and cause names through `ProtocolCodepointRegistry` when
   the registry covers the value; otherwise preserve the numeric value as an
   observed unknown.
3. Set `outcome` to `request` for request-role messages, `success` or
   `failure` for response-role messages with known cause semantics, and
   `unknown` when role or cause semantics are unavailable.
4. Link transaction context using decoder `response_to` fields when present.
   Otherwise record best-effort pairing attributes from sequence number,
   endpoint tuple and bounded time proximity; never rely on pairing for event
   identity.
5. Extract CP/UP SEID, node identity, F-SEID, PDR/FAR/QER/URR/BAR IDs,
   F-TEID, UE IP, QFI, forwarding action, network instance and S-NSSAI.
6. Preserve heartbeat and recovery timestamp messages. For v2.0,
   `retain_routine_pfcp_heartbeats` must be true; reject requests that set it
   false. Mark routine heartbeat events `attributes.routine=true`.
7. Add `raw_refs` to the PFCP tree and contributing frame/raw packet
   references.
8. Route every emitted PFCP event to `primary`.

## 11. Value Normalization Rules

- Frames: positive integer.
- Epoch timestamps: absolute Unix-epoch `Decimal` string with
  `timestamp_precision` set to seconds, milliseconds, microseconds,
  nanoseconds or unknown. Invalid or absent source time becomes
  `timestamp=None` and `timestamp_precision="unknown"`.
- Numeric protocol values: parsed integer plus optional original text label.
- IP addresses: canonical textual form; preserve original value in source.
- PLMN: normalized MCC/MNC with MNC-length metadata when known.
- DNN/FQDN/header names: comparison-normalized lowercase plus original display value.
- URI: preserve original; generate a separately normalized URI template.
- Hex/binary identifiers: lowercase hex without separators plus original reference.
- Empty string and absent field remain distinct.

Persisted decimal values use canonical plain strings with no binary-float
round trip. Runtime code may use native numeric types internally, but values
entering canonical events, indexes, manifests or revision inputs must pass
through this conversion layer.

Failed conversion leaves the semantic value `None`, preserves source
reference, and emits `T02_VALUE_PARSE_FAILED`.

## 12. Partition Router

NAS, NGAP and PFCP events always route to `primary`. HTTP/2/SBI events route
through the resolved partition policy using normalized SBI service/API,
resource, producer/consumer NF, target-api-root and callback/notification
metadata. Partition routing is an access-control classification; it is not a
diagnostic conclusion.

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

Hostnames containing `nrf` or `udr` alone are not sufficient. Ambiguous
records remain `primary`, carry `t02.partition_confidence=low`, and emit
`T02_AMBIGUOUS_DEPENDENCY_PARTITION` so they are not accidentally hidden from
first-pass analysis.

Partition rules are table-driven, versioned, and recorded in each event's
reserved T02 attributes plus the manifest. The router records the exact rule
ID and confidence band used. No tool may reinterpret partition ownership by
reading hostnames directly after T02 publishes.

### 12.4 Partition router pseudocode

```python
def route_event(event: CanonicalEvent, policy: ResolvedPolicy) -> PartitionDecision:
    if event.protocol in {"NAS", "NGAP", "PFCP"}:
        return PartitionDecision("primary", "protocol_primary", "high")

    if event.protocol != "HTTP2":
        return PartitionDecision("primary", "unknown_protocol_primary", "medium")

    facts = extract_partition_facts(event)
    matches = policy.match(facts)

    high_confidence_nrf = matches.has_api("nnrf-nfm") or matches.has_api("nnrf-disc")
    high_confidence_nrf = high_confidence_nrf or matches.has_nf_type("NRF")
    high_confidence_nrf = high_confidence_nrf or matches.has_rule("scp_delegated_discovery_nrf")
    if high_confidence_nrf:
        return PartitionDecision("nrf", matches.rule_id, "high")

    high_confidence_udr = matches.has_api("nudr-dr") or matches.has_nf_type("UDR")
    high_confidence_udr = high_confidence_udr or matches.has_rule("observed_identity_udr_with_api")
    if high_confidence_udr:
        return PartitionDecision("udr", matches.rule_id, "high")

    if facts.only_hostname_hint in {"nrf", "udr"} or matches.is_ambiguous:
        return PartitionDecision(
            "primary",
            "ambiguous_dependency_partition",
            "low",
            issue_code="T02_AMBIGUOUS_DEPENDENCY_PARTITION",
        )

    return PartitionDecision("primary", "default_primary", "medium")
```

`extract_partition_facts()` may read normalized SBI API, service name,
resource family, producer NF type, consumer NF type, target-api-root,
callback/notification role and policy-resolved endpoint identity. It must not
classify an event as NRF or UDR from hostname substrings alone.

## 13. Index Design

```text
indexes/frame_index.json
indexes/time_index.json
indexes/protocol_index.json
indexes/stream_index.json
indexes/identifier_index.json
indexes/nrf_index.json
indexes/udr_index.json
indexes/artifact_index.json
```

Index entries contain event ID, validation status, partition, frame/time,
source record, artifact descriptor reference, and only the fields needed for
bounded lookup. Sensitive values use keyed local hashes in general indexes;
clear values remain in trusted event/source records.

The frame index supports multiple events for one frame. The time index uses sorted buckets plus exact event timestamps. Index publication must be deterministic.

## 14. Output Layout and Manifest

```text
normalized/
  events/
    events.jsonl
    primary_events.jsonl
    nrf_events.jsonl
    udr_events.jsonl
  diagnostics/
    normalization_manifest.json
indexes/
  frame_index.json
  time_index.json
  protocol_index.json
  stream_index.json
  identifier_index.json
  nrf_index.json
  udr_index.json
  artifact_index.json
staging/T02-<uuid>/
```

The manifest records:

- Analysis and canonical schema versions.
- T01 manifest checksum and T01 revision.
- Normalizer build/version, protocol registry identity and partition-policy
  identity.
- Source artifact checksums and processed record counts.
- Event counts by protocol, partition, message type, and warning code.
- Output descriptors with checksum, size, record count, parent source checksum
  and T02 revision.
- Index descriptors and artifact-index descriptor.
- Start/end time, elapsed time, and peak RSS when available.
- Status and sampled warnings.

### 14.1 Normalization manifest shape

The manifest is JSON and must be deterministic except for timestamps and
elapsed/runtime measurements. Field order is not semantically significant, but
tests should compare canonical JSON serialization.

```json
{
  "schema_version": "2.0",
  "tool": "T02",
  "analysis_id": "00000000-0000-0000-0000-000000000000",
  "status": "success",
  "revision": "sha256:...",
  "parent": {
    "tool": "T01",
    "revision": "sha256:...",
    "manifest_sha256": "...",
    "source_pcap_sha256": "..."
  },
  "normalizer": {
    "version": "2.0.0",
    "canonical_schema_version": "2.0",
    "config_sha256": "..."
  },
  "protocol_registry": {
    "name": "5gc-protocol-codepoints",
    "version": "2026-06-10",
    "sha256": "..."
  },
  "partition_policy": {
    "name": "dependency-partitions",
    "version": "2026-06-10",
    "sha256": "..."
  },
  "counts": {
    "event_count": 0,
    "partition_counts": {"primary": 0, "nrf": 0, "udr": 0},
    "protocol_counts": {"HTTP2": 0, "NGAP": 0, "NAS": 0, "PFCP": 0},
    "source_record_counts": {},
    "unknown_field_counts": {},
    "warning_counts": {},
    "quarantined_count": 0
  },
  "artifacts": [],
  "indexes": [],
  "collections": [],
  "issues": [],
  "timing": {
    "started_at": "2026-06-10T00:00:00Z",
    "ended_at": "2026-06-10T00:00:00Z",
    "elapsed_ms": 0,
    "peak_rss_bytes": null
  }
}
```

`artifacts`, `indexes` and `collections` use the shared descriptor schemas
from `LLD.md` section 23. Manifest `issues` contain sampled shared `Issue`
objects; full per-event issues remain on canonical events.

### 14.2 Artifact descriptor expectations

T02 publishes exactly these artifact classes. Partition and index files are
still published when they contain zero records.

| Relative path | Artifact type | Media type | Count field |
| --- | --- | --- | --- |
| `normalized/events/events.jsonl` | `canonical_events_complete` | `application/x-ndjson` | `event_count` |
| `normalized/events/primary_events.jsonl` | `canonical_events_partition` | `application/x-ndjson` | `partition_counts.primary` |
| `normalized/events/nrf_events.jsonl` | `canonical_events_partition` | `application/x-ndjson` | `partition_counts.nrf` |
| `normalized/events/udr_events.jsonl` | `canonical_events_partition` | `application/x-ndjson` | `partition_counts.udr` |
| `normalized/diagnostics/normalization_manifest.json` | `normalization_manifest` | `application/json` | `1` |
| `indexes/frame_index.json` | `event_index` | `application/json` | implementation-defined entries |
| `indexes/time_index.json` | `event_index` | `application/json` | implementation-defined entries |
| `indexes/protocol_index.json` | `event_index` | `application/json` | implementation-defined entries |
| `indexes/stream_index.json` | `event_index` | `application/json` | implementation-defined entries |
| `indexes/identifier_index.json` | `event_index` | `application/json` | implementation-defined entries |
| `indexes/nrf_index.json` | `event_index` | `application/json` | implementation-defined entries |
| `indexes/udr_index.json` | `event_index` | `application/json` | implementation-defined entries |
| `indexes/artifact_index.json` | `event_index` | `application/json` | implementation-defined entries |

Each descriptor records relative path, artifact type, media type, schema
version, byte size, SHA-256, record/entry count, parent source artifact
checksum where applicable, producing tool `T02` and T02 revision. Partition
file descriptors must also record `partition`.

## 15. Atomicity and Recovery

- Write to `staging/T02-<uuid>/`.
- Flush and close each JSONL writer before checksum.
- Validate each event against the persisted schema while writing or in a final streaming pass.
- Validate every artifact descriptor and index descriptor before publication.
- Publish data files, then indexes, then manifest under
  `normalized/diagnostics/normalization_manifest.json`.
- If publication fails, remove staging and leave no valid manifest.
- A valid prior revision is never modified.
- Reject absolute paths, traversal, symlink escapes, parent source checksum
  mismatches, record-count mismatches and missing/extra index entries.

## 16. Failure Semantics

- Invalid request/path/schema: fatal T02 failure.
- T01 checksum mismatch: fatal evidence-integrity failure.
- One malformed record with recoverable JSONL alignment: warning and partial status.
- Unsupported source artifact version: fail that protocol; overall partial when others remain useful.
- Unknown protocol field: count/warn, not failure.
- Event validation failure: quarantine record reference, warn, and continue only below configured threshold.
- Quarantined events remain in complete `events.jsonl` with source references
  and issues, but are excluded from partition files and readers.
- Index/data count mismatch: fatal publication failure.
- Disk full/rename/fsync failure: fatal.

Warning codes must be registered `Issue` codes and include source artifact and
record location without logging sensitive values. Unknown issue codes fail
tests and should fail publication in strict validation mode.

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
- Run-local lookup hashes are not stable cross-run pseudonyms and are never
  sent to remote providers.
- Primary readers expose only `primary_events.jsonl`; NRF/UDR readers are
  constructed only inside the dependency executor after request validation.

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
  protocol_registry.py       resolved codepoint registry adapters
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

1. Define canonical event, manifest, descriptor and revision schemas using the
   shared model registry.
2. Wire resolved `ProtocolCodepointRegistry`, partition policy and issue-code
   registry into the request.
3. Implement atomic JSONL writer, descriptor builder and source-reference
   builder.
4. Implement HTTP/2 normalizer and stream indexes.
5. Implement NGAP and embedded NAS normalizers through the codepoint registry.
6. Implement PFCP normalizer with unknown-outcome preservation.
7. Implement versioned partition routing with NAS/NGAP/PFCP forced primary.
8. Implement indexes, artifact index and manifest validation.
9. Add revision determinism, descriptor, partition-security and performance
   fixtures for supported T01 schema versions.

## 22. Tests

### 22.1 Unit tests

- Deterministic event UUID generation.
- T02 revision determinism for identical T01 revision, source checksums,
  protocol registry, partition policy and normalizer version.
- Every value normalization rule and parse failure.
- Canonical timestamp precision and Decimal serialization.
- Ordered duplicate HTTP headers and malformed bodies.
- Request-only/reset/truncated HTTP streams.
- Multiple embedded NAS PDUs in one NGAP record.
- Encrypted/unknown NAS message.
- NAS message/cause lookup uses the resolved `ProtocolCodepointRegistry`;
  no duplicate local codepoint table is accepted.
- PFCP response pairing fields and retained heartbeat.
- PFCP unknown/unsupported outcome remains observed `unknown` data and is not
  converted to diagnostic `inconclusive`.
- NAS, NGAP and PFCP always route to `primary`; HTTP/SBI routes through the
  partition policy.
- NRF, UDR, delegated-discovery, and ambiguous partition rules.
- SourceRef JSON paths and offsets.
- Index entries for multiple events on one frame.
- Time and protocol index descriptors match published index files.
- Quarantined event retained in complete events file but excluded from
  partition readers.
- Descriptor validation rejects path traversal, symlink escape, checksum
  drift, record-count mismatch and index/event count mismatch.
- Atomic writer rollback.
- Unknown `Issue` code rejected by lint.

### 22.2 Integration tests

- All T01 artifact types present.
- T01 partial result with one protocol absent/failed.
- Unsupported artifact version.
- Corrupt JSONL record with recoverable continuation.
- Artifact checksum mismatch.
- Large capture with bounded memory.
- Re-run with identical inputs and changed configuration.
- Every normalized event resolves through T18 to full evidence.
- Primary readers cannot access NRF/UDR events through direct IDs, indexes,
  cursors or selector expansion without dependency capability.
- Canonical run tree and artifact index contain every normalized event file
  and index descriptor.

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
11. T02 writes the canonical `normalized/events/` and shared `indexes/` tree
    with descriptor-validated artifacts and manifest-last publication.
12. The T02 revision includes T01 revision, source checksums, normalizer
    version, protocol registry, partition policy and output descriptors.
13. NAS codepoints are read from one resolved registry; NAS/NGAP/PFCP route to
    primary by contract.
14. Logical event metadata includes `timestamp_precision`,
    `validation_status`, `raw_refs`, `issues` and partition audit attributes.
15. The manifest and descriptors enumerate every event file and every index
    file, including frame, time, protocol, stream, identifier, NRF, UDR and
    artifact indexes.

## 24. Mechanical Implementation Checklist

Use this checklist when implementing T02. A small implementer should be able to
complete the tool by following it in order:

1. Define `NormalizeEventsRequest`, `NormalizationConfig`,
   `NormalizeEventsResult`, `CanonicalEvent`, manifest and descriptor models
   from this document and the shared `LLD.md` schemas.
2. Register all T02 issue codes in the shared issue registry before writing
   normalizer code.
3. Implement path validation that rejects absolute, traversal and symlink
   escape paths outside `run_dir`.
4. Implement T01 manifest loading and descriptor checksum validation.
5. Validate `decoder_result.revision`, source PCAP checksum and artifact
   descriptors against the T01 manifest.
6. Require resolved `ProtocolCodepointRegistry` and partition-policy handles;
   do not load local ad hoc codepoint tables.
7. Create `staging/T02-<uuid>/` and build the final relative output tree
   inside it.
8. Implement atomic JSONL writers for complete, primary, NRF and UDR event
   files.
9. Implement source-reference construction with artifact path, artifact
   checksum, record ID, frame, JSON path or line/byte offset and raw packet
   reference when available.
10. Implement deterministic event ID generation exactly as §5.1 specifies.
11. Implement value normalization helpers for timestamps, decimals, IPs, PLMN,
    FQDN/DNN/header keys, URI templates and hex identifiers.
12. Implement HTTP/2 reader streaming one T01 stream document at a time.
13. Implement HTTP/2 event normalization using §8.4 and never copy full bodies
    into events.
14. Implement NGAP normalization using §9.3.
15. Implement embedded NAS normalization using the protocol registry only.
16. Implement encrypted/undecoded NAS placeholder events.
17. Implement PFCP message normalization using §10.1, emitting one event per
    PFCP message.
18. Preserve routine PFCP heartbeat events.
19. Implement the partition router using §12.4; force NAS/NGAP/PFCP to
    `primary`.
20. Write reserved T02 partition audit attributes on every event.
21. Validate each event; quarantine invalid-but-retainable events instead of
    dropping evidence.
22. Always write every event to `events.jsonl`.
23. Write only non-quarantined events to exactly one partition file.
24. Maintain counters from §7.2 while writing.
25. Build frame, time, protocol, stream, identifier, NRF, UDR and artifact
    indexes without exposing dependency partitions to primary readers.
26. Close, flush and optionally fsync writers before checksumming.
27. Run the streaming invariant validation from §7.2 against staged files.
28. Build artifact descriptors using §14.2.
29. Build the T02 `RevisionEnvelope` from T01 revision, source checksums,
    normalizer version, config, registry, partition policy and output
    descriptors.
30. Build `normalization_manifest.json` using §14.1 and validate it before
    publication.
31. Publish data files first, indexes second and the manifest last.
32. On any fatal error before manifest publication, remove staging and leave
    any prior valid revision untouched.
33. Add unit tests for event ID determinism, value parsing, protocol
    normalizers, partition routing, quarantine behavior and issue-code lint.
34. Add integration tests for complete T01 input, partial T01 input, corrupt
    recoverable records, checksum mismatch, large captures and T18 evidence
    resolution.
35. Add access-control tests proving primary readers cannot read NRF/UDR
    events through event IDs, indexes, cursors or selector expansion.
