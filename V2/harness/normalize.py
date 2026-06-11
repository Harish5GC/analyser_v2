"""T02 normalize_events implementation."""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, DefaultDict, Dict, Iterable, Iterator, Literal
from urllib.parse import parse_qs, urlparse
from uuid import UUID

from pydantic import BaseModel, Field

from harness.decoder.manifest import ArtifactDescriptor, CollectionDescriptor, DecoderManifest
from harness.decoder.runner import DecodeCaptureResult
from harness.decoder.validation import validate_all_artifacts, validate_manifest
from harness.shared import (
    CanonicalEvent,
    Endpoint,
    EventIdentifiers,
    Issue,
    JsonArtifactWriter,
    JsonlArtifactWriter,
    ProtocolCodepointRegistry,
    ResolvedPolicy,
    SourceRef,
    artifact_by_relative_path,
    compact_json_bytes,
    count_jsonl_rows,
    deterministic_uuid,
    first_int_for_suffixes,
    first_string_for_suffixes,
    iter_jsonl,
    parse_decimal,
    publish_closed_artifacts,
    sample_issues,
    sha256_bytes,
    sha256_file,
    timestamp_precision,
    validate_inside_run,
)

NORMALIZER_VERSION = "2.0.0"
SCHEMA_VERSION = "2.0"


class NormalizationConfig(BaseModel):
    canonical_schema_version: Literal["2.0"] = "2.0"
    max_materialized_body_bytes: int = 2_000_000
    max_warning_samples_per_code: int = 20
    fail_on_unknown_schema_version: bool = True
    retain_routine_pfcp_heartbeats: bool = True
    fsync_outputs: bool = True
    expected_release: str | None = None


class NormalizeEventsRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    decoder_result: DecodeCaptureResult
    run_dir: Path
    normalized_dir: Path
    indexes_dir: Path
    protocol_registry: ProtocolCodepointRegistry
    partition_policy: ResolvedPolicy
    enabled_capabilities: set[str] = Field(default_factory=set)
    policy_versions: dict[str, str] = Field(default_factory=dict)
    config: NormalizationConfig = Field(default_factory=NormalizationConfig)


class NormalizeEventsResult(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
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
    issues: list[Issue]
    manifest_path: Path


class PartitionDecision(BaseModel):
    partition: Literal["primary", "nrf", "udr"]
    reason: str
    confidence: Literal["high", "medium", "low"]
    issue: Issue | None = None


class NormalizationManifest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    tool: Literal["T02"] = "T02"
    analysis_id: UUID
    status: Literal["success", "partial", "failed"]
    revision: str
    parent: dict[str, Any]
    normalizer: dict[str, Any]
    protocol_registry: dict[str, Any]
    partition_policy: dict[str, Any]
    counts: dict[str, Any]
    artifacts: list[ArtifactDescriptor]
    indexes: list[ArtifactDescriptor]
    collections: list[CollectionDescriptor] = Field(default_factory=list)
    issues: list[Issue] = Field(default_factory=list)
    timing: dict[str, Any]


class JsonlPrimaryEventReader:
    """Simple JSONL-backed primary partition reader for downstream tools."""

    def __init__(self, revision: str, events_path: Path) -> None:
        self.revision = revision
        self._events: list[CanonicalEvent] = [
            CanonicalEvent.model_validate(record) for record in iter_jsonl(events_path)
        ]
        self._by_id = {event.event_id: event for event in self._events}

    def for_attempt(self, attempt_id: UUID) -> Iterable[CanonicalEvent]:
        return []

    def by_frame(self, start: int, end: int) -> Iterable[CanonicalEvent]:
        for event in self._events:
            if start <= event.frame <= end:
                yield event

    def by_protocol(self, protocol: str) -> Iterable[CanonicalEvent]:
        for event in self._events:
            if event.protocol == protocol:
                yield event

    def by_identifier(self, kind: str, value: str) -> Iterable[CanonicalEvent]:
        for event in self._events:
            if getattr(event.identifiers, kind, None) == value:
                yield event

    def get(self, event_id: UUID) -> CanonicalEvent:
        return self._by_id[event_id]


@dataclass
class _PendingEvent:
    event: CanonicalEvent
    source_record_type: str


@dataclass
class _StreamingIndexes:
    frames: DefaultDict[int, list[str]]
    times: list[dict[str, Any]]
    protocols: DefaultDict[str, list[str]]
    streams: DefaultDict[str, list[str]]
    identifiers: DefaultDict[str, list[str]]
    partitions: DefaultDict[str, list[dict[str, Any]]]
    artifacts: list[dict[str, Any]]
    event_frames: dict[str, int]

    @classmethod
    def create(cls) -> "_StreamingIndexes":
        return cls(
            frames=defaultdict(list),
            times=[],
            protocols=defaultdict(list),
            streams=defaultdict(list),
            identifiers=defaultdict(list),
            partitions=defaultdict(list),
            artifacts=[],
            event_frames={},
        )

    def add(self, event: CanonicalEvent) -> None:
        event_id = str(event.event_id)
        self.event_frames[event_id] = event.frame
        self.frames[event.frame].append(event_id)
        self.times.append(
            {
                "event_id": event_id,
                "timestamp": format(event.timestamp, "f") if event.timestamp is not None else None,
                "frame": event.frame,
            }
        )
        self.protocols[event.protocol].append(event_id)
        stream_key = event.identifiers.http2_key or event.attributes.get("http.uri") or event.attributes.get("ngap.raw_procedure_code")
        if stream_key:
            self.streams[str(stream_key)].append(event_id)
        for field_name, value in event.identifiers.model_dump(exclude_none=True).items():
            self.identifiers[f"{field_name}:{value}"].append(event_id)
        self.partitions[event.partition].append(
            {
                "event_id": event_id,
                "frame": event.frame,
                "message_type": event.message_type,
            }
        )
        self.artifacts.append(
            {
                "event_id": event_id,
                "partition": event.partition,
                "validation_status": event.validation_status,
                "raw_refs": [ref.model_dump(mode="json", exclude_none=True) for ref in event.raw_refs],
            }
        )


def open_primary_event_reader(result: NormalizeEventsResult) -> JsonlPrimaryEventReader:
    primary_desc = artifact_by_relative_path(result.artifacts, "normalized/events/primary_events.jsonl")
    if primary_desc is None:
        raise FileNotFoundError("normalized primary partition artifact descriptor is missing")
    run_dir = result.manifest_path.parents[2]
    return JsonlPrimaryEventReader(result.revision, run_dir / primary_desc.relative_path)


def normalize_events(request: NormalizeEventsRequest) -> NormalizeEventsResult:
    started = datetime.now(tz=timezone.utc)
    validate_inside_run(request.run_dir, request.normalized_dir, request.indexes_dir)
    request.normalized_dir.mkdir(parents=True, exist_ok=True)
    request.indexes_dir.mkdir(parents=True, exist_ok=True)

    t01_manifest = validate_manifest(request.run_dir, request.decoder_result.manifest_path)
    validate_all_artifacts(request.run_dir, t01_manifest)
    _validate_decoder_lineage(request, t01_manifest)
    _validate_decoder_artifact_schemas(t01_manifest)

    staging_root = request.run_dir / "staging" / f"T02-{request.analysis_id}"
    if staging_root.exists():
        for existing in sorted(staging_root.rglob("*"), reverse=True):
            if existing.is_file():
                existing.unlink()
            elif existing.is_dir():
                existing.rmdir()
    staging_root.mkdir(parents=True, exist_ok=True)

    event_writer = JsonlArtifactWriter(staging_root, request.run_dir, "normalized/events/events.jsonl", "canonical_events_complete")
    primary_writer = JsonlArtifactWriter(staging_root, request.run_dir, "normalized/events/primary_events.jsonl", "canonical_events_partition")
    nrf_writer = JsonlArtifactWriter(staging_root, request.run_dir, "normalized/events/nrf_events.jsonl", "canonical_events_partition")
    udr_writer = JsonlArtifactWriter(staging_root, request.run_dir, "normalized/events/udr_events.jsonl", "canonical_events_partition")

    counters = _initial_counters()
    issues: list[Issue] = []
    indexes = _StreamingIndexes.create()

    seen_event_ids: set[UUID] = set()
    for pending in _iter_normalized_events(request, t01_manifest, counters, issues):
        event = _finalize_event(request, pending.event, pending.source_record_type)
        _verify_source_refs(event, t01_manifest)
        if event.event_id in seen_event_ids:
            raise ValueError(f"duplicate event_id {event.event_id}")
        seen_event_ids.add(event.event_id)

        event_writer.write(event)
        indexes.add(event)
        counters["event_count"] += 1
        counters["protocol_counts"][event.protocol] += 1
        if event.validation_status == "quarantined":
            counters["quarantined_count"] += 1
            continue

        counters["partition_counts"][event.partition] += 1
        if event.partition == "primary":
            primary_writer.write(event)
        elif event.partition == "nrf":
            nrf_writer.write(event)
        else:
            udr_writer.write(event)

    event_closed = event_writer.close()
    primary_closed = primary_writer.close()
    nrf_closed = nrf_writer.close()
    udr_closed = udr_writer.close()

    frame_index = [
        {"frame": frame, "event_ids": sorted(event_ids)}
        for frame, event_ids in sorted(indexes.frames.items())
    ]
    time_index = sorted(
        indexes.times,
        key=lambda item: (
            item["timestamp"] is None,
            Decimal(item["timestamp"]) if item["timestamp"] is not None else Decimal(0),
            item["frame"],
            item["event_id"],
        ),
    )
    protocol_index = {protocol: sorted(event_ids) for protocol, event_ids in sorted(indexes.protocols.items())}
    stream_index = {key: sorted(event_ids) for key, event_ids in sorted(indexes.streams.items())}
    identifier_index = {key: sorted(event_ids) for key, event_ids in sorted(indexes.identifiers.items())}
    nrf_index = sorted(indexes.partitions["nrf"], key=lambda item: (item["frame"], item["event_id"]))
    udr_index = sorted(indexes.partitions["udr"], key=lambda item: (item["frame"], item["event_id"]))
    artifact_index = sorted(
        indexes.artifacts,
        key=lambda item: (indexes.event_frames[item["event_id"]], item["event_id"]),
    )

    frame_index_closed = JsonArtifactWriter(staging_root, request.run_dir, "indexes/frame_index.json", "event_index").write(frame_index)
    time_index_closed = JsonArtifactWriter(staging_root, request.run_dir, "indexes/time_index.json", "event_index").write(time_index)
    protocol_index_closed = JsonArtifactWriter(staging_root, request.run_dir, "indexes/protocol_index.json", "event_index").write(protocol_index)
    stream_index_closed = JsonArtifactWriter(staging_root, request.run_dir, "indexes/stream_index.json", "event_index").write(stream_index)
    identifier_index_closed = JsonArtifactWriter(staging_root, request.run_dir, "indexes/identifier_index.json", "event_index").write(identifier_index)
    nrf_index_closed = JsonArtifactWriter(staging_root, request.run_dir, "indexes/nrf_index.json", "event_index").write(nrf_index)
    udr_index_closed = JsonArtifactWriter(staging_root, request.run_dir, "indexes/udr_index.json", "event_index").write(udr_index)
    artifact_index_closed = JsonArtifactWriter(staging_root, request.run_dir, "indexes/artifact_index.json", "event_index").write(artifact_index)

    pre_revision_descriptors = [
        event_closed.descriptor(creation_stage="T02", parent_source_sha256=t01_manifest.source.sha256),
        primary_closed.descriptor(creation_stage="T02", parent_source_sha256=t01_manifest.source.sha256),
        nrf_closed.descriptor(creation_stage="T02", parent_source_sha256=t01_manifest.source.sha256),
        udr_closed.descriptor(creation_stage="T02", parent_source_sha256=t01_manifest.source.sha256),
        frame_index_closed.descriptor(creation_stage="T02", parent_source_sha256=t01_manifest.source.sha256),
        time_index_closed.descriptor(creation_stage="T02", parent_source_sha256=t01_manifest.source.sha256),
        protocol_index_closed.descriptor(creation_stage="T02", parent_source_sha256=t01_manifest.source.sha256),
        stream_index_closed.descriptor(creation_stage="T02", parent_source_sha256=t01_manifest.source.sha256),
        identifier_index_closed.descriptor(creation_stage="T02", parent_source_sha256=t01_manifest.source.sha256),
        nrf_index_closed.descriptor(creation_stage="T02", parent_source_sha256=t01_manifest.source.sha256),
        udr_index_closed.descriptor(creation_stage="T02", parent_source_sha256=t01_manifest.source.sha256),
        artifact_index_closed.descriptor(creation_stage="T02", parent_source_sha256=t01_manifest.source.sha256),
    ]

    revision = _build_t02_revision(request, t01_manifest, pre_revision_descriptors)
    artifacts: list[ArtifactDescriptor] = []
    indexes: list[ArtifactDescriptor] = []
    for descriptor in pre_revision_descriptors:
        descriptor.revision = revision
        if descriptor.relative_path.startswith("indexes/"):
            indexes.append(descriptor)
        else:
            artifacts.append(descriptor)

    _validate_output_counts(request, counters)

    ended = datetime.now(tz=timezone.utc)
    elapsed_ms = int((ended - started).total_seconds() * 1000)
    status: Literal["success", "partial", "failed"] = "partial" if counters["warning_counts"] or counters["quarantined_count"] else "success"

    manifest = NormalizationManifest(
        analysis_id=request.analysis_id,
        status=status,
        revision=revision,
        parent={
            "tool": "T01",
            "revision": request.decoder_result.revision,
            "manifest_sha256": request.decoder_result.manifest.sha256,
            "source_pcap_sha256": t01_manifest.source.sha256,
        },
        normalizer={
            "version": NORMALIZER_VERSION,
            "canonical_schema_version": request.config.canonical_schema_version,
            "config_sha256": sha256_bytes(compact_json_bytes(request.config)),
        },
        protocol_registry={
            "name": request.protocol_registry.registry_name,
            "version": request.protocol_registry.registry_version,
            "sha256": request.protocol_registry.sha256,
        },
        partition_policy={
            "name": request.partition_policy.name,
            "version": request.partition_policy.version,
            "sha256": request.partition_policy.sha256,
        },
        counts={
            "event_count": counters["event_count"],
            "partition_counts": counters["partition_counts"],
            "protocol_counts": counters["protocol_counts"],
            "source_record_counts": counters["source_record_counts"],
            "unknown_field_counts": counters["unknown_field_counts"],
            "warning_counts": counters["warning_counts"],
            "quarantined_count": counters["quarantined_count"],
        },
        artifacts=artifacts,
        indexes=indexes,
        issues=sample_issues(issues, request.config.max_warning_samples_per_code),
        timing={
            "started_at": started.isoformat(),
            "ended_at": ended.isoformat(),
            "elapsed_ms": elapsed_ms,
            "peak_rss_bytes": None,
        },
    )
    manifest_closed = JsonArtifactWriter(
        staging_root,
        request.run_dir,
        "normalized/diagnostics/normalization_manifest.json",
        "normalization_manifest",
    ).write(manifest)
    publish_closed_artifacts(
        request.run_dir,
        [
            event_closed,
            primary_closed,
            nrf_closed,
            udr_closed,
            frame_index_closed,
            time_index_closed,
            protocol_index_closed,
            stream_index_closed,
            identifier_index_closed,
            nrf_index_closed,
            udr_index_closed,
            artifact_index_closed,
            manifest_closed,
        ],
        manifest_relative_path="normalized/diagnostics/normalization_manifest.json",
    )

    manifest_path = request.run_dir / "normalized/diagnostics/normalization_manifest.json"
    manifest_descriptor = ArtifactDescriptor(
        artifact_id=str(deterministic_uuid(request.analysis_id, "T02", "manifest", revision)),
        relative_path="normalized/diagnostics/normalization_manifest.json",
        artifact_type="normalization_manifest",
        media_type="application/json",
        format_schema_version=SCHEMA_VERSION,
        sha256=sha256_file(manifest_path),
        byte_size=manifest_path.stat().st_size,
        record_count=1,
        creation_stage="T02",
        parent_source_sha256=t01_manifest.source.sha256,
        revision=revision,
    )

    return NormalizeEventsResult(
        analysis_id=request.analysis_id,
        status=status,
        revision=revision,
        manifest=manifest_descriptor,
        artifacts=artifacts,
        collections=[],
        event_count=counters["event_count"],
        partition_counts=counters["partition_counts"],
        protocol_counts=counters["protocol_counts"],
        source_record_counts=counters["source_record_counts"],
        unknown_field_counts=counters["unknown_field_counts"],
        warning_counts=counters["warning_counts"],
        elapsed_ms=elapsed_ms,
        issues=manifest.issues,
        manifest_path=manifest_path,
    )


def _initial_counters() -> dict[str, Any]:
    return {
        "event_count": 0,
        "partition_counts": {"primary": 0, "nrf": 0, "udr": 0},
        "protocol_counts": {"HTTP2": 0, "NGAP": 0, "NAS": 0, "PFCP": 0},
        "source_record_counts": defaultdict(int),
        "unknown_field_counts": defaultdict(int),
        "warning_counts": defaultdict(int),
        "quarantined_count": 0,
    }


def _validate_decoder_lineage(request: NormalizeEventsRequest, manifest: DecoderManifest) -> None:
    if manifest.revision != request.decoder_result.revision:
        raise ValueError("decoder result revision does not match decoder manifest revision")
    if manifest.source.sha256 != request.decoder_result.source.sha256:
        raise ValueError("decoder result source checksum does not match manifest source checksum")
    if request.protocol_registry.schema_version != SCHEMA_VERSION:
        raise ValueError(f"unsupported protocol registry schema_version {request.protocol_registry.schema_version!r}")
    if request.config.expected_release is not None and request.protocol_registry.release != request.config.expected_release:
        raise ValueError("protocol registry release does not match expected release")
    registry_version = request.policy_versions.get("protocol_registry")
    if registry_version is not None and registry_version != request.protocol_registry.registry_version:
        raise ValueError("protocol_registry policy version does not match registry_version")
    partition_version = request.policy_versions.get("partition_policy")
    if partition_version is not None and partition_version != request.partition_policy.version:
        raise ValueError("partition_policy policy version does not match resolved policy version")


def _validate_decoder_artifact_schemas(manifest: DecoderManifest) -> None:
    descriptors = [*manifest.artifacts]
    for collection in manifest.collections:
        descriptors.append(collection.index_artifact)
        descriptors.extend(collection.members)
    for descriptor in descriptors:
        if descriptor.format_schema_version != SCHEMA_VERSION:
            raise ValueError(
                f"unsupported decoder artifact schema {descriptor.relative_path}: "
                f"{descriptor.format_schema_version!r}"
            )


def _verify_source_refs(event: CanonicalEvent, manifest: DecoderManifest) -> None:
    descriptors: dict[str, Any] = {item.relative_path: item for item in manifest.artifacts}
    for collection in manifest.collections:
        descriptors.update({item.relative_path: item for item in collection.members})
    if not event.raw_refs:
        raise ValueError(f"normalized event {event.event_id} has no source reference")
    for source_ref in event.raw_refs:
        descriptor = descriptors.get(source_ref.decoder_file)
        if descriptor is None:
            raise ValueError(f"source reference points to undeclared artifact {source_ref.decoder_file}")
        if source_ref.artifact_sha256 != descriptor.sha256:
            raise ValueError(f"source reference checksum mismatch for {source_ref.decoder_file}")
        if source_ref.frame != event.frame:
            raise ValueError(f"source reference frame mismatch for event {event.event_id}")


def _iter_normalized_events(
    request: NormalizeEventsRequest,
    manifest: DecoderManifest,
    counters: dict[str, Any],
    issues: list[Issue],
) -> Iterator[_PendingEvent]:
    http2_collections = sorted(
        [collection for collection in manifest.collections if collection.artifact_type == "http2_stream_collection"],
        key=lambda item: item.relative_dir,
    )
    for collection in http2_collections:
        for member in sorted(collection.members, key=lambda item: item.relative_path):
            counters["source_record_counts"]["http2_stream"] += 1
            member_path = request.run_dir / member.relative_path
            try:
                stream_doc = json.loads(member_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                _count_warning(counters, issues, Issue(code="T02_MALFORMED_HTTP2_DOCUMENT", stage="T02", message=f"{member.relative_path}: {exc}"))
                counters["quarantined_count"] += 1
                continue
            if not isinstance(stream_doc, dict):
                _count_warning(counters, issues, Issue(code="T02_INVALID_HTTP2_DOCUMENT", stage="T02", message=f"{member.relative_path}: document must be an object"))
                counters["quarantined_count"] += 1
                continue
            pending = _normalize_http2_document(request, collection, member, stream_doc, counters, issues)
            if pending is not None:
                yield pending

    ngap_desc = next(
        (artifact for artifact in manifest.artifacts if artifact.artifact_type == "ngap_messages"),
        None,
    )
    if ngap_desc is not None:
        for record in _iter_jsonl_isolated(request.run_dir / ngap_desc.relative_path, "NGAP", counters, issues):
            counters["source_record_counts"]["ngap_message"] += 1
            for pending in _normalize_ngap_record(request, ngap_desc, record, counters, issues):
                yield pending

    pfcp_desc = next(
        (artifact for artifact in manifest.artifacts if artifact.artifact_type == "pfcp_messages"),
        None,
    )
    if pfcp_desc is not None:
        for record in _iter_jsonl_isolated(request.run_dir / pfcp_desc.relative_path, "PFCP", counters, issues):
            counters["source_record_counts"]["pfcp_message"] += 1
            pending = _normalize_pfcp_record(request, pfcp_desc, record, counters, issues)
            if pending is not None:
                yield pending


def _iter_jsonl_isolated(
    path: Path,
    protocol: str,
    counters: dict[str, Any],
    issues: list[Issue],
) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                _count_warning(counters, issues, Issue(code=f"T02_MALFORMED_{protocol}_JSONL", stage="T02", message=f"{path.name}:{line_number}: {exc.msg}"))
                counters["quarantined_count"] += 1
                continue
            if not isinstance(record, dict):
                _count_warning(counters, issues, Issue(code=f"T02_INVALID_{protocol}_RECORD", stage="T02", message=f"{path.name}:{line_number}: record must be an object"))
                counters["quarantined_count"] += 1
                continue
            yield record


def _validate_source_schema(
    request: NormalizeEventsRequest,
    record: dict[str, Any],
    protocol: str,
    counters: dict[str, Any],
    issues: list[Issue],
) -> bool:
    schema_version = record.get("schema_version")
    if schema_version == SCHEMA_VERSION:
        return True
    message = f"{protocol} record schema_version {schema_version!r} is not supported"
    if request.config.fail_on_unknown_schema_version:
        raise ValueError(message)
    _count_warning(counters, issues, Issue(code="T02_UNSUPPORTED_SOURCE_SCHEMA", stage="T02", message=message))
    counters["quarantined_count"] += 1
    return False


def _optional_uuid(
    value: Any,
    counters: dict[str, Any],
    issues: list[Issue],
    protocol: str,
) -> UUID | None:
    if value in {None, ""}:
        _count_warning(counters, issues, Issue(code="T02_MISSING_SOURCE_RECORD_ID", stage="T02", message=f"{protocol} source record has no record_id"))
        return None
    try:
        return UUID(str(value))
    except ValueError:
        _count_warning(counters, issues, Issue(code="T02_INVALID_SOURCE_RECORD_ID", stage="T02", message=f"{protocol} source record_id is not a UUID"))
        return None


def _normalized_headers(headers: Any) -> list[dict[str, Any]]:
    if not isinstance(headers, list):
        return []
    return [
        {
            "name": str(header.get("name", "")),
            "value": header.get("value"),
            "frame": header.get("frame"),
        }
        for header in headers
        if isinstance(header, dict)
    ]


def _normalize_http2_document(
    request: NormalizeEventsRequest,
    collection: CollectionDescriptor,
    member: Any,
    doc: dict[str, Any],
    counters: dict[str, Any],
    issues: list[Issue],
) -> _PendingEvent | None:
    del collection
    if not _validate_source_schema(request, doc, "HTTP2", counters, issues):
        return None
    transport = doc.get("transport") or {}
    request_side = doc.get("request") or {}
    response_side = doc.get("response") or {}
    completion = doc.get("completion") or {}
    request_headers = request_side.get("headers") or []
    response_headers = response_side.get("headers") or []
    method = request_side.get("method") or _header_value(request_headers, ":method")
    uri = request_side.get("uri") or _header_value(request_headers, ":path") or ""
    status = response_side.get("status")
    frame = request_side.get("start_frame") or response_side.get("start_frame")
    if frame is None:
        return None
    timestamp = request_side.get("start_time_epoch") or response_side.get("start_time_epoch")
    parsed_uri = urlparse(uri) if uri else None
    path = parsed_uri.path if parsed_uri else ""
    api = _infer_sbi_api(path)
    query = parse_qs(parsed_uri.query) if parsed_uri and parsed_uri.query else {}
    identifiers = EventIdentifiers(
        http2_key=str(transport.get("original_key") or ""),
        correlation_id=_first_header(request_headers, response_headers, names=("3gpp-sbi-correlation-info", "x-correlation-id")),
        sm_context_ref=_extract_sm_context_ref(uri),
        charging_id=_first_header(request_headers, response_headers, names=("3gpp-sbi-message-priority", "x-charging-id")),
    )
    if not identifiers.http2_key:
        identifiers.http2_key = None

    body_summary = _body_summary(request_side.get("body"), request.config.max_materialized_body_bytes)
    response_body_summary = _body_summary(response_side.get("body"), request.config.max_materialized_body_bytes)
    doc_id = doc.get("document_id") or ""
    event_id = deterministic_uuid(
        request.analysis_id,
        request.decoder_result.revision,
        member.sha256,
        doc_id,
        "http2_stream",
        0,
        request.protocol_registry.sha256,
    )
    event = CanonicalEvent(
        event_id=event_id,
        analysis_id=request.analysis_id,
        protocol="HTTP2",
        frame=int(frame),
        timestamp=parse_decimal(timestamp),
        timestamp_precision=timestamp_precision(timestamp),
        src=_endpoint_from_http_side(transport.get("client")),
        dst=_endpoint_from_http_side(transport.get("server")),
        direction="NF_TO_NF",
        message_type=f"{method or 'HTTP2'} {path or uri or 'HTTP2_STREAM'}".strip(),
        procedure=api or None,
        outcome=_http2_outcome(status, completion),
        identifiers=identifiers,
        attributes={
            "http.method": method,
            "http.uri": uri,
            "http.path": path,
            "http.query": query or None,
            "http.status": status,
            "http.sbi_api": api,
            "http.completion_state": completion.get("state"),
            "http.request_headers": _normalized_headers(request_headers),
            "http.response_headers": _normalized_headers(response_headers),
            "http.request_body": body_summary or None,
            "http.response_body": response_body_summary or None,
        },
        raw_refs=[
            SourceRef(
                decoder_file=member.relative_path,
                json_path="$",
                frame=int(frame),
                record_id=_optional_uuid(doc_id, counters, issues, "HTTP2") if doc_id else None,
                artifact_sha256=member.sha256,
            )
        ],
    )
    return _PendingEvent(event=event, source_record_type="http2_stream")


def _normalize_ngap_record(
    request: NormalizeEventsRequest,
    descriptor: ArtifactDescriptor,
    record: dict[str, Any],
    counters: dict[str, Any],
    issues: list[Issue],
) -> Iterator[_PendingEvent]:
    if not _validate_source_schema(request, record, "NGAP", counters, issues):
        return
    if record.get("frame") is None or not isinstance(record.get("ngap"), dict):
        _count_warning(counters, issues, Issue(code="T02_INVALID_NGAP_RECORD", stage="T02", message="NGAP record lacks frame or NGAP object"))
        counters["quarantined_count"] += 1
        return
    ngap_tree = record.get("ngap")
    frame = int(record["frame"])
    identifiers = EventIdentifiers()
    if found := first_string_for_suffixes(ngap_tree, ["amfuengapid", "amf-ue-ngap-id"]):
        _, identifiers.amf_ue_ngap_id = found
    if found := first_string_for_suffixes(ngap_tree, ["ranuengapid", "ran-ue-ngap-id"]):
        _, identifiers.ran_ue_ngap_id = found
    if found := first_int_for_suffixes(ngap_tree, ["pdusessionid", "pdu-session-id"]):
        _, identifiers.pdu_session_id = found
    procedure_code = first_string_for_suffixes(ngap_tree, ["procedurecode"])
    pdu_class = _detect_ngap_class(ngap_tree)
    raw_code = procedure_code[1] if procedure_code else None
    if raw_code is not None:
        message_type = request.protocol_registry.ngap_procedures.get(raw_code, f"NGAP_UNKNOWN_{raw_code}")
        if raw_code not in request.protocol_registry.ngap_procedures:
            _count_warning(counters, issues, Issue(code="T02_UNKNOWN_NGAP_PROCEDURE", stage="T02", message=f"unknown NGAP procedure code {raw_code}"))
    else:
        message_type = "NGAP_PDU"
    event_id = deterministic_uuid(
        request.analysis_id,
        request.decoder_result.revision,
        descriptor.sha256,
        record.get("record_id"),
        "ngap",
        0,
        request.protocol_registry.sha256,
    )
    event = CanonicalEvent(
        event_id=event_id,
        analysis_id=request.analysis_id,
        protocol="NGAP",
        frame=frame,
        timestamp=parse_decimal(record.get("time_epoch")),
        timestamp_precision=timestamp_precision(record.get("time_epoch")),
        src=Endpoint(ip=record.get("transport", {}).get("src_ip"), port=record.get("transport", {}).get("src_port")),
        dst=Endpoint(ip=record.get("transport", {}).get("dst_ip"), port=record.get("transport", {}).get("dst_port")),
        direction="UNKNOWN",
        message_type=message_type,
        procedure=message_type,
        outcome=_ngap_outcome(pdu_class),
        identifiers=identifiers,
        attributes={
            "ngap.pdu_class": pdu_class,
            "ngap.raw_procedure_code": raw_code,
            "ngap.cause": _first_value_only(ngap_tree, ["cause", "ngap.cause"]),
        },
        raw_refs=[
            SourceRef(
                decoder_file=descriptor.relative_path,
                json_path="$",
                frame=frame,
                record_id=_optional_uuid(record.get("record_id"), counters, issues, "NGAP"),
                artifact_sha256=descriptor.sha256,
            )
        ],
    )
    yield _PendingEvent(event=event, source_record_type="ngap_message")

    nas_tree = record.get("nas")
    if nas_tree is not None:
        counters["source_record_counts"]["nas_embedded"] += 1
        nas_event = _normalize_nas_tree(request, descriptor, record, nas_tree, identifiers, counters, issues)
        if nas_event is not None:
            yield _PendingEvent(event=nas_event, source_record_type="nas_embedded")


def _normalize_nas_tree(
    request: NormalizeEventsRequest,
    descriptor: ArtifactDescriptor,
    record: dict[str, Any],
    nas_tree: Any,
    inherited: EventIdentifiers,
    counters: dict[str, Any],
    issues: list[Issue],
) -> CanonicalEvent | None:
    msg_match = (
        first_string_for_suffixes(nas_tree, ["message_type", "mmmessage", "gsmmessage"])
        or first_string_for_suffixes(nas_tree, ["nas5gs.mm.message_type", "nas5gs.sm.message_type"])
    )
    raw_code = msg_match[1] if msg_match else None
    if raw_code is not None:
        message_type = request.protocol_registry.nas_message_types.get(raw_code, f"NAS_UNKNOWN_{raw_code}")
        if raw_code not in request.protocol_registry.nas_message_types:
            _count_warning(counters, issues, Issue(code="T02_UNKNOWN_NAS_MESSAGE", stage="T02", message=f"unknown NAS message type {raw_code}"))
    else:
        message_type = "NAS_PDU"
    identifiers = inherited.model_copy(deep=True)
    for field_name, suffixes in (
        ("suci", ["suci"]),
        ("supi", ["supi"]),
        ("gpsi", ["gpsi"]),
        ("guti", ["guti"]),
        ("pei", ["pei", "imei", "imeisv"]),
    ):
        if getattr(identifiers, field_name) is None:
            found = first_string_for_suffixes(nas_tree, suffixes)
            if found is not None:
                setattr(identifiers, field_name, found[1])
    if identifiers.pdu_session_id is None and (found := first_int_for_suffixes(nas_tree, ["pdusessionid", "pdu-session-id"])):
        _, identifiers.pdu_session_id = found
    if identifiers.procedure_transaction_id is None and (found := first_int_for_suffixes(nas_tree, ["pti", "proceduretransactionidentity"])):
        _, identifiers.procedure_transaction_id = found

    issue_list: list[Issue] = []
    visibility = None
    if raw_code is None:
        visibility = "encrypted_or_unparsed"
        issue_list.append(Issue(code="T02_NAS_VISIBILITY_LIMITED", stage="T02", message="NAS message type was not visible"))
        _count_warning(counters, issues, issue_list[-1])
    event_id = deterministic_uuid(
        request.analysis_id,
        request.decoder_result.revision,
        descriptor.sha256,
        record.get("record_id"),
        "nas",
        1,
        request.protocol_registry.sha256,
    )
    return CanonicalEvent(
        event_id=event_id,
        analysis_id=request.analysis_id,
        protocol="NAS",
        frame=int(record["frame"]),
        timestamp=parse_decimal(record.get("time_epoch")),
        timestamp_precision=timestamp_precision(record.get("time_epoch")),
        src=Endpoint(ip=record.get("transport", {}).get("src_ip"), port=record.get("transport", {}).get("src_port")),
        dst=Endpoint(ip=record.get("transport", {}).get("dst_ip"), port=record.get("transport", {}).get("dst_port")),
        direction="UNKNOWN",
        message_type=message_type,
        procedure=message_type,
        outcome="unknown",
        identifiers=identifiers,
        attributes={
            "nas.raw_message_type": raw_code,
            "nas.visibility": visibility,
            "nas.cause": _first_value_only(nas_tree, ["cause", "rejectcause"]),
        },
        raw_refs=[
            SourceRef(
                decoder_file=descriptor.relative_path,
                json_path="$.nas",
                frame=int(record["frame"]),
                record_id=_optional_uuid(record.get("record_id"), counters, issues, "NAS"),
                artifact_sha256=descriptor.sha256,
            )
        ],
        issues=issue_list,
    )


def _normalize_pfcp_record(
    request: NormalizeEventsRequest,
    descriptor: ArtifactDescriptor,
    record: dict[str, Any],
    counters: dict[str, Any],
    issues: list[Issue],
) -> _PendingEvent | None:
    if not _validate_source_schema(request, record, "PFCP", counters, issues):
        return None
    if record.get("frame") is None or not isinstance(record.get("pfcp"), dict):
        _count_warning(counters, issues, Issue(code="T02_INVALID_PFCP_RECORD", stage="T02", message="PFCP record lacks frame or PFCP object"))
        counters["quarantined_count"] += 1
        return None
    pfcp_tree = record.get("pfcp")
    raw_msg_type = str(record.get("msg_type")) if record.get("msg_type") is not None else None
    if raw_msg_type is not None:
        message_type = request.protocol_registry.pfcp_message_types.get(raw_msg_type, f"PFCP_UNKNOWN_{raw_msg_type}")
        if raw_msg_type not in request.protocol_registry.pfcp_message_types:
            _count_warning(counters, issues, Issue(code="T02_UNKNOWN_PFCP_MESSAGE", stage="T02", message=f"unknown PFCP message type {raw_msg_type}"))
    else:
        message_type = "PFCP_MESSAGE"
    identifiers = EventIdentifiers()
    if record.get("seq_num") is not None:
        try:
            identifiers.pfcp_sequence = int(str(record["seq_num"]), 10)
        except ValueError:
            pass
    for field_name, suffixes in (
        ("cp_seid", ["cpseid", "cp-f-seid", "f-seid"]),
        ("up_seid", ["upseid", "up-f-seid"]),
        ("ue_ip", ["ueip", "ue-ip-address"]),
        ("charging_id", ["chargingid", "charging-id"]),
    ):
        found = first_string_for_suffixes(pfcp_tree, suffixes)
        if found is not None:
            setattr(identifiers, field_name, found[1])
    if found := first_int_for_suffixes(pfcp_tree, ["pdusessionid", "pdu-session-id"]):
        _, identifiers.pdu_session_id = found

    routine = bool(record.get("is_heartbeat"))
    if routine and not request.config.retain_routine_pfcp_heartbeats:
        return None

    event_id = deterministic_uuid(
        request.analysis_id,
        request.decoder_result.revision,
        descriptor.sha256,
        record.get("record_id"),
        "pfcp",
        0,
        request.protocol_registry.sha256,
    )
    event = CanonicalEvent(
        event_id=event_id,
        analysis_id=request.analysis_id,
        protocol="PFCP",
        frame=int(record["frame"]),
        timestamp=parse_decimal(record.get("time_epoch")),
        timestamp_precision=timestamp_precision(record.get("time_epoch")),
        src=Endpoint(ip=record.get("transport", {}).get("src_ip"), port=record.get("transport", {}).get("src_port")),
        dst=Endpoint(ip=record.get("transport", {}).get("dst_ip"), port=record.get("transport", {}).get("dst_port")),
        direction="NF_TO_NF",
        message_type=message_type,
        procedure=message_type,
        outcome=_pfcp_outcome(record),
        identifiers=identifiers,
        attributes={
            "pfcp.raw_message_type": raw_msg_type,
            "pfcp.routine": routine,
            "pfcp.response_in": record.get("response_in"),
            "pfcp.response_to": record.get("response_to"),
            "pfcp.seid": record.get("seid"),
            "pfcp.cause": _first_value_only(pfcp_tree, ["cause", "pfcp.cause"]),
        },
        raw_refs=[
            SourceRef(
                decoder_file=descriptor.relative_path,
                json_path="$",
                frame=int(record["frame"]),
                record_id=_optional_uuid(record.get("record_id"), counters, issues, "PFCP"),
                artifact_sha256=descriptor.sha256,
            )
        ],
    )
    return _PendingEvent(event=event, source_record_type="pfcp_message")


def _finalize_event(request: NormalizeEventsRequest, event: CanonicalEvent, source_record_type: str) -> CanonicalEvent:
    issue_list = list(event.issues)
    decision = _route_event(event, request.partition_policy)
    if decision.issue is not None:
        issue_list.append(decision.issue)
    attributes = dict(event.attributes)
    attributes["t02.partition_reason"] = decision.reason
    attributes["t02.partition_confidence"] = decision.confidence
    attributes["t02.source_record_type"] = source_record_type
    attributes["t02.protocol_registry_version"] = request.protocol_registry.registry_version
    attributes["t02.partition_policy_version"] = request.partition_policy.version
    status = "partial" if issue_list else "valid"
    if event.message_type == "":
        status = "quarantined"
        issue_list.append(Issue(code="T02_INVALID_EVENT", stage="T02", message="empty message_type"))
    return event.model_copy(
        update={
            "partition": decision.partition,
            "attributes": attributes,
            "validation_status": status,
            "issues": issue_list,
        }
    )


def _route_event(event: CanonicalEvent, policy: ResolvedPolicy) -> PartitionDecision:
    if event.protocol in {"NAS", "NGAP", "PFCP"}:
        return PartitionDecision(partition="primary", reason="protocol_primary", confidence="high")

    payload = policy.payload if isinstance(policy.payload, dict) else {}
    api = str(event.attributes.get("http.sbi_api") or "").lower()
    producer = str(event.attributes.get("http.producer_nf_type") or "").upper()
    consumer = str(event.attributes.get("http.consumer_nf_type") or "").upper()
    nrf_apis = {str(item).lower() for item in payload.get("nrf_apis", ["nnrf-nfm", "nnrf-disc"])}
    udr_apis = {str(item).lower() for item in payload.get("udr_apis", ["nudr-dr", "nudr-group-id-map"])}
    nrf_nf_types = {str(item).upper() for item in payload.get("nrf_nf_types", ["NRF"])}
    udr_nf_types = {str(item).upper() for item in payload.get("udr_nf_types", ["UDR"])}

    if api in nrf_apis or producer in nrf_nf_types or consumer in nrf_nf_types:
        return PartitionDecision(partition="nrf", reason="dependency_partition_nrf", confidence="high")
    if api in udr_apis or producer in udr_nf_types or consumer in udr_nf_types:
        return PartitionDecision(partition="udr", reason="dependency_partition_udr", confidence="high")
    if api.startswith("nnrf") or api.startswith("nudr"):
        return PartitionDecision(
            partition="primary",
            reason="ambiguous_dependency_partition",
            confidence="low",
            issue=Issue(code="T02_AMBIGUOUS_DEPENDENCY_PARTITION", stage="T02", message=f"ambiguous HTTP/2 dependency routing for api {api}"),
        )
    return PartitionDecision(partition="primary", reason="default_primary", confidence="medium")


def _build_t02_revision(
    request: NormalizeEventsRequest,
    manifest: DecoderManifest,
    descriptors: Iterable[ArtifactDescriptor],
) -> str:
    payload = {
        "tool": "T02",
        "tool_version": NORMALIZER_VERSION,
        "schema_version": SCHEMA_VERSION,
        "analysis_id": str(request.analysis_id),
        "t01_revision": request.decoder_result.revision,
        "t01_manifest_sha256": request.decoder_result.manifest.sha256,
        "source_sha256": manifest.source.sha256,
        "registry": request.protocol_registry.model_dump(mode="json"),
        "partition_policy": request.partition_policy.model_dump(mode="json"),
        "config": request.config.model_dump(mode="json"),
        "capabilities": sorted(request.enabled_capabilities),
        "descriptors": [
            {
                "relative_path": descriptor.relative_path,
                "artifact_type": descriptor.artifact_type,
                "sha256": descriptor.sha256,
                "byte_size": descriptor.byte_size,
                "record_count": descriptor.record_count,
            }
            for descriptor in sorted(descriptors, key=lambda item: item.relative_path)
        ],
    }
    return f"sha256:{sha256_bytes(compact_json_bytes(payload))}"


def _validate_output_counts(request: NormalizeEventsRequest, counters: dict[str, Any]) -> None:
    checks = {
        "normalized/events/events.jsonl": counters["event_count"],
        "normalized/events/primary_events.jsonl": counters["partition_counts"]["primary"],
        "normalized/events/nrf_events.jsonl": counters["partition_counts"]["nrf"],
        "normalized/events/udr_events.jsonl": counters["partition_counts"]["udr"],
    }
    for relative_path, expected in checks.items():
        actual = count_jsonl_rows(request.run_dir / "staging" / f"T02-{request.analysis_id}" / relative_path)
        if actual != expected:
            raise ValueError(f"record count mismatch for {relative_path}: expected {expected}, got {actual}")


def _build_frame_index(events: list[CanonicalEvent]) -> list[dict[str, Any]]:
    buckets: DefaultDict[int, list[str]] = defaultdict(list)
    for event in events:
        buckets[event.frame].append(str(event.event_id))
    return [
        {"frame": frame, "event_ids": sorted(event_ids)}
        for frame, event_ids in sorted(buckets.items())
    ]


def _build_time_index(events: list[CanonicalEvent]) -> list[dict[str, Any]]:
    return [
        {
            "event_id": str(event.event_id),
            "timestamp": format(event.timestamp, "f") if event.timestamp is not None else None,
            "frame": event.frame,
        }
        for event in sorted(events, key=lambda item: ((item.timestamp is None), item.timestamp or Decimal(0), item.frame, str(item.event_id)))
    ]


def _build_protocol_index(events: list[CanonicalEvent]) -> dict[str, list[str]]:
    buckets: DefaultDict[str, list[str]] = defaultdict(list)
    for event in events:
        buckets[event.protocol].append(str(event.event_id))
    return {protocol: sorted(event_ids) for protocol, event_ids in sorted(buckets.items())}


def _build_stream_index(events: list[CanonicalEvent]) -> dict[str, list[str]]:
    buckets: DefaultDict[str, list[str]] = defaultdict(list)
    for event in events:
        key = event.identifiers.http2_key or event.attributes.get("http.uri") or event.attributes.get("ngap.raw_procedure_code")
        if key:
            buckets[str(key)].append(str(event.event_id))
    return {key: sorted(event_ids) for key, event_ids in sorted(buckets.items())}


def _build_identifier_index(events: list[CanonicalEvent]) -> dict[str, list[str]]:
    buckets: DefaultDict[str, list[str]] = defaultdict(list)
    for event in events:
        for field_name, value in event.identifiers.model_dump(exclude_none=True).items():
            buckets[f"{field_name}:{value}"].append(str(event.event_id))
    return {key: sorted(event_ids) for key, event_ids in sorted(buckets.items())}


def _build_partition_index(events: list[CanonicalEvent]) -> list[dict[str, Any]]:
    return [
        {
            "event_id": str(event.event_id),
            "frame": event.frame,
            "message_type": event.message_type,
        }
        for event in sorted(events, key=lambda item: (item.frame, str(item.event_id)))
    ]


def _build_artifact_index(events: list[CanonicalEvent]) -> list[dict[str, Any]]:
    return [
        {
            "event_id": str(event.event_id),
            "partition": event.partition,
            "validation_status": event.validation_status,
            "raw_refs": [ref.model_dump(mode="json", exclude_none=True) for ref in event.raw_refs],
        }
        for event in sorted(events, key=lambda item: (item.frame, str(item.event_id)))
    ]


def _first_header(*header_lists: list[dict[str, Any]], names: Iterable[str]) -> str | None:
    lowered = {name.lower() for name in names}
    for headers in header_lists:
        for header in headers or []:
            if str(header.get("name", "")).lower() in lowered:
                value = header.get("value")
                if value is not None:
                    return str(value)
    return None


def _header_value(headers: list[dict[str, Any]], name: str) -> str | None:
    for header in headers or []:
        if str(header.get("name")) == name:
            value = header.get("value")
            if value is not None:
                return str(value)
    return None


def _body_summary(body: Any, limit: int) -> dict[str, Any] | None:
    if not isinstance(body, dict):
        return None
    summary = {
        "byte_length": body.get("byte_length"),
        "sha256": body.get("sha256"),
        "content_type": body.get("content_type"),
    }
    decoded_json = body.get("decoded_json")
    if decoded_json is not None:
        raw = compact_json_bytes(decoded_json)
        if len(raw) <= limit:
            summary["decoded_json"] = decoded_json
    if body.get("multipart") is not None:
        summary["multipart"] = {"parts": len(body.get("multipart", []))}
    return summary


def _endpoint_from_http_side(value: Any) -> Endpoint | None:
    if not isinstance(value, dict):
        return None
    return Endpoint(ip=value.get("ip"), port=value.get("port"))


def _http2_outcome(status: Any, completion: dict[str, Any]) -> Literal["request", "success", "failure", "notification", "unknown"]:
    if completion.get("state") == "response_only":
        return "unknown"
    if status is None:
        return "unknown"
    try:
        code = int(status)
    except (TypeError, ValueError):
        return "unknown"
    if 200 <= code <= 399:
        return "success"
    if 400 <= code <= 599:
        return "failure"
    return "unknown"


def _infer_sbi_api(path: str) -> str | None:
    segments = [segment for segment in path.split("/") if segment]
    if not segments:
        return None
    return segments[0]


def _extract_sm_context_ref(uri: str) -> str | None:
    if "/sm-contexts/" not in uri:
        return None
    return uri.rsplit("/sm-contexts/", 1)[-1].split("/", 1)[0] or None


def _detect_ngap_class(ngap_tree: Any) -> str:
    text = json.dumps(ngap_tree).lower()
    if "successfuloutcome" in text:
        return "successfulOutcome"
    if "unsuccessfuloutcome" in text:
        return "unsuccessfulOutcome"
    if "initiatingmessage" in text:
        return "initiatingMessage"
    return "unknown"


def _ngap_outcome(pdu_class: str) -> Literal["request", "success", "failure", "notification", "unknown"]:
    if pdu_class == "initiatingMessage":
        return "request"
    if pdu_class == "successfulOutcome":
        return "success"
    if pdu_class == "unsuccessfulOutcome":
        return "failure"
    return "unknown"


def _pfcp_outcome(record: dict[str, Any]) -> Literal["request", "success", "failure", "notification", "unknown"]:
    if record.get("response_to") is not None:
        cause = json.dumps(record.get("pfcp", {})).lower()
        if "reject" in cause or "failure" in cause or "error" in cause:
            return "failure"
        return "success"
    if record.get("response_in") is not None:
        return "request"
    return "unknown"


def _count_warning(counters: dict[str, Any], issues: list[Issue], issue: Issue) -> None:
    counters["warning_counts"][issue.code] += 1
    issues.append(issue)


def _first_value_only(value: Any, suffixes: Iterable[str]) -> str | None:
    found = first_string_for_suffixes(value, suffixes)
    return found[1] if found is not None else None
