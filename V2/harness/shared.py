"""Shared models and IO helpers for post-decode harness stages."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
from collections import defaultdict
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, DefaultDict, Dict, Iterable, Iterator, Literal
from uuid import UUID, uuid4, uuid5

from pydantic import BaseModel, Field

from harness.decoder.manifest import ArtifactDescriptor, CollectionDescriptor

JsonValue = Any


class Issue(BaseModel):
    code: str
    severity: Literal["info", "warning", "error"] = "warning"
    stage: str
    message: str


class Endpoint(BaseModel):
    ip: str | None = None
    port: int | None = None


class SourceRef(BaseModel):
    decoder_file: str
    json_path: str
    frame: int
    field_path: str | None = None
    original_value: JsonValue | None = None
    record_id: UUID | None = None
    byte_offset: int | None = None
    byte_length: int | None = None
    artifact_sha256: str


class EventIdentifiers(BaseModel):
    supi: str | None = None
    suci: str | None = None
    gpsi: str | None = None
    guti: str | None = None
    pei: str | None = None
    amf_ue_ngap_id: str | None = None
    ran_ue_ngap_id: str | None = None
    pdu_session_id: int | None = None
    procedure_transaction_id: int | None = None
    http2_key: str | None = None
    correlation_id: str | None = None
    sm_context_ref: str | None = None
    pfcp_sequence: int | None = None
    cp_seid: str | None = None
    up_seid: str | None = None
    ue_ip: str | None = None
    charging_id: str | None = None


class CanonicalEvent(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    event_id: UUID
    analysis_id: UUID
    protocol: Literal["NAS", "NGAP", "HTTP2", "PFCP"]
    frame: int
    timestamp: Decimal | None = None
    timestamp_precision: Literal[
        "seconds", "milliseconds", "microseconds", "nanoseconds", "unknown"
    ] = "unknown"
    src: Endpoint | None = None
    dst: Endpoint | None = None
    direction: Literal["UE_TO_NETWORK", "NETWORK_TO_UE", "NF_TO_NF", "UNKNOWN"]
    message_type: str
    procedure: str | None = None
    outcome: Literal["request", "success", "failure", "notification", "unknown"]
    identifiers: EventIdentifiers = Field(default_factory=EventIdentifiers)
    attributes: dict[str, JsonValue] = Field(default_factory=dict)
    raw_refs: list[SourceRef] = Field(default_factory=list)
    partition: Literal["primary", "nrf", "udr"] = "primary"
    validation_status: Literal["valid", "partial", "quarantined"] = "valid"
    issues: list[Issue] = Field(default_factory=list)


class ProtocolCodepointRegistry(BaseModel):
    registry_name: str
    registry_version: str
    schema_version: str
    sha256: str
    release: str | None = None
    nas_message_types: dict[str, str] = Field(default_factory=dict)
    nas_causes: dict[str, str] = Field(default_factory=dict)
    ngap_procedures: dict[str, str] = Field(default_factory=dict)
    ngap_causes: dict[str, str] = Field(default_factory=dict)
    pfcp_message_types: dict[str, str] = Field(default_factory=dict)
    pfcp_causes: dict[str, str] = Field(default_factory=dict)


class ResolvedPolicy(BaseModel):
    name: str
    version: str
    sha256: str
    payload: dict[str, JsonValue] = Field(default_factory=dict)


class CaptureMetadata(BaseModel):
    first_frame: int
    last_frame: int
    first_timestamp: Decimal | None = None
    last_timestamp: Decimal | None = None
    packet_count: int
    source_sha256: str


def _json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value)!r} is not JSON serializable")


def to_jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Path):
        return str(value)
    return value


def compact_json_bytes(value: Any, *, sort_keys: bool = True) -> bytes:
    return json.dumps(
        to_jsonable(value),
        sort_keys=sort_keys,
        separators=(",", ":"),
        ensure_ascii=True,
        default=_json_default,
    ).encode("utf-8")


def pretty_json_bytes(value: Any) -> bytes:
    return json.dumps(
        to_jsonable(value),
        sort_keys=True,
        indent=2,
        ensure_ascii=True,
        default=_json_default,
    ).encode("utf-8") + b"\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def deterministic_uuid(namespace: UUID | str, *parts: object) -> UUID:
    ns = namespace if isinstance(namespace, UUID) else UUID(str(namespace))
    text = "\x1f".join(str(part) for part in parts)
    return uuid5(ns, text)


def validate_inside_run(run_dir: Path, *paths: Path) -> None:
    run_root = run_dir.resolve()
    for path in paths:
        resolved = path.resolve()
        try:
            resolved.relative_to(run_root)
        except ValueError as exc:
            raise ValueError(f"path {path} resolves outside run dir {run_root}") from exc


def relative_to_run(run_dir: Path, path: Path) -> str:
    return path.resolve().relative_to(run_dir.resolve()).as_posix()


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def parse_decimal(value: Any) -> Decimal | None:
    if value is None or value == "":
        return None
    if isinstance(value, Decimal):
        return value
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def timestamp_precision(value: Any) -> Literal[
    "seconds", "milliseconds", "microseconds", "nanoseconds", "unknown"
]:
    if value is None:
        return "unknown"
    text = str(value)
    if "." not in text:
        return "seconds"
    digits = len(text.split(".", 1)[1].rstrip("0"))
    if digits <= 0:
        return "seconds"
    if digits <= 3:
        return "milliseconds"
    if digits <= 6:
        return "microseconds"
    return "nanoseconds"


def normalized_key(key: str) -> str:
    return "".join(ch for ch in key.lower() if ch.isalnum())


def iter_key_values(value: Any, path: str = "$") -> Iterator[tuple[str, str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            yield key, child_path, child
            yield from iter_key_values(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            yield from iter_key_values(child, child_path)


def _stringify_leaf(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (str, int, float, Decimal, bool)):
        return str(value)
    if isinstance(value, list) and len(value) == 1:
        return _stringify_leaf(value[0])
    return None


def first_value_for_suffixes(value: Any, suffixes: Iterable[str]) -> tuple[str, Any] | None:
    normalized_suffixes = [normalized_key(suffix) for suffix in suffixes]
    for key, path, child in iter_key_values(value):
        candidate = normalized_key(key)
        if any(candidate.endswith(suffix) for suffix in normalized_suffixes):
            leaf = _stringify_leaf(child)
            if leaf is not None:
                return path, leaf
    return None


def all_values_for_suffixes(value: Any, suffixes: Iterable[str]) -> list[tuple[str, Any]]:
    normalized_suffixes = [normalized_key(suffix) for suffix in suffixes]
    results: list[tuple[str, Any]] = []
    for key, path, child in iter_key_values(value):
        candidate = normalized_key(key)
        if any(candidate.endswith(suffix) for suffix in normalized_suffixes):
            leaf = _stringify_leaf(child)
            if leaf is not None:
                results.append((path, leaf))
    return results


def first_string_for_suffixes(value: Any, suffixes: Iterable[str]) -> tuple[str, str] | None:
    found = first_value_for_suffixes(value, suffixes)
    if found is None:
        return None
    path, leaf = found
    return path, str(leaf)


def first_int_for_suffixes(value: Any, suffixes: Iterable[str]) -> tuple[str, int] | None:
    found = first_value_for_suffixes(value, suffixes)
    if found is None:
        return None
    path, leaf = found
    text = str(leaf).strip()
    base = 16 if text.lower().startswith("0x") else 10
    try:
        return path, int(text, base)
    except ValueError:
        return None


def mask_identifier(kind: str, value: str, salt: str) -> str:
    digest = hmac.new(salt.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{kind}:mask_{digest[:24]}"


def sample_issues(issues: Iterable[Issue], max_per_code: int) -> list[Issue]:
    sampled: list[Issue] = []
    counts: DefaultDict[str, int] = defaultdict(int)
    for issue in issues:
        if counts[issue.code] >= max_per_code:
            continue
        sampled.append(issue)
        counts[issue.code] += 1
    return sampled


@dataclass
class ClosedArtifact:
    relative_path: str
    artifact_type: str
    media_type: str
    format_schema_version: str
    sha256: str
    byte_size: int
    record_count: int | None
    staged_path: Path
    protocol: str | None = None

    def descriptor(
        self,
        *,
        creation_stage: str,
        parent_source_sha256: str | None,
        revision: str | None = None,
    ) -> ArtifactDescriptor:
        artifact_key = compact_json_bytes(
            {
                "creation_stage": creation_stage,
                "relative_path": self.relative_path,
                "artifact_type": self.artifact_type,
                "protocol": self.protocol,
                "media_type": self.media_type,
                "format_schema_version": self.format_schema_version,
                "sha256": self.sha256,
                "byte_size": self.byte_size,
                "record_count": self.record_count,
                "parent_source_sha256": parent_source_sha256,
                "revision": revision,
            }
        )
        return ArtifactDescriptor(
            artifact_id=f"artifact:{sha256_bytes(artifact_key)}",
            relative_path=self.relative_path,
            artifact_type=self.artifact_type,
            protocol=self.protocol,
            media_type=self.media_type,
            format_schema_version=self.format_schema_version,
            sha256=self.sha256,
            byte_size=self.byte_size,
            record_count=self.record_count,
            creation_stage=creation_stage,
            parent_source_sha256=parent_source_sha256,
            revision=revision,
        )


class JsonlArtifactWriter:
    def __init__(
        self,
        staged_root: Path,
        run_dir: Path,
        relative_path: str,
        artifact_type: str,
        *,
        media_type: str = "application/x-ndjson",
        protocol: str | None = None,
        format_schema_version: str = "2.0",
    ) -> None:
        self.relative_path = relative_path
        self.artifact_type = artifact_type
        self.media_type = media_type
        self.protocol = protocol
        self.format_schema_version = format_schema_version
        self._path = staged_root / relative_path
        ensure_directory(self._path.parent)
        self._handle = self._path.open("wb")
        self._digest = hashlib.sha256()
        self._record_count = 0
        self._byte_size = 0
        self._run_dir = run_dir

    def write(self, value: Any) -> None:
        line = compact_json_bytes(value) + b"\n"
        self._handle.write(line)
        self._digest.update(line)
        self._record_count += 1
        self._byte_size += len(line)

    def close(self) -> ClosedArtifact:
        self._handle.flush()
        os.fsync(self._handle.fileno())
        self._handle.close()
        return ClosedArtifact(
            relative_path=self.relative_path,
            artifact_type=self.artifact_type,
            media_type=self.media_type,
            format_schema_version=self.format_schema_version,
            sha256=self._digest.hexdigest(),
            byte_size=self._byte_size,
            record_count=self._record_count,
            staged_path=self._path,
            protocol=self.protocol,
        )


class JsonArtifactWriter:
    def __init__(
        self,
        staged_root: Path,
        run_dir: Path,
        relative_path: str,
        artifact_type: str,
        *,
        media_type: str = "application/json",
        protocol: str | None = None,
        format_schema_version: str = "2.0",
    ) -> None:
        self.relative_path = relative_path
        self.artifact_type = artifact_type
        self.media_type = media_type
        self.protocol = protocol
        self.format_schema_version = format_schema_version
        self._path = staged_root / relative_path
        ensure_directory(self._path.parent)
        self._run_dir = run_dir

    def write(self, value: Any) -> ClosedArtifact:
        data = pretty_json_bytes(value)
        with self._path.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        return ClosedArtifact(
            relative_path=self.relative_path,
            artifact_type=self.artifact_type,
            media_type=self.media_type,
            format_schema_version=self.format_schema_version,
            sha256=sha256_bytes(data),
            byte_size=len(data),
            record_count=1,
            staged_path=self._path,
            protocol=self.protocol,
        )


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            yield json.loads(stripped)


def reset_staging_directory(run_dir: Path, staging_root: Path) -> None:
    validate_inside_run(run_dir, staging_root)
    if staging_root.is_symlink():
        raise ValueError(f"staging root {staging_root} must not be a symlink")
    if staging_root.exists():
        shutil.rmtree(staging_root)
    staging_root.mkdir(parents=True, exist_ok=True)


def fsync_directory(path: Path) -> None:
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _validate_publish_relative_path(relative_path: str) -> None:
    candidate = Path(relative_path)
    if candidate.is_absolute():
        raise ValueError(f"absolute publish path is not allowed: {relative_path}")
    if ".." in candidate.parts:
        raise ValueError(f"relative publish path escapes the run directory: {relative_path}")


def _ensure_safe_destination(run_dir: Path, destination: Path) -> None:
    validate_inside_run(run_dir, destination)
    current = destination
    while True:
        if current.exists() and current.is_symlink():
            raise ValueError(f"destination path contains symlink: {current}")
        if current == run_dir:
            break
        current = current.parent


def publish_closed_artifacts(run_dir: Path, artifacts: Iterable[ClosedArtifact], *, manifest_relative_path: str | None = None) -> None:
    manifest_rel = manifest_relative_path
    normal: list[ClosedArtifact] = []
    manifest: list[ClosedArtifact] = []
    seen_paths: set[str] = set()
    for artifact in artifacts:
        _validate_publish_relative_path(artifact.relative_path)
        if artifact.relative_path in seen_paths:
            raise ValueError(f"duplicate publish path: {artifact.relative_path}")
        seen_paths.add(artifact.relative_path)
        if manifest_rel is not None and artifact.relative_path == manifest_rel:
            manifest.append(artifact)
        else:
            normal.append(artifact)

    for group in (sorted(normal, key=lambda item: item.relative_path), sorted(manifest, key=lambda item: item.relative_path)):
        for artifact in group:
            destination = run_dir / artifact.relative_path
            _ensure_safe_destination(run_dir, destination)
            ensure_directory(destination.parent)
            fsync_directory(destination.parent)
            if destination.exists() and not destination.is_file():
                raise ValueError(f"publish destination is not a regular file: {destination}")
            os.replace(artifact.staged_path, destination)
            file_fd = os.open(destination, os.O_RDONLY)
            try:
                os.fsync(file_fd)
            finally:
                os.close(file_fd)
            fsync_directory(destination.parent)


def artifact_by_relative_path(artifacts: Iterable[ArtifactDescriptor], relative_path: str) -> ArtifactDescriptor | None:
    for artifact in artifacts:
        if artifact.relative_path == relative_path:
            return artifact
    return None


def count_jsonl_rows(path: Path) -> int:
    count = 0
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                count += 1
    return count
