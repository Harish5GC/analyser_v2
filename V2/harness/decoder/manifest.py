"""Pydantic models mirroring decoder_manifest.json — spec §13."""
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class DecodeWarning(BaseModel):
    code: str
    severity: str
    stage: str
    message: str


class ArtifactDescriptor(BaseModel):
    artifact_id: str
    relative_path: str
    artifact_type: str
    protocol: Optional[str] = None
    media_type: str
    format_schema_version: str
    sha256: str
    byte_size: int
    record_count: Optional[int] = None
    creation_stage: str
    parent_source_sha256: Optional[str] = None
    revision: Optional[str] = None


class CollectionMemberDescriptor(BaseModel):
    relative_path: str
    sha256: str
    byte_size: int
    record_count: Optional[int] = None
    artifact_type: str
    media_type: str
    format_schema_version: str


class CollectionDescriptor(BaseModel):
    collection_id: str
    relative_dir: str
    artifact_type: str
    index_artifact: ArtifactDescriptor
    member_count: int
    members_sha256: str
    members: List[CollectionMemberDescriptor]
    parent_source_sha256: Optional[str] = None
    revision: Optional[str] = None


class ProtocolDecodeResult(BaseModel):
    status: Literal["success", "absent", "partial", "failed", "not_requested"]
    input_packets: int
    records_written: int
    incomplete_records: int = 0
    elapsed_ms: int
    warnings: List[DecodeWarning] = Field(default_factory=list)


class DecoderInfo(BaseModel):
    name: str
    version: str
    go_version: str
    tshark_version: str


class DecoderManifest(BaseModel):
    schema_version: Literal["2.0"]
    analysis_id: str
    status: Literal["success", "partial", "failed"]
    revision: str
    enabled_capabilities: List[str] = Field(default_factory=list)
    policy_versions: Dict[str, str] = Field(default_factory=dict)
    decoder: DecoderInfo
    source: ArtifactDescriptor
    protocols: Dict[str, ProtocolDecodeResult]
    artifacts: List[ArtifactDescriptor] = Field(default_factory=list)
    collections: List[CollectionDescriptor] = Field(default_factory=list)
    warnings: List[DecodeWarning] = Field(default_factory=list)
    started_at: str
    completed_at: str
    elapsed_ms: int
