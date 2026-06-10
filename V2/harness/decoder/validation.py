"""Artifact and manifest validation — spec §4, §7, §13, §16."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .errors import ArtifactValidationError, ManifestValidationError
from .manifest import ArtifactDescriptor, CollectionDescriptor, DecoderManifest


# ---------------------------------------------------------------------------
# Path safety helpers (spec §7, §13, §16)
# ---------------------------------------------------------------------------

def _check_rel_path(run_root: Path, rel_path: str) -> Path:
    """Resolve rel_path inside run_root, rejecting traversal and symlink escapes.

    Raises ManifestValidationError if the path is unsafe.
    """
    if os.path.isabs(rel_path):
        raise ManifestValidationError(f"Absolute path in manifest: {rel_path!r}")
    if ".." in Path(rel_path).parts:
        raise ManifestValidationError(f"Path traversal in manifest: {rel_path!r}")

    candidate = (run_root / rel_path).resolve()
    try:
        candidate.relative_to(run_root.resolve())
    except ValueError:
        raise ManifestValidationError(
            f"Path {rel_path!r} resolves outside run root {run_root}"
        )
    return candidate


# ---------------------------------------------------------------------------
# File-level checks
# ---------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_artifact(run_root: Path, desc: ArtifactDescriptor) -> Path:
    """Verify a single artifact: existence, size, and SHA-256 (spec §4, §7)."""
    abs_path = _check_rel_path(run_root, desc.relative_path)

    if not abs_path.exists():
        raise ArtifactValidationError(
            f"Artifact missing: {desc.relative_path}",
        )

    actual_size = abs_path.stat().st_size
    if actual_size != desc.byte_size:
        raise ArtifactValidationError(
            f"Artifact size mismatch for {desc.relative_path}: "
            f"expected {desc.byte_size}, got {actual_size}"
        )

    actual_sha = _sha256_file(abs_path)
    if actual_sha != desc.sha256:
        raise ArtifactValidationError(
            f"Artifact checksum mismatch for {desc.relative_path}: "
            f"expected {desc.sha256}, got {actual_sha}"
        )

    return abs_path


def validate_collection(run_root: Path, coll: CollectionDescriptor) -> None:
    """Validate an HTTP/2 stream collection: index artifact + every member."""
    # Validate the index artifact itself.
    validate_artifact(run_root, coll.index_artifact)

    if len(coll.members) != coll.member_count:
        raise ArtifactValidationError(
            f"Collection {coll.collection_id}: member_count={coll.member_count} "
            f"but {len(coll.members)} member descriptors"
        )

    # Validate each member document.
    for member in coll.members:
        member_desc = ArtifactDescriptor(
            artifact_id="",
            relative_path=member.relative_path,
            artifact_type=member.artifact_type,
            media_type=member.media_type,
            format_schema_version=member.format_schema_version,
            sha256=member.sha256,
            byte_size=member.byte_size,
            record_count=member.record_count,
            creation_stage="T01",
        )
        validate_artifact(run_root, member_desc)

    # Verify the MembersSHA256 is consistent with the ordered member checksums.
    h = hashlib.sha256()
    for m in coll.members:
        h.update(m.sha256.encode())
        h.update(b"\n")
    expected_digest = h.hexdigest()
    if expected_digest != coll.members_sha256:
        raise ArtifactValidationError(
            f"Collection {coll.collection_id}: members_sha256 mismatch"
        )


# ---------------------------------------------------------------------------
# Manifest-level validation
# ---------------------------------------------------------------------------

def validate_manifest(run_root: Path, manifest_path: Path) -> DecoderManifest:
    """Load and structurally validate decoder_manifest.json.

    Does NOT validate referenced artifacts — call validate_all_artifacts
    separately so errors are distinguishable.
    """
    if not manifest_path.exists():
        raise ManifestValidationError(
            f"decoder_manifest.json not found at {manifest_path}"
        )

    try:
        raw = manifest_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except Exception as exc:
        raise ManifestValidationError(f"Failed to parse manifest: {exc}") from exc

    try:
        manifest = DecoderManifest.model_validate(data)
    except Exception as exc:
        raise ManifestValidationError(f"Manifest schema validation failed: {exc}") from exc

    if manifest.schema_version != "2.0":
        raise ManifestValidationError(
            f"Unsupported manifest schema_version: {manifest.schema_version!r}"
        )

    return manifest


def validate_all_artifacts(run_root: Path, manifest: DecoderManifest) -> None:
    """Validate every artifact and collection referenced in the manifest.

    Raises ArtifactValidationError on the first failure (spec §4, AC#8).
    """
    # Validate the source PCAP descriptor.
    validate_artifact(run_root, manifest.source)

    # Validate each standalone artifact.
    for desc in manifest.artifacts:
        validate_artifact(run_root, desc)

    # Validate each collection (index + all member docs + digest).
    for coll in manifest.collections:
        validate_collection(run_root, coll)
