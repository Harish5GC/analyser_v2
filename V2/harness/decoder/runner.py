"""T01 decode_capture runner — spec §4, §18.

This is the only public entry point exposed to the orchestrator.  It:
  1. Validates the request (DecodeCaptureRequest).
  2. Copies the PCAP into the run's source/ directory and writes
     source_manifest.json.
  3. Invokes the Go binary with a safe argv list (no shell).
  4. Reads, structurally validates, and artifact-validates decoder_manifest.json.
  5. Returns DecodeCaptureResult.

The wrapper never trusts the Go exit code alone (spec §4, AC#8).
"""
from __future__ import annotations

import hashlib
import json
import os
import signal
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Literal, Set
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from .command import build_decode_argv
from .errors import (
    ArtifactValidationError,
    DecoderFatalError,
    DecoderPartialError,
    ManifestValidationError,
)
from .manifest import (
    ArtifactDescriptor,
    CollectionDescriptor,
    DecodeWarning,
    DecoderManifest,
    ProtocolDecodeResult,
)
from .validation import validate_all_artifacts, validate_manifest


# ---------------------------------------------------------------------------
# Public request / result models (spec §4)
# ---------------------------------------------------------------------------

CapabilityName = Literal[
    "cli_single_run",
    "jsonl_run_store",
    "profile_registry",
    "canonical_artifact_revisions",
    "two_pass_dependency_inspection",
    "bounded_targeted_redecode",
    "authenticated_evidence_cursors",
    "openai_compatible_provider",
    "masking_policy",
    "api_service",
    "sqlite_event_store",
    "queued_analysis",
    "additional_dependency_tools",
    "vendor_specific_profiles",
    "learned_anomaly_ranking",
]


class DecodeCaptureRequest(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    retained_pcap_path: Path
    run_dir: Path
    decoder_binary: Path
    timeout_seconds: int = 600
    protocols: Set[Literal["http2", "ngap", "pfcp"]] = Field(
        default_factory=lambda: {"http2", "ngap", "pfcp"}
    )
    retain_raw_packets: bool = True
    build_packet_access_index: bool = False
    enabled_capabilities: Set[str] = Field(default_factory=set)
    policy_versions: Dict[str, str] = Field(default_factory=dict)


class DecodeCaptureResult(BaseModel):
    """Validated T01 result returned to the orchestrator (spec §4)."""

    schema_version: Literal["2.0"] = "2.0"
    analysis_id: UUID
    status: Literal["success", "partial", "failed"]
    revision: str
    source: ArtifactDescriptor
    manifest: ArtifactDescriptor
    protocols: Dict[str, ProtocolDecodeResult]
    artifacts: List[ArtifactDescriptor]
    collections: List[CollectionDescriptor] = Field(default_factory=list)
    decoder_version: str
    tshark_version: str
    started_at: datetime
    completed_at: datetime
    elapsed_ms: int
    warnings: List[DecodeWarning] = Field(default_factory=list)
    # Convenience extra (not part of §4): absolute path to the validated manifest.
    manifest_path: Path


# ---------------------------------------------------------------------------
# Source-manifest helper
# ---------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_source_manifest(source_dir: Path, pcap_path: Path) -> None:
    """Write source/source_manifest.json with PCAP identity metadata."""
    stat = pcap_path.stat()
    sha = _sha256_file(pcap_path)
    manifest = {
        "schema_version": "2.0",
        "pcap_path": str(pcap_path),
        "sha256": sha,
        "byte_size": stat.st_size,
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    dest = source_dir / "source_manifest.json"
    dest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def _terminate_process_group(proc: subprocess.Popen, grace_seconds: float = 5.0) -> None:
    """Terminate the Go decoder and any child tshark processes it started."""
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except PermissionError:
        proc.terminate()

    try:
        proc.wait(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except PermissionError:
        proc.kill()
    proc.wait()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_decode(request: DecodeCaptureRequest) -> DecodeCaptureResult:
    """Execute T01 decode_capture and return a validated result.

    Raises:
        DecoderFatalError   — the run produced no usable manifest.
        DecoderPartialError — partial decode; manifest exists but some protocols
                              failed.  Caller may inspect and continue.
        ManifestValidationError — manifest exists but is structurally invalid.
        ArtifactValidationError — manifest-referenced artifact is wrong.
    """
    # ---- pre-flight validation -------------------------------------------
    if not request.retained_pcap_path.exists():
        raise DecoderFatalError(
            f"PCAP not found: {request.retained_pcap_path}", exit_code=3
        )
    if not request.decoder_binary.exists():
        raise DecoderFatalError(
            f"decoder binary not found: {request.decoder_binary}", exit_code=6
        )

    # build_packet_access_index requires bounded_targeted_redecode (spec §4).
    if request.build_packet_access_index and "bounded_targeted_redecode" not in request.enabled_capabilities:
        raise DecoderFatalError(
            "build_packet_access_index=true requires bounded_targeted_redecode capability",
            exit_code=2,
        )

    run_dir = request.run_dir.resolve()
    source_dir = run_dir / "source"
    decoder_dir = run_dir / "decoder"

    source_dir.mkdir(parents=True, exist_ok=True)
    decoder_dir.mkdir(parents=True, exist_ok=True)

    # ---- copy PCAP into source/ (no hard links by default — immutability) -
    retained_pcap = source_dir / "capture.pcap"
    requested_sha = _sha256_file(request.retained_pcap_path)
    if retained_pcap.exists():
        retained_sha = _sha256_file(retained_pcap)
        if retained_sha != requested_sha:
            raise DecoderFatalError(
                "run/source/capture.pcap already exists but does not match "
                f"requested PCAP {request.retained_pcap_path}",
                exit_code=2,
            )
    else:
        shutil.copy2(str(request.retained_pcap_path), str(retained_pcap))
        copied_sha = _sha256_file(retained_pcap)
        if copied_sha != requested_sha:
            raise DecoderFatalError(
                "retained source PCAP checksum mismatch after copy",
                exit_code=3,
            )
    _write_source_manifest(source_dir, retained_pcap)

    # ---- build argv and invoke Go binary ---------------------------------
    argv = build_decode_argv(
        binary=request.decoder_binary,
        pcap_path=retained_pcap,
        analysis_id=str(request.analysis_id),
        output_dir=decoder_dir,
        protocols=request.protocols,
        retain_raw=request.retain_raw_packets,
        packet_access_index=request.build_packet_access_index,
        enabled_capabilities=sorted(request.enabled_capabilities),
        policy_versions=request.policy_versions,
    )

    started_at = datetime.now(tz=timezone.utc)
    manifest_path = decoder_dir / "decoder_manifest.json"

    try:
        proc = subprocess.Popen(
            argv,
            start_new_session=True,
        )
        exit_code = proc.wait(timeout=request.timeout_seconds)
    except subprocess.TimeoutExpired:
        # Python owns the wall-clock timeout (spec §3.1, §14). The Go decoder
        # publishes decoder_manifest.json last and atomically, so a manifest
        # present here is complete: validate it and continue (it may report
        # partial). With no manifest, the run is fatal.
        _terminate_process_group(proc)
        exit_code = None
        if not manifest_path.exists():
            raise DecoderFatalError(
                "Go decoder timed out before publishing a manifest", exit_code=None
            )

    completed_at = datetime.now(tz=timezone.utc)
    elapsed_ms = int((completed_at - started_at).total_seconds() * 1000)

    # ---- read and validate manifest — NEVER trust exit code alone --------
    # Exit codes 4/5/6 before manifest is written are fatal.
    if exit_code in (4, 5, 6) and not manifest_path.exists():
        raise DecoderFatalError(
            f"Go decoder exited with code {exit_code} and no manifest produced",
            exit_code=exit_code,
        )

    if not manifest_path.exists():
        raise DecoderFatalError(
            f"No decoder_manifest.json produced (exit code {exit_code})",
            exit_code=exit_code,
        )

    manifest: DecoderManifest = validate_manifest(run_dir, manifest_path)
    validate_all_artifacts(run_dir, manifest)

    # ---- build result ---------------------------------------------------
    # Descriptor for the manifest file itself (a manifest cannot contain its own
    # checksum, so Python computes it after the file is published) — spec §4.
    manifest_desc = ArtifactDescriptor(
        artifact_id="",
        relative_path="decoder/decoder_manifest.json",
        artifact_type="decoder_manifest",
        media_type="application/json",
        format_schema_version=manifest.schema_version,
        sha256=_sha256_file(manifest_path),
        byte_size=manifest_path.stat().st_size,
        creation_stage="T01",
    )

    all_warnings: List[DecodeWarning] = list(manifest.warnings)
    for pr in manifest.protocols.values():
        all_warnings.extend(pr.warnings)

    decode_result = DecodeCaptureResult(
        analysis_id=request.analysis_id,
        status=manifest.status,
        revision=manifest.revision,
        source=manifest.source,
        manifest=manifest_desc,
        manifest_path=manifest_path,
        protocols=manifest.protocols,
        artifacts=manifest.artifacts,
        collections=manifest.collections,
        decoder_version=manifest.decoder.version,
        tshark_version=manifest.decoder.tshark_version,
        started_at=started_at,
        completed_at=completed_at,
        elapsed_ms=elapsed_ms,
        warnings=all_warnings,
    )

    if manifest.status == "failed":
        raise DecoderFatalError(
            "All protocol decoders failed; inspect manifest for details",
            exit_code=4,
        )
    if manifest.status == "partial":
        raise DecoderPartialError(
            "Partial decode: some protocols failed; inspect manifest for details",
            manifest_path=str(manifest_path),
        )

    return decode_result
