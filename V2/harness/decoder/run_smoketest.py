#!/usr/bin/env python3
"""End-to-end smoke test for the T01 decode_capture wrapper.

Runs the Go decoder via the Python wrapper against a reference PCAP and asserts
the §4 DecodeCaptureResult contract: typed protocol results, a manifest
descriptor, collection descriptors, and typed warnings. Exits non-zero on any
failure so it can gate CI.

Usage:
    python3 -m V2.harness.decoder.run_smoketest \
        [--pcap PATH] [--binary PATH]

Defaults: PCAP from $T01_TEST_PCAP or /home/newuegnb/corevonr.pcap;
binary from $T01_DECODER_BIN or <repo>/V2/tools/decoder/5g_call.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

# Allow running both as a module and as a direct script.
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from V2.harness.decoder import DecodeCaptureRequest, run_decode  # noqa: E402
from V2.harness.decoder.manifest import (  # noqa: E402
    ArtifactDescriptor,
    CollectionDescriptor,
    DecodeWarning,
    ProtocolDecodeResult,
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--pcap",
        default=os.environ.get("T01_TEST_PCAP", "/home/newuegnb/corevonr.pcap"),
    )
    ap.add_argument(
        "--binary",
        default=os.environ.get(
            "T01_DECODER_BIN", str(_REPO_ROOT / "V2" / "tools" / "decoder" / "5g_call")
        ),
    )
    args = ap.parse_args()

    pcap = Path(args.pcap)
    binary = Path(args.binary)
    if not pcap.exists():
        print(f"SKIP: reference pcap not found: {pcap}")
        return 0
    if not binary.exists():
        print(f"SKIP: decoder binary not found: {binary}")
        return 0

    with tempfile.TemporaryDirectory(prefix="t01_smoke_") as run_dir:
        req = DecodeCaptureRequest(
            analysis_id=uuid4(),
            retained_pcap_path=pcap,
            run_dir=Path(run_dir),
            decoder_binary=binary,
            timeout_seconds=120,
        )
        result = run_decode(req)

        # --- §4 contract assertions ---------------------------------------
        assert result.status in ("success", "partial"), result.status
        assert result.revision.startswith("sha256:"), result.revision

        assert isinstance(result.manifest, ArtifactDescriptor)
        assert result.manifest.artifact_type == "decoder_manifest"
        assert result.manifest.sha256 and result.manifest.byte_size > 0

        assert isinstance(result.source, ArtifactDescriptor)
        assert result.source.relative_path == "source/capture.pcap"

        assert result.protocols, "no protocol results"
        for name, pr in result.protocols.items():
            assert isinstance(pr, ProtocolDecodeResult), name

        for c in result.collections:
            assert isinstance(c, CollectionDescriptor)
            assert c.member_count == len(c.members)
            assert c.members_sha256

        for w in result.warnings:
            assert isinstance(w, DecodeWarning)

        print("SMOKETEST PASS")
        print(f"  status      : {result.status}")
        print(f"  revision    : {result.revision}")
        print(f"  manifest    : {result.manifest.byte_size} bytes")
        print(f"  artifacts   : {len(result.artifacts)}")
        print(f"  collections : {len(result.collections)}")
        for name, pr in sorted(result.protocols.items()):
            print(
                f"  {name:6s}    : status={pr.status} "
                f"input={pr.input_packets} records={pr.records_written}"
            )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
