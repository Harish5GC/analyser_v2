"""Safe Go argv construction — spec §4, §16.

The Python wrapper NEVER passes these arguments through a shell.
All values are passed as list elements to subprocess.Popen / subprocess.run.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Set


def build_decode_argv(
    binary: Path,
    pcap_path: Path,
    analysis_id: str,
    output_dir: Path,
    *,
    protocols: Optional[Set[str]] = None,
    retain_raw: bool = True,
    packet_access_index: bool = False,
    parallel: bool = True,
    tshark_path: Optional[Path] = None,
    enabled_capabilities: Optional[List[str]] = None,
    policy_versions: Optional[Dict[str, str]] = None,
) -> List[str]:
    """Return an argv list for the Go decode command.

    No shell quoting is applied; pass the result directly to Popen.
    """
    argv: List[str] = [
        str(binary),
        "decode",
        str(pcap_path),
        "--analysis-id", analysis_id,
        "--output-dir", str(output_dir),
        "--format", "v2",
        "--retain-raw", str(retain_raw).lower(),
        "--packet-access-index", str(packet_access_index).lower(),
        "--parallel", str(parallel).lower(),
    ]

    if protocols:
        for proto in sorted(protocols):
            argv += ["--protocol", proto]
    else:
        argv += ["--protocol", "all"]

    if tshark_path is not None:
        argv += ["--tshark", str(tshark_path)]

    if enabled_capabilities:
        for cap in enabled_capabilities:
            argv += ["--capability", cap]

    if policy_versions:
        for key in sorted(policy_versions):
            argv += ["--policy-version", f"{key}={policy_versions[key]}"]

    return argv
