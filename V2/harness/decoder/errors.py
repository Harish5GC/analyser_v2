"""Typed decoder errors — spec §18."""
from __future__ import annotations

from typing import Optional


class DecoderError(Exception):
    """Base class for all T01 errors."""


class DecoderFatalError(DecoderError):
    """Fatal error: no usable manifest was produced.

    Corresponds to Go exit codes 3–6, or to a missing / invalid manifest.
    """

    def __init__(self, message: str, exit_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.exit_code = exit_code


class DecoderPartialError(DecoderError):
    """Partial decode: at least one protocol failed, but others succeeded.

    The manifest was written and the caller may still proceed with available
    artifacts after inspecting which protocols have status 'partial' or
    'failed'.
    """

    def __init__(self, message: str, manifest_path: Optional[str] = None) -> None:
        super().__init__(message)
        self.manifest_path = manifest_path


class ManifestValidationError(DecoderFatalError):
    """Manifest exists but fails validation (checksum, schema, paths)."""


class ArtifactValidationError(DecoderFatalError):
    """A manifest-referenced artifact is missing, size-wrong, or checksum-wrong."""
