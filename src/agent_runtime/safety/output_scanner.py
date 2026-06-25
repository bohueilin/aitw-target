"""Output scanner: redact registered secret values from any agent-facing text.

This is the egress redactor for the runtime security surface. The credential broker registers the
run's backing secrets and every issued ephemeral token onto a single scanner instance at runtime
(see agent_runtime.control.broker.make_broker), so register() must accept new secret values at any
time — not just up front.

For every registered value, the scanner redacts the literal value AND its common machine encodings —
base64 (standard and url-safe, padded and unpadded) and hexadecimal (both lower- and upper-case) —
replacing each occurrence with the literal marker "[REDACTED]". Detections are reported as neutral
CATEGORY LABELS ONLY; a detection label never contains the secret value itself.

The scanner works standalone (it has no I/O and no dependencies), so the acceptance gate and the
task registry can both exercise it directly.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

REDACTION_MARKER = "[REDACTED]"


@dataclass(frozen=True)
class ScanResult:
    """Outcome of a scan. `redacted` is the input with every secret encoding replaced by the marker;
    `detections` is a sorted list of neutral category labels (never the secret value)."""

    redacted: str
    detections: list[str]


def _encodings(value: str) -> dict[str, str]:
    """All representations of `value` to redact, mapped to a neutral category label.

    Covers the raw value, base64 (standard + url-safe, padded + unpadded) and hex (both cases).
    """
    raw = value.encode("utf-8")
    std = base64.b64encode(raw).decode("ascii")
    url = base64.urlsafe_b64encode(raw).decode("ascii")
    reps = {
        value: "secret_value",
        std: "secret_base64",
        std.rstrip("="): "secret_base64",
        url: "secret_base64",
        url.rstrip("="): "secret_base64",
        raw.hex(): "secret_hex",
        raw.hex().upper(): "secret_hex",
    }
    # Drop empty representations defensively (e.g. base64 of an empty string).
    return {rep: label for rep, label in reps.items() if rep}


class OutputScanner:
    """Redacts registered secret values (and their encodings) from text.

    register() is idempotent and may be called repeatedly at runtime as new secrets/tokens come into
    existence. scan() never mutates scanner state.
    """

    def __init__(self) -> None:
        # representation -> neutral category label. A dict dedupes repeated registrations.
        self._reps: dict[str, str] = {}

    def register(self, *values: str) -> None:
        """Teach the scanner one or more new secret VALUES. Non-string / empty values are ignored."""
        for value in values:
            if not isinstance(value, str) or not value:
                continue
            self._reps.update(_encodings(value))

    def scan(self, text: str) -> ScanResult:
        """Return a ScanResult with every registered secret encoding replaced by the marker.

        Non-string input is coerced to str. Representations are applied longest-first so a longer
        encoding is redacted before any shorter encoding it might contain.
        """
        if not isinstance(text, str):
            text = str(text)
        detections: set[str] = set()
        # Longest-first: prevents a shorter representation from matching inside a longer one's bytes.
        for rep in sorted(self._reps, key=len, reverse=True):
            if rep and rep in text:
                detections.add(self._reps[rep])
                text = text.replace(rep, REDACTION_MARKER)
        return ScanResult(redacted=text, detections=sorted(detections))
