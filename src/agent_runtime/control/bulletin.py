"""Operational-bulletin schema validation for the posture turn.

The posture registry's read_operational_bulletin tool sources content from `ctx.bulletin` and
validates it against the vendored schema (schemas/operational_bulletin.schema.json), falling back to
an in-code, schema-valid routine bulletin when the delivered bulletin is absent or invalid. This
module reads only that schema file — no bundled data/config — and depends only on the standard library.

Validation is FAIL-CLOSED: a malformed/invalid bulletin raises BulletinValidationError, which the
posture tool catches and replaces with the safe routine bulletin.
"""

from __future__ import annotations

import json
from pathlib import Path

# Repo root: .../src/agent_runtime/control/bulletin.py -> parents[3].
_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = _ROOT / "schemas" / "operational_bulletin.schema.json"


class BulletinValidationError(ValueError):
    """Raised when a bulletin fails strict validation. Handled fail-closed by the posture tool."""


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _validate_against_schema(bulletin, schema: dict) -> None:
    """Compact, dependency-free draft-07-subset validation, driven by the vendored schema.

    Enforces: object type, required fields, no additional properties, declared field types, the
    priority enum, and minLength. Kept boring and self-contained so the fail-closed path has no
    external dependency.
    """
    if not isinstance(bulletin, dict):
        raise BulletinValidationError("bulletin is not an object")

    props = schema.get("properties", {})
    required = schema.get("required", [])

    missing = [f for f in required if f not in bulletin]
    if missing:
        raise BulletinValidationError(f"missing required field(s): {missing}")

    if schema.get("additionalProperties") is False:
        extra = [k for k in bulletin if k not in props]
        if extra:
            raise BulletinValidationError(f"unexpected field(s): {extra}")

    type_map = {"string": str, "object": dict, "array": list, "boolean": bool}
    for name, spec in props.items():
        if name not in bulletin:
            continue
        value = bulletin[name]
        expected = spec.get("type")
        if expected in type_map and not isinstance(value, type_map[expected]):
            raise BulletinValidationError(f"field '{name}' must be {expected}")
        if "enum" in spec and value not in spec["enum"]:
            raise BulletinValidationError(f"field '{name}' must be one of {spec['enum']}")
        if isinstance(value, str) and len(value) < spec.get("minLength", 0):
            raise BulletinValidationError(f"field '{name}' is shorter than minLength")


def validate_bulletin(bulletin) -> dict:
    """Strictly validate against the vendored schema. Raises BulletinValidationError on any issue."""
    _validate_against_schema(bulletin, load_schema())
    return bulletin


def _safe_routine_bulletin() -> dict:
    """A minimal, schema-valid routine bulletin used as the fail-closed fallback."""
    return {
        "bulletin_id": "b-fallback",
        "issued_at": "1970-01-01T00:00:00Z",
        "effective_window": "n/a",
        "source": "platform-ops",
        "priority": "routine",
        "summary": "Fallback routine notice.",
        "operational_context": "Bulletin unavailable or invalid; defaulting to standard posture.",
        "recommended_posture": "Maintain standard controls.",
        "reference": "runbook-ops-standard",
    }
