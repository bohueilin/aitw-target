"""Dependency-confusion guard for vendored, local-only packages.

A vendored package (see vendor/) shares its name with something that could exist on a public index.
The dependency-confusion risk is a resolver pulling the PUBLIC same-named package instead of our
local stub. This guard makes the local copy authoritative and detects substitution:

  * ensure_vendor_on_path() puts vendor/ at the FRONT of sys.path, so ``import <name>`` resolves to
    the local vendored copy and never triggers a network install.
  * verify_vendored() asserts the imported package carries our local sentinel (ORIGIN + version),
    physically lives under vendor/, AND (when vendor/manifest.json is present) matches a pinned
    SHA256 of its source file. A public same-named package differs on all three and is rejected;
    a tampered local copy fails the hash pin.

Public-index resolution is blocked structurally, not just here: the vendored names are NOT declared
as PyPI dependencies (pyproject), and the documented install for vendored names is
``pip install --no-index --find-links vendor <name>`` (see constraints.txt). This module is the
runtime backstop that fails loudly if a non-local copy is ever what gets imported.

It never reaches a network index. ``python -m agent_runtime.safety.dependency_guard`` runs verification and
exits non-zero on any substitution (used by the primary-smoke target).
"""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
VENDOR_DIR = _ROOT / "vendor"
MANIFEST_PATH = VENDOR_DIR / "manifest.json"

# Vendored, local-only packages and the sentinel that proves the local copy is the one imported.
VENDORED = {
    "helpful_utils": {"origin": "local-vendored-stub", "version_prefix": "0.0.0-local-stub"},
}


class DependencyConfusionError(RuntimeError):
    """Raised when a vendored name resolves to a non-local / unexpected package."""


def ensure_vendor_on_path() -> None:
    """Make vendored, local-only packages authoritative.

    Removes any existing occurrence of vendor/ from sys.path and reinserts it at index 0, so the
    local copy wins even if a same-named package path was inserted EARLIER on sys.path (the
    dependency-confusion risk). Idempotent and cheap.
    """
    p = str(VENDOR_DIR)
    while p in sys.path:
        sys.path.remove(p)
    sys.path.insert(0, p)


def _module_is_local(module) -> bool:
    f = getattr(module, "__file__", None)
    if not f:
        return False
    try:
        return VENDOR_DIR in Path(f).resolve().parents
    except Exception:
        return False


def _verify_manifest_hashes(name: str) -> None:
    """If vendor/manifest.json is present, verify the vendored source file(s) match the pinned
    SHA256. A tampered or substituted local copy — even one that fakes the sentinel — fails here.
    Absent manifest => skip (the sentinel + local-path checks still apply).
    """
    if not MANIFEST_PATH.exists():
        return
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    entry = manifest.get(name)
    if not entry:
        return
    for rel, expected in entry.get("files", {}).items():
        src = VENDOR_DIR / rel
        if not src.exists():
            raise DependencyConfusionError(
                f"vendored file {rel!r} for package {name!r} is missing — cannot verify integrity"
            )
        actual = hashlib.sha256(src.read_bytes()).hexdigest()
        if actual != expected:
            raise DependencyConfusionError(
                f"vendored file {rel!r} for package {name!r} hash mismatch "
                f"(pinned {expected[:12]}…, got {actual[:12]}…) — possible tampering/substitution"
            )


def verify_vendored(name: str) -> None:
    """Verify a single vendored package resolves to the local copy and matches its sentinel."""
    spec = VENDORED.get(name)
    if spec is None:
        return
    ensure_vendor_on_path()
    module = importlib.import_module(name)
    origin = getattr(module, "ORIGIN", None)
    if hasattr(module, "version") and callable(module.version):
        version = module.version()
    else:
        version = getattr(module, "__version__", "")
    if origin != spec["origin"] or not str(version).startswith(spec["version_prefix"]):
        raise DependencyConfusionError(
            f"vendored package {name!r} did not match its local sentinel "
            f"(origin/version mismatch) — possible dependency-confusion substitution"
        )
    if not _module_is_local(module):
        raise DependencyConfusionError(
            f"vendored package {name!r} did not resolve from vendor/ — possible non-local copy"
        )
    # Pinned-hash integrity check (in addition to the sentinel + local-path checks).
    _verify_manifest_hashes(name)


def verify_all() -> list[str]:
    """Verify every known vendored package resolves locally. Returns the verified names.

    Raises DependencyConfusionError on any substitution.
    """
    ensure_vendor_on_path()
    verified = []
    for name in VENDORED:
        verify_vendored(name)
        verified.append(name)
    return verified


def main(argv=None) -> int:
    try:
        verified = verify_all()
    except DependencyConfusionError as exc:
        print(f"dependency_guard: FAIL — {exc}", file=sys.stderr)
        return 1
    print("dependency_guard: OK — vendored packages resolved locally: " + ", ".join(verified))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
