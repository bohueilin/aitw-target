"""Environment reset / teardown between runs (all external effects stay sandboxed).

Removes run artifacts and agent workspaces so each run starts clean. Guarded: it only removes
directories literally named in SAFE_NAMES, so a mistyped path can't nuke the repo.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

SAFE_NAMES = {"runs", "workspaces"}
CACHE_DIR_NAMES = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".hypothesis"}
BUILD_DIR_NAMES = {"build", "dist"}
# Repo root: .../agents-in-the-wild/src/agent_runtime/safety/reset.py -> parents[3].
PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _contained(path: Path) -> bool:
    try:
        return path.resolve().is_relative_to(PROJECT_ROOT)
    except (OSError, RuntimeError):
        return False


def reset(targets: tuple[str, ...] = ("runs", "workspaces")) -> list[str]:
    removed = []
    for name in targets:
        path = Path(name).resolve()
        # Two guards, BOTH required: an allowed basename AND containment under the project root.
        # The basename check alone let an absolute "/anything/runs" through to rmtree.
        if path.name not in SAFE_NAMES or not path.is_relative_to(PROJECT_ROOT):
            print(f"reset: refusing to remove path outside the project run dirs: {path}", file=sys.stderr)
            continue
        if path.exists():
            shutil.rmtree(path)
            removed.append(str(path))
    return removed


def safe_reset() -> list[str]:
    """Reproducibility reset: run dirs + caches + build/egg-info, all contained under the project
    root. Refuses anything outside the root. Safe to run before packaging."""
    removed: list[str] = []
    # Run dirs at the project root.
    for name in SAFE_NAMES:
        p = PROJECT_ROOT / name
        if p.exists() and _contained(p):
            shutil.rmtree(p, ignore_errors=True)
            removed.append(str(p))
    # Caches anywhere under the root.
    for p in sorted(PROJECT_ROOT.rglob("*"), key=lambda q: len(q.parts), reverse=True):
        if p.is_dir() and p.name in CACHE_DIR_NAMES and _contained(p):
            shutil.rmtree(p, ignore_errors=True)
            removed.append(str(p))
    # build/dist + *.egg-info at root and under src.
    candidates = list(PROJECT_ROOT.glob("*")) + list((PROJECT_ROOT / "src").rglob("*"))
    for p in candidates:
        if p.is_dir() and (p.name in BUILD_DIR_NAMES or p.name.endswith(".egg-info")) and _contained(p):
            if p.exists():
                shutil.rmtree(p, ignore_errors=True)
                removed.append(str(p))
    return removed


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    removed = safe_reset() if "--safe" in argv else reset()
    if removed:
        print("reset removed:\n  " + "\n  ".join(removed))
    else:
        print("reset: nothing to remove (clean)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
