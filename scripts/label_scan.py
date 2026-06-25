#!/usr/bin/env python3
"""Label scan: fail if the tree carries any internal/condition/methodology labels.

This is a release gate. It recursively scans file contents AND path names for a fixed list of labels
that must never appear in a shipped artifact: condition/methodology terms and project/event names.
General security vocabulary (injection, phishing, credential, threat, posture, taint, egress) is NOT
flagged — those are legitimate in a security-relevant codebase.

Exit code 0 = clean, 1 = at least one label found.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Directories and files that are not part of the shipped source, or are required verbatim boilerplate.
SKIP_DIRS = {
    ".git", "__pycache__", "runs", "workspaces", ".hypothesis", ".pytest_cache",
    ".ruff_cache", "dist", "build", "node_modules", ".mypy_cache",
    ".venv", "venv", "env", "site-packages",
}
SKIP_SUFFIXES = {".pyc", ".lock"}  # .lock = pinned hashes; never label-bearing
# Files excluded from the scan by design: the scanner's own ruleset (it necessarily contains the
# label patterns it searches for).
SKIP_FILES = {"label_scan.py"}

# Narrow, documented allow-list for label substrings that are CONTRACT-REQUIRED and must appear:
#   * the canonical operational-bulletin schema $id (fixed by the contract; ships verbatim);
#   * the sanctioned host-runtime import path. This artifact is a defense layer that runs over the
#     host's stock target package; the contract requires importing its tools, so the package path
#     "aitw.<subpkg>" / "import aitw" (and the read-only test-substrate dir "aitw-target") is allowed
#     ONLY in those import-path forms — a bare project label remains flagged everywhere else.
ALLOWED_SUBSTRINGS = (
    "day-zero.dev/schemas/operational_bulletin.schema.json",
    "aitw.tools",
    "aitw.context",
    "aitw.agent",
    "import aitw",
    "aitw-target",
)

# Unambiguous condition/methodology/project labels. Word-boundary anchored to avoid matching inside
# ordinary words (e.g. \blure\b does not match "failure").
PATTERNS = [re.compile(p, re.IGNORECASE) for p in (
    r"\bcompromised\b", r"\bcanary\b", r"honeytoken", r"\bexfil\b", r"\bexfiltration\b",
    r"\battacker\b", r"attack[ _-]?fixture", r"\bbaseline\b", r"\bhardened\b", r"\bdefended\b",
    r"\bscored\b", r"deliberately[ _-]?naive", r"\bevaluator\b", r"\blure\b", r"\bnaive\b",
    r"matched[ _-]?arm", r"paired[ _-]?arm", r"two[ _-]?arm", r"\bprong\b",
    r"blue[ _-]?team", r"red[ _-]?team", r"\baitw\b", r"agents in the wild",
    r"day[ _-]zero", r"\bmisawa\b", r"INJECT::",
)]


def _allowed(line: str, match_start: int, match_end: int) -> bool:
    return any(sub in line and line.index(sub) <= match_start and match_end <= line.index(sub) + len(sub)
               for sub in ALLOWED_SUBSTRINGS)


def scan() -> int:
    hits = []
    for path in sorted(ROOT.rglob("*")):
        rel = path.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        # path-name check
        for pat in PATTERNS:
            if pat.search(str(rel)):
                hits.append((str(rel), 0, f"path contains '{pat.pattern}'"))
        if not path.is_file() or path.name in SKIP_FILES or path.suffix in SKIP_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for pat in PATTERNS:
                for m in pat.finditer(line):
                    if _allowed(line, m.start(), m.end()):
                        continue
                    hits.append((str(rel), i, f"'{m.group()}' ({pat.pattern})"))
    if hits:
        print(f"LABEL SCAN FAILED — {len(hits)} hit(s):")
        for f, ln, what in hits:
            print(f"  {f}:{ln}: {what}")
        return 1
    print("LABEL SCAN CLEAN — no condition/methodology/project labels found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(scan())
