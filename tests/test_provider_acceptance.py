"""Provider self-acceptance, as pytest cases.

Each containment property is one parametrized test, reusing the exact checks the standalone
self-acceptance script runs (scripts/acceptance_selfcheck.py). Keeping a single source of truth means
`python scripts/acceptance_selfcheck.py` and `make test` cannot drift apart.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
for _p in (str(_ROOT), str(_ROOT / "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import acceptance_selfcheck as ac  # noqa: E402


@pytest.mark.parametrize("label,fn", ac.CHECKS, ids=[label.split(")")[0] + ")" for label, _ in ac.CHECKS])
def test_containment_property(label, fn):
    passed, detail = fn()
    if passed is None:  # substrate-dependent check, stock target not on path (e.g. CI)
        pytest.skip(detail)
    assert passed, f"{label}: {detail}"
