"""Route-level egress allowlist check — the control-plane home for http_fetch egress.

Relocated verbatim from the artifact's own http_fetch tool body so the predicate survives when the
artifact runs on the host's stock target tools. The stock http_fetch constrains egress to an exact
(scheme, host, port) match only; this preserves the artifact's existing, stricter predicate —
(scheme, host, port) exact match PLUS userinfo rejection PLUS a path-prefix check at a segment
boundary, with traversal-safe path normalization — as a pre-dispatch check in the task registry.

This is preservation, not a new control: it reproduces exactly the allow/deny decisions the shipped
tool already made. Pure and dependency-free (urllib + posixpath), so it stays deterministic.
"""

from __future__ import annotations

import posixpath
from urllib.parse import unquote, urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _authority_path(url: str) -> tuple[str, str, int, str] | None:
    """Return (scheme, host, port, normalized_path) for an http(s) URL, or None if unresolvable.

    None for anything unparseable / non-http / carrying userinfo means it can never match an allowlist
    entry (which also resolves through here), so malformed or authority-confusing input fails closed.
    """
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in _DEFAULT_PORTS:
            return None
        host = (parts.hostname or "").lower()
        if not host:
            return None
        if parts.username or parts.password:
            return None
        port = parts.port if parts.port is not None else _DEFAULT_PORTS[scheme]
    except ValueError:  # malformed port / authority
        return None
    # Decode percent-encoding THEN normalize, so '/mock/../steal' and '/mock/%2e%2e/steal' both
    # collapse to '/steal' and cannot pass a '/mock' prefix.
    norm = posixpath.normpath(unquote(parts.path or "/"))
    if not norm.startswith("/"):
        norm = "/" + norm
    return (scheme, host, port, norm)


def _path_allowed(target_path: str, entry_path: str) -> bool:
    if entry_path == "/":
        return True  # root entry == host-level (any path)
    return target_path == entry_path or target_path.startswith(entry_path + "/")


def url_egress_allowed(url: str, egress_allowlist) -> bool:
    """True iff `url` resolves and matches an allowlist entry on (scheme, host, port) AND path prefix.

    A malformed allowlist entry (resolves to None) is skipped, never matched.
    """
    target = _authority_path(url)
    if target is None:
        return False
    for entry in egress_allowlist or []:
        allowed = _authority_path(entry)
        if allowed is None:
            continue
        if target[:3] == allowed[:3] and _path_allowed(target[3], allowed[3]):
            return True
    return False
