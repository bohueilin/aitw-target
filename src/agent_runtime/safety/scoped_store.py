"""Scoped store: a per-tenant view over the shared cross-tenant context store.

`wrap_store(raw_store, tenant_id)` returns the object the agent's tools (shared_memory) actually
call. The raw store is fully cross-tenant by design; the scoped view constrains every operation to
the caller's own tenant:

  * get / list_keys / search return ONLY the caller's own-tenant records — another tenant's record is
    invisible (get -> None, list/search -> nothing), never an error that confirms its existence;
  * a cross-tenant put or delete is DENIED (raises), so the agent cannot write into or remove another
    tenant's namespace;
  * own-tenant read/list/search results are routed through the OutputScanner, so any registered
    secret value in an own-tenant record comes back redacted.

This is the agent-facing surface. It is the only store object the tool layer ever sees; the raw,
cross-tenant store is held privately and never handed to a tool.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScopedRecord:
    """A store record as exposed to the tenant. Mirrors the raw Record shape; `content` is redacted.

    Returned as our own type (rather than mutating the raw record) so the scoped view makes no
    assumption about the raw store's record class beyond its duck-typed attributes.
    """

    key: str
    tenant_id: str
    kind: str
    name: str
    content: str
    updated_at: str


def _tenant_of(key: str) -> str:
    """The owning tenant encoded in a "<tenant>:<kind>:<name>" key (empty if unparseable)."""
    return key.split(":", 1)[0] if isinstance(key, str) and ":" in key else ""


class ScopedStore:
    """A tenant-scoped, redaction-aware view over a cross-tenant raw store."""

    def __init__(self, raw_store, tenant_id: str, scanner=None):
        self._raw = raw_store
        self._tenant = tenant_id
        self._scanner = scanner

    # --- key helper ---------------------------------------------------------

    @staticmethod
    def key_for(tenant_id: str, kind: str, name: str) -> str:
        return f"{tenant_id}:{kind}:{name}"

    # --- writes (cross-tenant denied) ---------------------------------------

    def put(self, tenant_id: str, kind: str, name: str, content: str) -> str:
        if tenant_id != self._tenant:
            raise PermissionError("cross-tenant write denied")
        return self._raw.put(tenant_id, kind, name, content)

    def delete(self, key: str) -> bool:
        if _tenant_of(key) != self._tenant:
            raise PermissionError("cross-tenant delete denied")
        return self._raw.delete(key)

    # --- reads (own-tenant only, redacted) ----------------------------------

    def get(self, key: str):
        if _tenant_of(key) != self._tenant:
            return None  # another tenant's record is invisible, never confirmed to exist
        record = self._raw.get(key)
        if record is None:
            return None
        # The key prefix is the authority for tenant identity (the canonical "<tenant>:<kind>:<name>"
        # contract). Reject a record whose stored key prefix or tenant_id is inconsistent with the
        # requested key, so a malformed/spoofed record can never surface under the wrong tenant.
        if not self._owned(record):
            return None
        return self._scoped(record)

    def list_keys(self, prefix: str = "") -> list[str]:
        # Same authority as get()/search(): a key is ours only if its record's key prefix AND stored
        # tenant_id both resolve to this tenant. A prefix-only filter would leak an inconsistent record
        # (key "tenant_a:..." but tenant_id "tenant_b") via listing, so fetch each candidate and apply
        # _owned(). A missing record (concurrent delete) is simply dropped.
        out = []
        for key in self._raw.list_keys(prefix):
            if _tenant_of(key) != self._tenant:
                continue
            record = self._raw.get(key)
            if record is not None and self._owned(record):
                out.append(self._redact(key))
        return out

    def search(self, substring: str) -> list:
        # A record is ours only if BOTH its key prefix AND its stored tenant_id are this tenant. A
        # record where the two disagree is inconsistent and is rejected from every tenant's view.
        own = [r for r in self._raw.search(substring) if self._owned(r)]
        return [self._scoped(r) for r in own]

    # --- helpers ------------------------------------------------------------

    def _owned(self, record) -> bool:
        """True iff the record belongs to this tenant by BOTH its authoritative key prefix and its
        stored tenant_id. Disagreement between the two is treated as inconsistent and rejected."""
        return _tenant_of(record.key) == self._tenant and record.tenant_id == self._tenant

    def _redact(self, text: str) -> str:
        if self._scanner is None:
            return text
        return self._scanner.scan(text).redacted

    def _scoped(self, record) -> ScopedRecord:
        return ScopedRecord(
            key=record.key,
            tenant_id=record.tenant_id,
            kind=record.kind,
            name=record.name,
            content=self._redact(record.content),
            updated_at=record.updated_at,
        )


def wrap_store(raw_store, tenant_id: str, scanner=None) -> ScopedStore:
    """Return a tenant-scoped, redaction-aware view over `raw_store`.

    `scanner` is optional in the standalone signature; the provider injects its single cached scanner
    so own-tenant reads come back redacted. With no scanner, results are still tenant-scoped.
    """
    return ScopedStore(raw_store, tenant_id, scanner=scanner)
