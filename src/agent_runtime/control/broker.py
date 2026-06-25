"""Credential broker — ephemeral tool credentials + the run's secret-registration path.

The host builds this via make_broker(model_key, tool_backing_secret, scanner, spend_cap). It owns the
run's BACKING secrets privately and is the single path that teaches the OutputScanner the run's secret
values: on construction it registers the backing secrets, and on every credential issue it registers
the issued ephemeral token. It never hands a backing secret to anything agent-reachable.

Three concerns are kept strictly separate, by design:

  * is_valid(cred)          — credential validity ONLY: the tenant's currently-active, non-revoked,
                              non-expired token. No spend/budget consideration, so a spend-exhausted
                              run never masquerades as an invalid credential.
  * use_model_key(tenant)   — the operator-side model-key accessor (adapter path, never reachable from
                              a tool). spend_cap is a per-tenant cap on MODEL-KEY access only: one unit
                              per call, and the accessor RAISES on exceed (fail-closed). None=uncapped.
  * allow_external_effect() — a separate, optional per-tenant budget/rate limit on EXTERNAL-EFFECT
                              dispatch, with its own deny path, independent of is_valid() and spend_cap.

This module imports only the standard library so the package loads cleanly with nothing but the
artifact root on the path.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class EphemeralCredential:
    """A short-lived tool credential handed to a tenant. The backing secrets are never exposed this
    way; only this opaque, time-boxed token is. `ttl_seconds` is part of the contract shape."""

    token: str
    tenant_id: str
    ttl_seconds: int
    issued_monotonic: float


class CredentialBroker:
    """Issues ephemeral tool credentials and registers the run's secrets onto the output scanner.

    Backing secrets are held privately (no public getter). The model key is reachable only through
    use_model_key(), the operator-side accessor that enforces spend_cap and is never wired to a tool.
    """

    def __init__(
        self,
        *,
        model_key: str,
        tool_backing_secret: str,
        scanner=None,
        spend_cap: int | None = None,
        external_effect_cap: int | None = None,
        default_ttl_seconds: int = 900,
        clock=None,
    ):
        # Backing secrets — PRIVATE. No getter exposes them; the agent never receives them.
        self._model_key = model_key
        self._tool_backing_secret = tool_backing_secret
        self._scanner = scanner
        self._spend_cap = spend_cap
        self._external_effect_cap = external_effect_cap
        self._default_ttl = default_ttl_seconds
        self._clock = clock or time.monotonic

        self._active: dict[str, str] = {}          # tenant_id -> currently-active token
        self._revoked: set[str] = set()            # explicitly revoked tokens
        self._model_key_uses: dict[str, int] = {}  # tenant_id -> model-key access count (spend_cap)
        self._effect_uses: dict[str, int] = {}     # tenant_id -> external-effect count (budget guard)

        # The ONLY path that teaches the scanner the run's backing secret values.
        if self._scanner is not None:
            self._scanner.register(model_key, tool_backing_secret)

    # --- credential lifecycle ----------------------------------------------

    def issue_tool_credential(self, tenant_id: str, ttl_seconds: int | None = None) -> EphemeralCredential:
        """Mint a fresh ephemeral credential, make it the tenant's active token, and register the
        token value onto the scanner. Issuing supersedes any prior credential for the tenant."""
        token = secrets.token_urlsafe(24)
        cred = EphemeralCredential(
            token=token,
            tenant_id=tenant_id,
            ttl_seconds=self._default_ttl if ttl_seconds is None else ttl_seconds,
            issued_monotonic=self._clock(),
        )
        self._active[tenant_id] = token  # the new token supersedes the old one for this tenant
        if self._scanner is not None:
            self._scanner.register(token)
        return cred

    def is_valid(self, cred) -> bool:
        """True iff `cred` is the tenant's currently-active, non-revoked, non-expired token.

        Deliberately narrow: no spend/budget consideration (those are separate guards), so run
        telemetry never confuses 'budget exhausted' with 'invalid credential'.
        """
        if not isinstance(cred, EphemeralCredential):
            return False
        if cred.token in self._revoked:
            return False
        if self._active.get(cred.tenant_id) != cred.token:
            return False
        elapsed = self._clock() - cred.issued_monotonic
        return elapsed < cred.ttl_seconds

    def revoke(self, cred) -> None:
        """Explicitly revoke a credential (real defense; also exercised by the self-check)."""
        if isinstance(cred, EphemeralCredential):
            self._revoked.add(cred.token)

    # --- operator-side model-key accessor (spend_cap) -----------------------

    def use_model_key(self, tenant_id: str) -> str:
        """Operator/adapter-side accessor for the model key. NEVER wired to a tool.

        Enforces spend_cap as a per-tenant cap on MODEL-KEY access: one unit per call, and a call that
        would exceed the cap RAISES (fail-closed). spend_cap=None means uncapped.
        """
        if self._spend_cap is not None:
            used = self._model_key_uses.get(tenant_id, 0)
            if used >= self._spend_cap:
                raise PermissionError("model-key spend cap exceeded")
            self._model_key_uses[tenant_id] = used + 1
        return self._model_key

    # --- separate external-effect budget guard ------------------------------

    def allow_external_effect(self, tenant_id: str) -> bool:
        """A per-tenant budget/rate limit on external-effect dispatch, independent of is_valid() and
        spend_cap. Returns False once the tenant's external-effect budget is exhausted. None=uncapped.
        """
        if self._external_effect_cap is None:
            return True
        used = self._effect_uses.get(tenant_id, 0)
        if used >= self._external_effect_cap:
            return False
        self._effect_uses[tenant_id] = used + 1
        return True


def make_broker(
    *,
    model_key: str,
    tool_backing_secret: str,
    scanner=None,
    spend_cap: int | None = None,
    external_effect_cap: int | None = None,
    default_ttl_seconds: int = 900,
    clock=None,
) -> CredentialBroker:
    """Construct a CredentialBroker. On construction it registers the backing secrets onto `scanner`
    (the single path that teaches the scanner the run's secret values).

    The harness calls this as make_broker(model_key=..., tool_backing_secret=..., scanner=...,
    spend_cap=...); the remaining keyword-only parameters are local extensions with safe defaults.
    """
    return CredentialBroker(
        model_key=model_key,
        tool_backing_secret=tool_backing_secret,
        scanner=scanner,
        spend_cap=spend_cap,
        external_effect_cap=external_effect_cap,
        default_ttl_seconds=default_ttl_seconds,
        clock=clock,
    )
