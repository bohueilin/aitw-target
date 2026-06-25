"""Deployment provider — the object the harness drives.

This satisfies the host's DeploymentProvider contract STRUCTURALLY (duck typing): nothing here is
subclassed from or imported out of the operator runtime. The provider owns ONLY the runtime security
surface — how the store is exposed to the agent's tools, which tools dispatch, and which runtime
guards (output scanner / credential broker) are active. The harness owns the model/agent loop, the
scenario, the attack, the bulletin content, scoring, and telemetry.

Threading the harness performs (and that this provider is built for):

    scanner = provider.make_scanner()                       # once; a single cached instance
    broker  = provider.make_broker(model_key=..., tool_backing_secret=..., scanner=scanner,
                                   spend_cap=...)            # registers the run secrets onto scanner
    store   = provider.wrap_store(raw_store, tenant_id)      # per tenant (uses the cached scanner)
    cred    = broker.issue_tool_credential(tenant_id)
    posture = provider.posture_registry(ctx)
    task    = provider.task_registry(ctx, scanner=scanner,
                                     credential_guard=lambda: broker.is_valid(cred))

Packaging: this artifact ships ONLY the defense layer (control/ + safety/ + this provider). It runs as
a layer over the host's stock target runtime (imported as `aitw.tools`), which the host puts on the
path; the artifact does not bundle or shadow that runtime. Its own modules live under <artifact_root>/src,
so the shim below makes them importable from a bare checkout where the host loader has placed only the
artifact root on sys.path (no install step).
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

# src -> sys.path shim. Runs BEFORE any agent_runtime import so a bare checkout (root-only on the path,
# no install) can import the defense layer at <artifact_root>/src/agent_runtime.
_SRC = _Path(__file__).resolve().parent / "src"
if _SRC.is_dir() and str(_SRC) not in _sys.path:
    _sys.path.insert(0, str(_SRC))

from agent_runtime.control.broker import make_broker as _make_broker  # noqa: E402
from agent_runtime.control.enforcing_registry import EnforcingTaskRegistry, PostureRegistry  # noqa: E402
from agent_runtime.safety.output_scanner import OutputScanner  # noqa: E402
from agent_runtime.safety.scoped_store import wrap_store as _wrap_store  # noqa: E402


class Deployment:
    """The runtime security surface this artifact ships."""

    # Neutral profile id; becomes the run report `deployment` field. Not a reserved/operator id and
    # carries no version or condition label.
    name = "defense"

    def __init__(self) -> None:
        self._scanner: OutputScanner | None = None

    # --- output scanner (single cached instance) ----------------------------

    def make_scanner(self) -> OutputScanner:
        """Create and CACHE one scanner, returning the same instance on every call. The broker
        registers the run's secrets onto this instance; the scoped store and task registry redact
        through it."""
        if self._scanner is None:
            self._scanner = OutputScanner()
        return self._scanner

    # --- credential broker --------------------------------------------------

    def make_broker(self, *, model_key, tool_backing_secret, scanner, spend_cap):
        """Construct the credential broker. On construction it registers the backing secrets onto the
        scanner — the single path that teaches the scanner the run's secret values."""
        return _make_broker(
            model_key=model_key,
            tool_backing_secret=tool_backing_secret,
            scanner=scanner,
            spend_cap=spend_cap,
        )

    # --- store --------------------------------------------------------------

    def wrap_store(self, raw_store, tenant_id):
        """Return a tenant-scoped, redaction-aware view over the raw cross-tenant store. The cached
        scanner is injected so own-tenant reads come back redacted."""
        return _wrap_store(raw_store, tenant_id, scanner=self.make_scanner())

    # --- registries ---------------------------------------------------------

    def task_registry(self, ctx, *, scanner=None, credential_guard=None):
        """Task-turn registry: allow-list dispatch, result scanning, and (when given) the credential
        guard over external-effect tools. Uses the scanner the harness passes in."""
        return EnforcingTaskRegistry(
            ctx,
            scanner=scanner if scanner is not None else self.make_scanner(),
            credential_guard=credential_guard,
        )

    def posture_registry(self, ctx):
        """Posture-turn registry exposing a schema-valid, fail-closed read_operational_bulletin tool.
        May use the cached scanner (posture results are also scanned by the harness)."""
        return PostureRegistry(ctx, scanner=self.make_scanner())


# The manifest (deployment.yaml) points at this object: `provider: provider:DEPLOYMENT`.
DEPLOYMENT = Deployment()
