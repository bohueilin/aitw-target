"""Control plane for the defense layer.

The containment controls the host path uses live in submodules and are imported directly from them
(e.g. `from agent_runtime.control.broker import make_broker`, `from agent_runtime.control.
enforcing_registry import EnforcingTaskRegistry`): the credential broker (broker.py), the enforcing
tool registries (enforcing_registry.py), the route-level egress check (egress.py), and the
operational-bulletin schema validation (bulletin.py). This package exposes no re-exports of its own,
so importing it pulls in nothing beyond what a caller explicitly imports.
"""
