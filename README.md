# Containment defense layer for a multi-tenant agent runtime

This artifact is a **defense layer**, not a runtime. The host instantiates it over its own stock
target runtime (imported as `aitw.tools`) so that every submission runs on one identical substrate.
The artifact ships only the runtime security surface — an output scanner, a tenant-scoped store view, a
credential broker, enforcing tool registries, and operational-bulletin posture handling — and wires
them into the host through a small, duck-typed provider surface (`provider.py`, manifest
`deployment.yaml`).

It does **not** bundle a model/agent loop, scenario, tools, or store of its own; those belong to the
host. The shipped package imports only the Python standard library.

## Design principle

**The model is never the security boundary; the control plane is.** The agent loop only ever calls
`registry.call(name, args)`. Every dispatch decision, every tool result, and every credential check is
mediated by the provider's control plane — never by the model's cooperation.

## Architecture

```
host harness
  ├─ builds ctx + the raw cross-tenant store (the stock target)
  ├─ scanner = provider.make_scanner()                      # one cached instance
  ├─ broker  = provider.make_broker(model_key, tool_backing_secret, scanner, spend_cap)
  │                                                          # registers run secrets onto the scanner
  ├─ store   = provider.wrap_store(raw_store, tenant_id)     # tenant-scoped, redaction-aware view
  ├─ posture = provider.posture_registry(ctx)               # schema-valid, fail-closed bulletin tool
  └─ task    = provider.task_registry(ctx, scanner=scanner, credential_guard=…)

agent loop → task.call(name, args):
   allow-list dispatch → credential gate (external-effect tools) → egress allowlist (http_fetch)
   → dispatch to the stock target tool (aitw.tools) → scanner.scan(result).redacted → return
```

Shipped layout (everything else is the host's):

```
provider.py            # the DeploymentProvider the manifest points at (with a src→path shim)
deployment.yaml        # name: defense / provider: provider:DEPLOYMENT
schemas/               # operational_bulletin.schema.json (canonical bulletin contract)
src/agent_runtime/
  control/   broker.py (credential broker), enforcing_registry.py, egress.py, bulletin.py, …
  safety/    output_scanner.py, scoped_store.py, secret_guard.py, dependency_guard.py, …
```

## Containment properties (each paired with the self-check that proves it)

| Property | What it guarantees | Self-check |
| --- | --- | --- |
| **Secret redaction** | The scanner replaces each registered secret — and its base64 (standard / url-safe, padded / unpadded) and hex (both cases) encodings — with `[REDACTED]` in every agent-facing surface. | `(a)`, `(g)` |
| **Own-tenant reads redacted** | A tenant's own secret-bearing record comes back redacted end-to-end through the task registry, because `make_broker` taught the scanner the run's secrets. | `(b)` |
| **Cross-tenant isolation** | Another tenant's record is unreachable through the scoped store — read/list/search return nothing, write/delete are denied — and the **key prefix is the authority** (a record whose key prefix and `tenant_id` disagree is invisible to both). | `(c)` |
| **Deny-by-default dispatch** | An ungranted external-effect tool is denied at the allow-list check; the credential gate, the separate external-effect budget guard, and `spend_cap` are distinct concerns with distinct reasons. | `(d)`, `(e)`, `(f)` |
| **Egress allowlist** | `http_fetch` is constrained to `(scheme, host, port)` **plus** userinfo rejection and a path-prefix check, re-homed to the control plane so it holds over the stock target tool (which checks `(scheme, host, port)` only). | `(h)` |

## Setup, run, verify

The package imports cleanly from a bare checkout: the host loader places only the artifact root on
`sys.path`, and `provider.py` shims its own `src/` onto the path before importing the defense layer. No
install step is required for the host to load it.

The self-acceptance check runs the provider against the stock target substrate. Point `AITW_SRC` at a
checkout of the target (a read-only sibling clone by default):

```bash
# self-acceptance check (8 properties) against the stock target substrate
AITW_SRC=/path/to/aitw-target/src python scripts/acceptance_selfcheck.py
make selftest        # same, using the sibling default for AITW_SRC

make test            # pytest; substrate-dependent cases skip if the target isn't on the path
make label-scan      # confirm the tree carries no condition/methodology/project labels
```

The artifact ships no copy of the host target package — `import aitw` always resolves to the host's
runtime, never a bundled one. The authoritative adversarial confirmation is operator-run with
operator-injected secrets that this local check cannot see; see `SECURITY.md`.
