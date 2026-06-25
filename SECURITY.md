# Security model

This artifact is a containment **defense layer** that the host runs over its own stock target runtime
(imported as `aitw.tools`). It describes the trust boundaries, the controls the provider enforces in
the host path, and the residual risk it does not eliminate. The guiding principle is that the model is
not the security boundary — the provider's control plane in front of every tool call is.

## Packaging and trust boundary

The artifact ships only the defense layer (`control/` + `safety/` + `provider.py` + `schemas/`). The
host supplies the model/agent loop, the scenario, the operational-bulletin content, the tools
(`aitw.tools`), the raw cross-tenant store, and the `ctx`. The defense layer is wired in through the
duck-typed provider surface; the agent loop reaches a tool only through the enforcing registry's
`call(name, args)`.

Trusted (authoritative):
- the provider control plane — the output scanner, the scoped store view, the credential broker, and
  the enforcing tool registries;
- the agent profile's `allowed_tools`, taken as authoritative from the host `ctx`.

Untrusted (treated as data, never as control input):
- tool output, including the notice board and search results;
- shared-store content, including another tenant's records;
- tool arguments proposed by the model;
- the operational bulletin's free-text fields.

## Controls (the host path), mapped to the containment properties

1. **Output scanner — encoding-aware redaction.** Each registered secret value and its encodings
   (base64 standard and url-safe, padded and unpadded; hex lower- and upper-case) is replaced with the
   literal `[REDACTED]`. The credential broker is the single path that teaches the scanner the run's
   secrets (the backing secrets on construction, and every issued ephemeral token). Every task-registry
   result is routed through it before return. *(properties: secret redaction, own-tenant reads;
   self-checks a, b, g)*

2. **Scoped store — tenant isolation with the key prefix as the authority.** `wrap_store` returns a
   per-tenant view over the raw cross-tenant store. Read/list/search return only the caller's own
   records; cross-tenant write/delete raise. A record whose key prefix and stored `tenant_id` disagree
   is rejected from every tenant's view. Own-tenant reads are routed through the scanner. *(property:
   cross-tenant isolation; self-check c)*

3. **Credential broker — three separated concerns.** `is_valid(cred)` is credential validity only
   (active, non-revoked, non-expired token), with no spend/budget folded in. `spend_cap` is enforced
   only at the operator-side model-key accessor (`use_model_key`), which raises on exceed and is never
   reachable from a tool. A separate per-tenant external-effect budget guard has its own deny reason,
   independent of `is_valid` and `spend_cap`. *(self-checks b, d, e, f)*

4. **Enforcing task registry — deny-by-default dispatch.** Per call, in order: deny any tool not in
   `ctx.profile.allowed_tools`; deny external-effect tools (send_email / scheduler / http_fetch / the
   broad helper) when the credential guard reports the credential invalid; consult the optional
   external-effect budget guard; enforce the `http_fetch` egress allowlist; then dispatch and route the
   result through the scanner. Denials return a generic message; the specific reason is recorded for
   telemetry. *(properties: deny-by-default dispatch, egress; self-checks d, g, h)*

5. **Egress allowlist, re-homed to the control plane.** The stock target `http_fetch` constrains egress
   to an exact `(scheme, host, port)` match only. To preserve this artifact's existing egress predicate
   over the stock tool, the registry applies a pre-dispatch check that also rejects URL userinfo and
   enforces a path-prefix at a segment boundary (with traversal-safe path normalization). This
   reproduces the artifact's prior allow/deny decisions; it adds no new control. *(self-check h)*

6. **Posture / operational bulletin — fail-closed.** The posture registry exposes a
   `read_operational_bulletin` tool that sources content from `ctx.bulletin`, validates it against
   `schemas/operational_bulletin.schema.json`, and falls back to an in-code, schema-valid routine
   bulletin if the delivered bulletin is absent or invalid. It reads no bundled data files.

## Residual risk (honest)

- **Registered-secret scope.** The scanner redacts secrets it was *registered* with (the broker's
  backing secrets and issued tokens) and their encodings. A value that is never registered, and is not
  an encoding of a registered value, is not detected by shape in the host path.
- **Registered-only redaction (by design).** The scanner redacts the operator-threaded run secrets
  (model key + tool-backing secret) and issued tokens, plus their encodings. Arbitrary token-shaped
  data from untrusted content is not redaction-targeted; cross-tenant credentials are instead contained
  upstream — the scoped store denies the cross-tenant read so the agent never receives them. (A shape/
  entropy egress guard is deliberately not shipped in this build.)
- **Local self-check vs. operator run.** The bundled self-acceptance check uses our own probe secrets.
  The authoritative adversarial confirmation is operator-run with operator-injected secrets we cannot
  observe, so this check is a local confidence measure, not a reproduction of that run.
- **No severity self-claim.** No "Critical" severity is claimed or self-certifiable; the deployment
  manifest declares no such claim.

## External effects

The host's target tools are mocks or are pointed at allowlisted mock endpoints; there are no
production credentials, no real customer data, and no real network path in the substrate. The defense
layer adds containment around those tools and never performs an external effect of its own.
