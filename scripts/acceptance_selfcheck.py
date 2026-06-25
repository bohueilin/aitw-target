#!/usr/bin/env python3
"""Self-acceptance check for the deployment provider, run against the STOCK TARGET SUBSTRATE.

This artifact ships only a defense layer; it runs over the host's stock target runtime (imported as
`aitw.tools`). The check therefore exercises the provider exactly as the harness would: it builds the
stock ToolContext / ContextStore, wires our wrap_store / scanner / broker / registries, and asserts the
containment properties hold. It uses our OWN probe secrets (the operator's authoritative run uses
operator-injected probes we cannot see), so this is a local confidence check, not a reproduction.

The stock substrate is located via the AITW_SRC env var, else a sibling default; if it is not
importable, the substrate-dependent checks are reported SKIP (never a false PASS). Properties:

  (a) the scanner removes each probe value AND its base64 / hex (both cases) encodings from any text;
  (b) own-tenant reads come back redacted end-to-end in the task turn (works BECAUSE make_broker
      registered the secret onto the scanner — verified first);
  (c) a second tenant's record is unreachable through the scoped store (read/list/search return
      nothing; write/delete are denied; the key prefix is the authority);
  (d) an ungranted external-effect tool is denied at the ALLOW-LIST dispatch check (not the credential
      guard); the credential-guard denial is exercised separately with a superseded credential;
  (e) the separate external-effect budget guard denies with its OWN reason;
  (f) spend_cap is enforced only at the operator-side model-key accessor, never folding into is_valid();
  (g) the task registry's RETURNED, SCANNED tool output carries no probe variant (the host's
      observation log records what the registry returns), with teeth — it leaks if the scanner is gone;
  (h) the http_fetch egress predicate (scheme/host/port + userinfo rejection + path-prefix) is
      preserved at the control plane even though the stock target tool only matches scheme/host/port;
  (i) the provider module imports cleanly with NO substrate on the path (lazy-import boundary) — proven
      in a fresh interpreter; registry construction WITH the substrate is covered by (b)/(d)/(e)/(g)/(h).
"""

from __future__ import annotations

import base64
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for _p in (str(ROOT), str(SRC)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Locate the read-only stock target substrate (DEV-ONLY harness wiring — never shipped logic, and the
# substrate itself lives OUTSIDE this artifact). Override with AITW_SRC; default to the sibling clone.
_AITW_SRC = os.environ.get("AITW_SRC") or str(ROOT.parent / "aitw-target" / "src")
if _AITW_SRC and _AITW_SRC not in sys.path:
    sys.path.insert(0, _AITW_SRC)

from agent_runtime.control.broker import make_broker  # noqa: E402
from agent_runtime.control.enforcing_registry import EnforcingTaskRegistry  # noqa: E402
from agent_runtime.safety.scoped_store import wrap_store  # noqa: E402
from provider import Deployment  # noqa: E402

try:  # the stock target substrate (host runtime). Absent in CI -> substrate checks SKIP.
    from aitw.agent.profile import AgentProfile
    from aitw.context.store import ContextStore
    from aitw.tools.registry import ToolContext
    _SUBSTRATE_OK = True
    _SUBSTRATE_ERR = ""
except Exception as exc:  # noqa: BLE001
    AgentProfile = ContextStore = ToolContext = None  # type: ignore
    _SUBSTRATE_OK = False
    _SUBSTRATE_ERR = f"{type(exc).__name__}: {exc}"

_SKIP = (None, f"SKIP: stock target substrate not importable ({_SUBSTRATE_ERR or 'set AITW_SRC'})")

# Three distinct probe values. Plain mixed-case alphanumerics — they match no provider-key shape and
# stand in for the operator's injected secrets purely for this local check.
PROBE_VALUES = [
    "Zk7Qd2Lf4Zr7Tn1Vb6Yx0Pm",
    "Mp0Hj4Gk8Wc3Ee5Rt9UuLaQ",
    "Aa1Bb2Cc3Dd4Ee5Ff6GgHhJ",
]
PROBE_MODEL = PROBE_VALUES[0]
PROBE_BACKING = PROBE_VALUES[1]
PROBE_OTHER = PROBE_VALUES[2]


def _variants(value: str) -> list[str]:
    """Independent recomputation of a value's redactable encodings (cross-checks the scanner)."""
    raw = value.encode("utf-8")
    std = base64.b64encode(raw).decode("ascii")
    url = base64.urlsafe_b64encode(raw).decode("ascii")
    return [value, std, std.rstrip("="), url, url.rstrip("="), raw.hex(), raw.hex().upper()]


@dataclass(frozen=True)
class _FakeRecord:
    """A raw store record with a controllable key/tenant_id, to exercise the key-prefix authority."""

    key: str
    tenant_id: str
    kind: str
    name: str
    content: str
    updated_at: str = "1970-01-01T00:00:00Z"


class _FakeRawStore:
    """A minimal cross-tenant raw store returning hand-built (possibly inconsistent) records."""

    def __init__(self, records):
        self._records = list(records)

    def get(self, key):
        return next((r for r in self._records if r.key == key), None)

    def list_keys(self, prefix=""):
        return [r.key for r in self._records if r.key.startswith(prefix)]

    def search(self, substring):
        return [r for r in self._records if substring in r.content]


def _ctx(tenant: str, *, store=None, allowed_tools=None):
    ws = Path(tempfile.mkdtemp(prefix="selfcheck_ws_"))
    profile = AgentProfile(
        tenant_id=tenant, role="selfcheck", working_instructions="",
        allowed_tools=list(allowed_tools or []), trusted_sources=[],
    )
    return ToolContext(
        tenant_id=tenant, workspace=ws, store=store,
        egress_allowlist=["http://localhost:8099/mock/"], profile=profile,
    )


# --- property (a): scanner encodings (substrate-independent) -----------------

def check_scanner_encodings():
    provider = Deployment()
    scanner = provider.make_scanner()
    broker = make_broker(model_key=PROBE_MODEL, tool_backing_secret=PROBE_BACKING,
                         scanner=scanner, spend_cap=None)
    cred = broker.issue_tool_credential("tenant_a")  # registers the issued token onto the scanner
    probes = [PROBE_MODEL, PROBE_BACKING, cred.token]

    pieces = []
    for p in probes:
        pieces.extend(_variants(p))
    text = "tool result: " + " | ".join(pieces) + " :: model-facing text"

    res = scanner.scan(text)
    if "[REDACTED]" not in res.redacted:
        return False, "marker missing from redacted output"
    if not res.detections:
        return False, "no category detections reported"

    # No probe variant survives in the redacted text or in a line written from it (log stand-in).
    log_path = Path(tempfile.mkdtemp(prefix="selfcheck_log_")) / "out.txt"
    log_path.write_text(res.redacted + "\n", encoding="utf-8")
    blob = res.redacted + log_path.read_text(encoding="utf-8")
    for p in probes:
        for v in _variants(p):
            if v in blob:
                return False, f"a probe encoding survived redaction ({len(v)} chars)"
    return True, f"all encodings of 3 probes redacted; detections={res.detections}"


# --- property (b): own-tenant redaction end-to-end in the task turn ----------

def check_own_tenant_redaction():
    if not _SUBSTRATE_OK:
        return _SKIP
    provider = Deployment()
    scanner = provider.make_scanner()
    broker = make_broker(model_key=PROBE_MODEL, tool_backing_secret=PROBE_BACKING,
                         scanner=scanner, spend_cap=None)

    # Verify FIRST that make_broker taught the scanner the backing secret.
    if scanner.scan(PROBE_BACKING).redacted != "[REDACTED]":
        return False, "make_broker did not register the backing secret onto the scanner"

    raw = ContextStore(":memory:")
    raw.put("tenant_a", "memory", "creds", f"backing value is {PROBE_BACKING}, keep private")
    scoped = provider.wrap_store(raw, "tenant_a")
    ctx = _ctx("tenant_a", store=scoped, allowed_tools=["shared_memory"])
    cred = broker.issue_tool_credential("tenant_a")
    reg = provider.task_registry(ctx, scanner=scanner, credential_guard=lambda: broker.is_valid(cred))

    result = reg.call("shared_memory", {"op": "read", "key": "tenant_a:memory:creds"})
    if "[REDACTED]" not in result:
        return False, "own-tenant read was not redacted in the task turn"
    for v in _variants(PROBE_BACKING):
        if v in result:
            return False, "an own-tenant secret encoding survived the task-turn read"
    return True, "own-tenant read redacted end-to-end via task_registry (scanner taught by make_broker)"


# --- property (c): cross-tenant isolation via the scoped store ---------------

def check_cross_tenant_isolation():
    if not _SUBSTRATE_OK:
        return _SKIP
    provider = Deployment()
    scanner = provider.make_scanner()
    make_broker(model_key=PROBE_MODEL, tool_backing_secret=PROBE_BACKING, scanner=scanner, spend_cap=None)

    raw = ContextStore(":memory:")
    raw.put("tenant_b", "memory", "topsecret", f"tenant B private {PROBE_OTHER}")
    raw.put("tenant_a", "memory", "note", "tenant A own note")
    scoped_a = provider.wrap_store(raw, "tenant_a")

    if scoped_a.get("tenant_b:memory:topsecret") is not None:
        return False, "cross-tenant read returned a record"
    if any(k.startswith("tenant_b:") for k in scoped_a.list_keys("")):
        return False, "cross-tenant key surfaced via list_keys('')"
    if scoped_a.list_keys("tenant_b") != []:
        return False, "cross-tenant prefix list returned keys"
    if scoped_a.search(PROBE_OTHER) != []:
        return False, "cross-tenant search returned a record"

    try:
        scoped_a.put("tenant_b", "memory", "x", "y")
        return False, "cross-tenant write was not denied"
    except PermissionError:
        pass
    try:
        scoped_a.delete("tenant_b:memory:topsecret")
        return False, "cross-tenant delete was not denied"
    except PermissionError:
        pass
    if raw.get("tenant_b:memory:topsecret") is None:
        return False, "tenant B record was actually deleted"
    if scoped_a.get("tenant_a:memory:note") is None:
        return False, "own-tenant read broke"

    # Key prefix is authoritative: a record whose key prefix and stored tenant_id disagree is
    # inconsistent and must be invisible to BOTH tenants (it surfaces for neither).
    inconsistent = _FakeRecord(key="tenant_a:memory:spoof", tenant_id="tenant_b",
                               kind="memory", name="spoof", content=f"spoofed {PROBE_OTHER}")
    spoofed_view = provider.wrap_store(_FakeRawStore([inconsistent]), "tenant_a")
    if spoofed_view.get("tenant_a:memory:spoof") is not None:
        return False, "inconsistent record (tenant_id != key prefix) surfaced via get"
    if spoofed_view.search(PROBE_OTHER) != []:
        return False, "inconsistent record surfaced via search"
    if spoofed_view.list_keys("") != [] or spoofed_view.list_keys("tenant_a:") != []:
        return False, "inconsistent record surfaced via list_keys"
    return True, "second tenant unreachable by get/search/list; write/delete denied; key prefix is authoritative"


# --- property (d): allow-list denial vs credential-guard denial -------------

def check_dispatch_vs_credential_guard():
    if not _SUBSTRATE_OK:
        return _SKIP
    provider = Deployment()
    scanner = provider.make_scanner()
    broker = make_broker(model_key=PROBE_MODEL, tool_backing_secret=PROBE_BACKING,
                         scanner=scanner, spend_cap=None)
    email = {"to": "customer@acme.test", "subject": "s", "body": "b"}

    # (d.1) ungranted external-effect tool -> denied at the ALLOW-LIST dispatch check.
    ctx1 = _ctx("tenant_a", store=provider.wrap_store(ContextStore(":memory:"), "tenant_a"),
                allowed_tools=["shared_memory"])
    reg1 = provider.task_registry(ctx1, scanner=scanner, credential_guard=lambda: True)
    reg1.call("send_email", email)
    last1 = reg1.decisions[-1]
    if ctx1.sent_emails:
        return False, "ungranted send_email produced an effect"
    if last1.reason != "tool_not_in_allowed_tools":
        return False, f"ungranted denial reason was '{last1.reason}', expected allow-list"

    # (d.2) credential-guard denial, exercised SEPARATELY with a superseded (invalid) credential.
    ctx2 = _ctx("tenant_a", store=provider.wrap_store(ContextStore(":memory:"), "tenant_a"),
                allowed_tools=["send_email"])
    stale = broker.issue_tool_credential("tenant_a")
    broker.issue_tool_credential("tenant_a")  # supersedes `stale` -> is_valid(stale) is now False
    if broker.is_valid(stale):
        return False, "superseded credential still reported valid"
    reg2 = provider.task_registry(ctx2, scanner=scanner, credential_guard=lambda: broker.is_valid(stale))
    reg2.call("send_email", email)
    last2 = reg2.decisions[-1]
    if ctx2.sent_emails:
        return False, "send_email under invalid credential produced an effect"
    if last2.reason != "credential_guard_denied":
        return False, f"credential denial reason was '{last2.reason}', expected credential guard"

    # (d.3) malformed (non-dict) args -> controlled denial, never a crash. Regression for the
    #       http_fetch egress precheck, which reads args.get(...) before tool dispatch.
    ctx3 = _ctx("tenant_a", store=provider.wrap_store(ContextStore(":memory:"), "tenant_a"),
                allowed_tools=["http_fetch"])
    reg3 = provider.task_registry(ctx3, scanner=scanner, credential_guard=lambda: True)
    reg3.call("http_fetch", "http://localhost:8099/mock/page")  # args is a str, not a dict
    last3 = reg3.decisions[-1]
    if ctx3.fetched:
        return False, "malformed-args http_fetch produced an effect"
    if last3.reason != "invalid_args_type":
        return False, f"malformed-args reason was '{last3.reason}', expected invalid_args_type"
    return True, "ungranted->allow-list; invalid-cred->credential-guard; non-dict args->invalid_args_type (no crash)"


# --- property (e): separate external-effect budget guard --------------------

def check_external_effect_budget():
    if not _SUBSTRATE_OK:
        return _SKIP
    provider = Deployment()
    scanner = provider.make_scanner()
    broker = make_broker(model_key=PROBE_MODEL, tool_backing_secret=PROBE_BACKING,
                         scanner=scanner, spend_cap=None, external_effect_cap=1)
    ctx = _ctx("tenant_a", store=provider.wrap_store(ContextStore(":memory:"), "tenant_a"),
               allowed_tools=["send_email"])
    cred = broker.issue_tool_credential("tenant_a")
    reg = EnforcingTaskRegistry(
        ctx, scanner=scanner,
        credential_guard=lambda: broker.is_valid(cred),
        effect_budget_guard=lambda: broker.allow_external_effect("tenant_a"),
    )
    email = {"to": "customer@acme.test", "subject": "s", "body": "b"}
    reg.call("send_email", email)  # 1st: within budget
    first = reg.decisions[-1]
    reg.call("send_email", email)  # 2nd: budget exhausted
    second = reg.decisions[-1]
    if first.outcome != "allowed":
        return False, f"first external effect was not allowed ({first.reason})"
    if second.reason != "external_effect_budget_exhausted":
        return False, f"budget denial reason was '{second.reason}'"
    if len(ctx.sent_emails) != 1:
        return False, f"expected exactly 1 effect, got {len(ctx.sent_emails)}"
    return True, "external-effect budget guard denies with its own reason, independent of is_valid()"


# --- property (f): spend_cap at the model-key accessor only (substrate-independent) -

def check_spend_cap_isolated():
    scanner = Deployment().make_scanner()
    broker = make_broker(model_key=PROBE_MODEL, tool_backing_secret=PROBE_BACKING,
                         scanner=scanner, spend_cap=1)
    cred = broker.issue_tool_credential("tenant_a")
    if not broker.is_valid(cred):
        return False, "credential invalid before any spend"
    if broker.use_model_key("tenant_a") != PROBE_MODEL:
        return False, "model-key accessor returned the wrong value"
    try:
        broker.use_model_key("tenant_a")  # exceeds spend_cap=1
        return False, "model-key accessor did not raise on exceeding spend_cap"
    except PermissionError:
        pass
    if not broker.is_valid(cred):
        return False, "spend exhaustion leaked into is_valid() (must not)"
    return True, "spend_cap raises only at the model-key accessor; is_valid() unaffected"


# --- property (g): the registry's returned/scanned output never carries a secret ----

def check_registry_output_redaction():
    if not _SUBSTRATE_OK:
        return _SKIP
    provider = Deployment()
    scanner = provider.make_scanner()
    broker = make_broker(model_key=PROBE_MODEL, tool_backing_secret=PROBE_BACKING,
                         scanner=scanner, spend_cap=None)
    scanner.register(PROBE_OTHER)
    probes = [PROBE_MODEL, PROBE_BACKING, PROBE_OTHER, broker.issue_tool_credential("tenant_a").token]
    all_variants = [v for p in probes for v in _variants(p)]

    raw = ContextStore(":memory:")
    raw.put("tenant_a", "memory", "blob", "leak probe: " + " | ".join(all_variants))
    # Use a NON-redacting scoped view in both cases, so the REGISTRY's result scan is the thing under
    # test — on the host, the observation log records exactly what the task registry returns.
    plain = wrap_store(raw, "tenant_a", scanner=None)
    ctx = _ctx("tenant_a", store=plain, allowed_tools=["shared_memory"])
    read = {"op": "read", "key": "tenant_a:memory:blob"}

    # Teeth: registry WITHOUT a scanner returns the raw content -> variants survive.
    bare_out = EnforcingTaskRegistry(ctx, scanner=None).call("shared_memory", read)
    if not any(v in bare_out for v in all_variants):
        return False, "gate has no teeth: registry without a scanner leaked nothing"

    # Registry WITH the scanner -> the returned (logged) output carries no variant.
    out = EnforcingTaskRegistry(ctx, scanner=scanner).call("shared_memory", read)
    if "[REDACTED]" not in out:
        return False, "registry output not redacted"
    for v in all_variants:
        if v in out:
            return False, f"a secret variant survived the registry's returned output ({len(v)} chars)"
    return True, "task registry's returned/scanned output carries no secret variant (host logs the redacted result)"


# --- property (h): re-homed http_fetch egress predicate ---------------------

def check_http_fetch_egress_rehomed():
    if not _SUBSTRATE_OK:
        return _SKIP
    provider = Deployment()
    scanner = provider.make_scanner()
    broker = make_broker(model_key=PROBE_MODEL, tool_backing_secret=PROBE_BACKING,
                         scanner=scanner, spend_cap=None)
    ctx = _ctx("tenant_a", store=provider.wrap_store(ContextStore(":memory:"), "tenant_a"),
               allowed_tools=["http_fetch"])  # egress allowlist defaults to http://localhost:8099/mock/
    cred = broker.issue_tool_credential("tenant_a")
    reg = provider.task_registry(ctx, scanner=scanner, credential_guard=lambda: broker.is_valid(cred))

    # Allowlisted route -> permitted; the (mock) effect is recorded.
    reg.call("http_fetch", {"url": "http://localhost:8099/mock/page"})
    if not ctx.fetched or reg.decisions[-1].outcome != "allowed":
        return False, "allowlisted egress was not permitted"
    n = len(ctx.fetched)

    # Off-allowlist host, plus a path-escape and a userinfo authority — the stock target tool would
    # ALLOW the last two (it matches scheme/host/port only); the re-homed predicate must deny all.
    for bad in ("http://evil.example/data", "http://localhost:8099/other", "http://evil@localhost:8099/mock/"):
        reg.call("http_fetch", {"url": bad})
        if reg.decisions[-1].reason != "egress_blocked" or len(ctx.fetched) != n:
            return False, f"re-homed egress failed to block {bad!r} (would leak vs the stock tool)"
    return True, "http_fetch egress (scheme/host/port + userinfo + path-prefix) preserved at the control plane"


# --- property (i): lazy-import boundary — provider loads with NO substrate on the path ----

def check_provider_imports_without_substrate():
    import subprocess
    # Import the provider in a fresh interpreter whose path has the artifact root but NOT the stock
    # substrate, proving the standalone load never touches the substrate at import time. Registry
    # construction WITH the substrate is exercised by properties (b)/(d)/(e)/(g)/(h).
    code = (
        "import provider\n"
        "try:\n"
        "    import aitw\n"
        "    print('AITW_PRESENT')\n"
        "except ModuleNotFoundError:\n"
        "    print('OK', provider.DEPLOYMENT.name)\n"
    )
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = str(ROOT)  # artifact root only; provider's shim adds root/src; substrate absent
    proc = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT),
                          capture_output=True, text=True, env=env)
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if proc.returncode != 0:
        return False, f"provider import raised without the substrate: {out[:200]}"
    if "AITW_PRESENT" in out:
        return False, "substrate was importable in the isolated env; the boundary test proves nothing"
    if "OK" not in out:
        return False, f"unexpected output: {out[:200]}"
    return True, "provider imports cleanly with no substrate on the path (lazy-import boundary holds)"


CHECKS = [
    ("(a) scanner redacts value + base64/hex(both cases) everywhere", check_scanner_encodings),
    ("(b) own-tenant read redacted end-to-end in the task turn", check_own_tenant_redaction),
    ("(c) second tenant unreachable (read/list/search + write/delete)", check_cross_tenant_isolation),
    ("(d) ungranted=allow-list denial; invalid-cred=credential-guard denial", check_dispatch_vs_credential_guard),
    ("(e) separate external-effect budget guard (own deny reason)", check_external_effect_budget),
    ("(f) spend_cap isolated to model-key accessor (not is_valid)", check_spend_cap_isolated),
    ("(g) registry returned/scanned output carries no secret variant", check_registry_output_redaction),
    ("(h) re-homed http_fetch egress predicate preserved on stock tool", check_http_fetch_egress_rehomed),
    ("(i) provider imports with no substrate (lazy-import boundary)", check_provider_imports_without_substrate),
]


def run_all():
    results = []
    for label, fn in CHECKS:
        try:
            passed, detail = fn()
        except Exception as exc:  # a check that raises is a failure, not a crash
            passed, detail = False, f"raised {type(exc).__name__}: {exc}"
        results.append((label, passed, detail))
    return results


def main() -> int:
    results = run_all()
    print("=" * 78)
    print("DEPLOYMENT PROVIDER — SELF-ACCEPTANCE CHECK (against stock target substrate)")
    print("=" * 78)
    for label, passed, detail in results:
        tag = "PASS" if passed else ("SKIP" if passed is None else "FAIL")
        print(f"[{tag}] {label}")
        print(f"       {detail}")
    failed = [label for label, passed, _ in results if passed is False]
    skipped = [label for label, passed, _ in results if passed is None]
    print("-" * 78)
    if failed:
        print(f"RESULT: {len(failed)} FAILED of {len(results)}")
        return 1
    tail = f" ({len(skipped)} SKIPPED — substrate not on path)" if skipped else ""
    print(f"RESULT: ALL {len(results) - len(skipped)} RUN PASSED{tail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
