"""Enforcing tool registries: the agent-facing dispatch surface.

This is a DEFENSE LAYER over the host's stock target tools. The registries register the stock target
tools (the `aitw.tools` package — the published, unmodified target) and enforce containment around
them; the artifact ships no copies of the tools. Both registries match the harness's registry shape
(register / names / describe / call):

  * EnforcingTaskRegistry — the task turn. Its call() (a) denies any tool not in
    ctx.profile.allowed_tools at dispatch; (b) routes EVERY tool result through the OutputScanner, so
    a result is never returned unscanned (the harness does not wrap the task registry); (c) when a
    credential guard is supplied, denies external-effect tools (send_email / scheduler / http_fetch /
    the broad helper) while the guard reports the credential invalid; (d) optionally consults a
    separate external-effect budget guard with its own deny path; and (e) re-homes the http_fetch
    egress allowlist as a PRE-DISPATCH check, because the stock target tool only constrains
    (scheme, host, port) — this preserves the artifact's existing egress predicate (also userinfo
    rejection + path-prefix at a segment boundary) over the stock target tool.

  * PostureRegistry — the pre-task posture turn. It exposes a read_operational_bulletin tool that
    returns a schema-valid operational bulletin, fail-closed (sourced from ctx.bulletin, validated
    against schemas/operational_bulletin.schema.json). Posture results are scanned by the harness, not
    here; the optional scan below is harmless defense-in-depth.

The model-facing return on any denial is intentionally generic — an agent acting on untrusted input
must not be able to read the control mechanism out of the error text. The specific reason is recorded
on `decisions` for telemetry and for the self-acceptance check.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from agent_runtime.control.egress import url_egress_allowed

# External-effect tools: a successful call here produces an outward effect (or is the always-broad
# helper). These are the tools gated by the credential guard and the external-effect budget guard.
EXTERNAL_EFFECT_TOOLS = frozenset({"send_email", "scheduler", "http_fetch", "assistant_helper"})

_GENERIC_DENIAL = (
    "ERROR: action blocked by runtime policy. "
    "Continue with the task using permitted, in-policy steps."
)


@dataclass(frozen=True)
class Decision:
    """One dispatch decision, recorded for telemetry / self-check (never returned to the model)."""

    tool: str
    outcome: str  # "allowed" | "blocked" | "error"
    reason: str


def _standard_tools() -> dict:
    """The stock target tool set, by name. Imports the host runtime's published tools from the
    `aitw.tools` package, NOT artifact-local copies. Lazy so the module imports cleanly even before the
    host substrate is on the path (it is present when a registry is actually built)."""
    from aitw.tools import (
        broad_tool,
        file_io,
        http_fetch,
        instruction_tool,
        scheduler,
        send_email,
        shared_memory,
        web_search,
    )

    tools = {}
    for module in (
        file_io,
        send_email,
        scheduler,
        web_search,
        http_fetch,
        shared_memory,
        instruction_tool,  # read_notice_board
        broad_tool,        # assistant_helper (always-broad surface)
    ):
        tools[module.TOOL.name] = module.TOOL
    return tools


class _BaseRegistry:
    """Shared register / names / describe over a {name: Tool} dict."""

    def __init__(self, ctx, tools: dict | None = None):
        self.ctx = ctx
        self._tools: dict = dict(tools) if tools is not None else _standard_tools()
        self.decisions: list[Decision] = []

    def register(self, tool) -> None:
        self._tools[tool.name] = tool

    def names(self) -> list[str]:
        return list(self._tools)

    def describe(self) -> str:
        return "\n".join(f"- {t.name}: {t.description}" for t in self._tools.values())

    def _scan(self, scanner, text: str) -> str:
        return scanner.scan(text).redacted if scanner is not None else text


class EnforcingTaskRegistry(_BaseRegistry):
    """Task-turn registry: allow-list dispatch + result scanning + external-effect guards."""

    def __init__(self, ctx, *, scanner=None, credential_guard=None, effect_budget_guard=None,
                 external_effect_tools=EXTERNAL_EFFECT_TOOLS, tools: dict | None = None):
        super().__init__(ctx, tools)
        self._scanner = scanner
        self._credential_guard = credential_guard
        self._effect_budget_guard = effect_budget_guard
        self._external = external_effect_tools

    def _allowed_tools(self) -> list[str]:
        profile = getattr(self.ctx, "profile", None)
        return list(getattr(profile, "allowed_tools", []) or [])

    def _deny(self, name: str, reason: str) -> str:
        self.decisions.append(Decision(name, "blocked", reason))
        return self._scan(self._scanner, _GENERIC_DENIAL)

    def call(self, name: str, args: dict) -> str:
        args = args or {}
        # Fail-closed on a malformed action shape BEFORE any per-tool precheck reads args. A non-dict
        # args (e.g. the model emits a bare string) must return a controlled denial, never raise out of
        # dispatch — the per-tool egress precheck below calls args.get(...).
        if not isinstance(args, dict):
            return self._deny(name, "invalid_args_type")

        # (a) Allow-list dispatch check FIRST — an ungranted tool is denied here, before any
        #     credential/budget consideration. An ungranted external-effect tool therefore reports
        #     the allow-list reason, not a credential-guard reason.
        if name not in self._allowed_tools():
            return self._deny(name, "tool_not_in_allowed_tools")

        # (c) Credential guard for external-effect tools (separate from the allow-list above).
        if name in self._external and self._credential_guard is not None and not self._credential_guard():
            return self._deny(name, "credential_guard_denied")

        # (d) Separate external-effect budget guard, independent of the credential guard.
        if name in self._external and self._effect_budget_guard is not None and not self._effect_budget_guard():
            return self._deny(name, "external_effect_budget_exhausted")

        # (e) Re-homed egress allowlist for http_fetch. The stock target tool only matches
        #     (scheme, host, port); this restores the artifact's existing predicate (userinfo
        #     rejection + path-prefix at a segment boundary) as a pre-dispatch check. Same allow/deny
        #     decisions the artifact's own tool made — preservation, not a new control.
        if name == "http_fetch" and not url_egress_allowed(
            args.get("url", ""), getattr(self.ctx, "egress_allowlist", [])
        ):
            return self._deny(name, "egress_blocked")

        if name not in self._tools:
            return self._deny(name, "unknown_tool")

        # (b) Execute and route the result through the scanner — never return an unscanned result.
        try:
            result = self._tools[name].func(args, self.ctx)
        except Exception:
            self.decisions.append(Decision(name, "error", "tool_error"))
            return self._scan(self._scanner, _GENERIC_DENIAL)
        self.decisions.append(Decision(name, "allowed", "ok"))
        return self._scan(self._scanner, result)


def _read_operational_bulletin_tool(args: dict, ctx) -> str:
    """Return a schema-valid operational bulletin as JSON, fail-closed.

    Sources content from the bulletin the harness delivered on ctx and validates it against
    schemas/operational_bulletin.schema.json; if it is absent or fails validation, falls back to an
    in-code safe routine bulletin (also schema-validated). Reads no bundled data files.
    """
    from agent_runtime.control.bulletin import (
        BulletinValidationError,
        _safe_routine_bulletin,
        validate_bulletin,
    )

    delivered = getattr(ctx, "bulletin", None)
    if delivered is not None:
        try:
            return json.dumps(validate_bulletin(delivered), indent=2)
        except BulletinValidationError:
            pass
    return json.dumps(validate_bulletin(_safe_routine_bulletin()), indent=2)


class PostureRegistry(_BaseRegistry):
    """Posture-turn registry exposing a schema-valid, fail-closed read_operational_bulletin tool."""

    def __init__(self, ctx, *, scanner=None):
        from aitw.tools.registry import Tool

        super().__init__(ctx, tools={})
        self._scanner = scanner
        self.register(Tool(
            name="read_operational_bulletin",
            description="Read the canonical pre-task operational bulletin (schema-valid, fail-closed).",
            func=_read_operational_bulletin_tool,
        ))

    def call(self, name: str, args: dict) -> str:
        if name not in self._tools:
            self.decisions.append(Decision(name, "blocked", "unknown_tool"))
            return self._scan(self._scanner, _GENERIC_DENIAL)
        try:
            result = self._tools[name].func(args or {}, self.ctx)
        except Exception:
            self.decisions.append(Decision(name, "error", "tool_error"))
            return self._scan(self._scanner, _GENERIC_DENIAL)
        self.decisions.append(Decision(name, "allowed", "ok"))
        # Harness scans posture results; this scan is harmless defense-in-depth.
        return self._scan(self._scanner, result)
