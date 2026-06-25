"""Containment defense layer for a multi-tenant agent runtime.

This package ships only the runtime security surface — the credential broker, output scanner, scoped
store, enforcing tool registries, and operational-bulletin posture handling (control/ + safety/). It
is designed to run as a defense layer over the host's stock target runtime (imported as `aitw.tools`);
it does not bundle a model/agent loop, scenario, or tools of its own. See README.md and SECURITY.md.
"""

__version__ = "2.0.0"
