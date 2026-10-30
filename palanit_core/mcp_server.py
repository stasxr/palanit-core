"""PALANIT as an MCP server.

Exposes the Palanit Core scanner as Model Context Protocol tools, so an agent (or
an MCP client like Claude Desktop / Cursor / Cline) can scan a config on demand.

Requires the optional dependency:  pip install "palanit-core[mcp]"
Run:  palanit-mcp     (stdio transport)

The tool bodies live at module level (not as closures inside ``_build``) so they
can be unit-tested without the optional ``mcp`` dependency installed, and are
registered as MCP tools — with annotations — in ``_build``.
"""
from __future__ import annotations

import json
from typing import Any

from . import __version__
from .engine import scan_data


# --- Tool implementations ---------------------------------------------------

def scan_mcp_config(config: str) -> dict[str, Any]:
    """Scan an MCP server config or tool manifest for security issues.

    Pass the config as a JSON string (an object with "mcpServers"/"servers",
    or a "tools" array, or a single tool object). Returns findings with
    severity, location, evidence and remediation — the same engine as the
    Palanit Core CLI. Nothing is stored.
    """
    try:
        raw = json.loads(config)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"invalid JSON: {exc}"}
    result = scan_data(raw, filename="mcp-tool-input.json")
    return {"ok": True, "result": result.to_dict()}


def list_rules() -> list[dict[str, str]]:
    """List the detection rules Palanit Core applies."""
    from . import rules as rules_mod

    return [
        {"id": rid, "title": title}
        for rid, title, _fn in sorted(rules_mod.all_rules())
    ]


def version() -> str:
    """Return the Palanit Core version."""
    return __version__


# Every tool is read-only, side-effect-free and touches nothing but its input —
# no filesystem writes, no network. These MCP tool annotations advertise that to
# clients so they can surface/trust the tools appropriately.
_READ_ONLY = dict(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
_TOOLS = [
    (scan_mcp_config, "Scan MCP config"),
    (list_rules, "List detection rules"),
    (version, "Palanit Core version"),
]


# --- Server wiring ----------------------------------------------------------

def _server_class():
    """Return the MCP server class across SDK versions.

    mcp 2.x renamed FastMCP -> MCPServer; mcp 1.x uses FastMCP. The decorator
    (`.tool()`) and `.run()` ergonomics are the same, so either works here.
    """
    try:
        from mcp.server.mcpserver import MCPServer  # mcp >= 2.0

        return MCPServer
    except Exception:
        pass
    try:
        from mcp.server.fastmcp import FastMCP  # mcp 1.x

        return FastMCP
    except Exception as exc:  # pragma: no cover - optional dep missing
        raise SystemExit(
            "The MCP server needs the optional 'mcp' dependency.\n"
            "Install it with:  pip install \"palanit-core[mcp]\"\n"
            f"(import error: {exc})"
        )


def _annotations(title: str):
    """Build a ToolAnnotations object, or None on SDKs too old to have the type."""
    try:
        from mcp.types import ToolAnnotations

        return ToolAnnotations(title=title, **_READ_ONLY)
    except Exception:  # pragma: no cover - older mcp without ToolAnnotations
        return None


def _register(mcp, fn, title) -> None:
    """Register `fn` as an MCP tool, with annotations when the SDK supports them."""
    ann = _annotations(title)
    if ann is not None:
        try:
            mcp.tool(annotations=ann)(fn)
            return
        except TypeError:  # pragma: no cover - .tool() predates `annotations`
            pass
    mcp.tool()(fn)


def _build():
    mcp = _server_class()("palanit")
    for fn, title in _TOOLS:
        _register(mcp, fn, title)
    return mcp


def main() -> None:
    _build().run()


if __name__ == "__main__":
    main()
