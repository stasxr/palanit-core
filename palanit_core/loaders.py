"""Load and normalize agent-surface files (MCP configs, tool manifests)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolDef:
    name: str
    description: str = ""
    schema: dict[str, Any] | None = None
    server: str = ""
    path: str = ""  # JSON pointer-ish path for reporting


@dataclass
class ServerDef:
    name: str
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""
    transport: str = ""
    path: str = ""


@dataclass
class Normalized:
    """Normalized view of a target file."""

    raw: Any
    servers: list[ServerDef] = field(default_factory=list)
    tools: list[ToolDef] = field(default_factory=list)


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _as_str(v: Any) -> str:
    return v if isinstance(v, str) else ""


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def normalize(raw: Any) -> Normalized:
    """Recognize common shapes: MCP server configs and tool manifests.

    Supported:
      - {"mcpServers": {name: {command, args, env, url, transport}}}
      - {"servers": {...}} (same shape)
      - {"tools": [{name, description, inputSchema|input_schema|schema}]}
      - a bare list of tool objects
      - a single tool object
    Unknown shapes still get walked for string-level rules by the engine.
    """
    norm = Normalized(raw=raw)
    if not isinstance(raw, (dict, list)):
        return norm

    if isinstance(raw, dict):
        servers_obj = raw.get("mcpServers") or raw.get("servers")
        if isinstance(servers_obj, dict):
            for name, cfg in servers_obj.items():
                if not isinstance(cfg, dict):
                    continue
                base = "mcpServers" if "mcpServers" in raw else "servers"
                norm.servers.append(
                    ServerDef(
                        name=name,
                        command=_as_str(cfg.get("command")),
                        args=[str(a) for a in _as_list(cfg.get("args"))],
                        env={str(k): str(v) for k, v in (cfg.get("env") or {}).items()}
                        if isinstance(cfg.get("env"), dict)
                        else {},
                        url=_as_str(cfg.get("url")) or _as_str(cfg.get("endpoint")),
                        transport=_as_str(cfg.get("transport") or cfg.get("type")),
                        path=f"/{base}/{name}",
                    )
                )
                # tools may be nested under a server
                for ti, tool in enumerate(_as_list(cfg.get("tools"))):
                    if isinstance(tool, dict):
                        norm.tools.append(_tool_from(tool, server=name, path=f"/{base}/{name}/tools/{ti}"))

        tools_val = raw.get("tools")
        if isinstance(tools_val, list):
            for ti, tool in enumerate(tools_val):
                if isinstance(tool, dict):
                    norm.tools.append(_tool_from(tool, path=f"/tools/{ti}"))

        # a single tool object
        if not norm.servers and not norm.tools and ("name" in raw and ("description" in raw or "inputSchema" in raw)):
            norm.tools.append(_tool_from(raw, path=""))

    elif isinstance(raw, list):
        for ti, tool in enumerate(raw):
            if isinstance(tool, dict) and "name" in tool:
                norm.tools.append(_tool_from(tool, path=f"/{ti}"))

    return norm


def _tool_from(tool: dict[str, Any], server: str = "", path: str = "") -> ToolDef:
    schema = tool.get("inputSchema") or tool.get("input_schema") or tool.get("schema")
    return ToolDef(
        name=_as_str(tool.get("name")),
        description=_as_str(tool.get("description")),
        schema=schema if isinstance(schema, dict) else None,
        server=server,
        path=path,
    )


MAX_WALK_DEPTH = 200  # guard against pathologically-nested input blowing the stack


def walk_strings(obj: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Yield (json_path, string_value) for every string in a JSON structure."""
    out: list[tuple[str, str]] = []

    def _walk(node: Any, path: str, depth: int) -> None:
        if depth > MAX_WALK_DEPTH:
            return
        if isinstance(node, str):
            out.append((path, node))
        elif isinstance(node, dict):
            for k, v in node.items():
                _walk(v, f"{path}/{k}", depth + 1)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                _walk(v, f"{path}/{i}", depth + 1)

    _walk(obj, prefix, 0)
    return out
