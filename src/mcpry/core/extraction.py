"""
MCPry core extraction — orchestrates tool extraction across all file types.

Responsibilities:
  - Python: delegates to parsing.py (AST-based)
  - JavaScript/TypeScript: regex-based extraction of server.tool() / mcp.tool() calls
  - JSON: parses MCP config files (mcpServers blocks, tool arrays)
  - Merges all results into a unified list[ToolDefinition]
"""

from __future__ import annotations

import json
import re
from typing import Any

from mcpry.models import FileManifest, ToolDefinition, ToolParameter

from .parsing import parse_python_tools

# ── JS/TS regex patterns ──────────────────────────────────────────────────────

# Matches: server.tool("name", "description", schema, handler)
#          mcp.tool("name", { description: "...", inputSchema: {...} })
#          app.tool("name", ...)
_JS_TOOL_RE = re.compile(
    r"""
    (?:server|mcp|app|fastmcp)             # receiver object
    \s*\.\s*tool\s*\(                      # .tool(
    \s*                                    # optional whitespace
    ['"]([^'"]+)['"]                       # capture tool name (string literal)
    """,
    re.VERBOSE,
)

# Matches: description: "some text"  or  description: 'some text'
_JS_DESC_RE = re.compile(r"""description\s*:\s*['"]([^'"]{0,500})['"]""")

# Matches: title: "some text"  used in some MCP SDKs
_JS_TITLE_RE = re.compile(r"""title\s*:\s*['"]([^'"]{0,200})['"]""")


def _extract_js_tools(content: str, file_path: str) -> list[dict]:
    """
    Regex-based extraction of tool definitions from JS/TS source files.
    Returns raw dicts compatible with _build_tool_definition().
    """
    tools: list[dict] = []
    lines = content.splitlines()

    for i, line in enumerate(lines, start=1):
        m = _JS_TOOL_RE.search(line)
        if not m:
            continue

        tool_name = m.group(1)

        # Look ahead up to 20 lines for a description
        description = ""
        lookahead = "\n".join(lines[i - 1 : i + 20])
        desc_m = _JS_DESC_RE.search(lookahead)
        if desc_m:
            description = desc_m.group(1)
        else:
            title_m = _JS_TITLE_RE.search(lookahead)
            if title_m:
                description = title_m.group(1)

        tools.append(
            {
                "name": tool_name,
                "description": description,
                "file_path": file_path,
                "line_number": i,
                "parameters": [],
                "raw_schema": {},
                "has_output_schema": False,
            }
        )

    return tools


# ── JSON extraction ───────────────────────────────────────────────────────────


def _extract_json_tools(content: str, file_path: str) -> list[dict]:
    """
    Parse MCP-related JSON config files and extract tool/server definitions.

    Handles:
      - Claude Desktop config: {"mcpServers": {"name": {"command": "..."}}}
      - Generic tool arrays:   {"tools": [{"name": "...", "description": "..."}]}
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    tools: list[dict] = []

    if not isinstance(data, dict):
        return []

    # Claude Desktop / MCP host config format
    if "mcpServers" in data:
        for server_name, server_cfg in data["mcpServers"].items():
            if not isinstance(server_cfg, dict):
                continue
            tools.append(
                {
                    "name": server_name,
                    "description": server_cfg.get("description", ""),
                    "file_path": file_path,
                    "line_number": 0,
                    "parameters": [],
                    "raw_schema": server_cfg,
                    "has_output_schema": False,
                }
            )

    # Explicit tools array (some MCP manifest formats)
    if "tools" in data and isinstance(data["tools"], list):
        for tool_entry in data["tools"]:
            if not isinstance(tool_entry, dict):
                continue
            name = tool_entry.get("name", "")
            if not name:
                continue

            raw_schema = tool_entry.get("inputSchema", tool_entry.get("input_schema", {}))
            parameters = _parse_schema_params(raw_schema) if isinstance(raw_schema, dict) else []

            tools.append(
                {
                    "name": name,
                    "description": tool_entry.get("description", ""),
                    "file_path": file_path,
                    "line_number": 0,
                    "parameters": parameters,
                    "raw_schema": raw_schema,
                    "has_output_schema": "outputSchema" in tool_entry or "output_schema" in tool_entry,
                }
            )

    return tools


def _parse_schema_params(schema: dict) -> list[dict]:
    """Parse a JSON Schema properties dict into parameter info dicts."""
    params: list[dict] = []
    properties = schema.get("properties", {})
    required_set = set(schema.get("required", []))

    for name, prop in properties.items():
        if not isinstance(prop, dict):
            continue
        params.append(
            {
                "name": name,
                "type": prop.get("type", "string"),
                "description": prop.get("description", ""),
                "required": name in required_set,
                "has_max_length": "maxLength" in prop,
                "has_pattern": "pattern" in prop,
                "has_enum": "enum" in prop,
                "constraints": {
                    k: v for k, v in prop.items() if k not in ("type", "description")
                },
            }
        )
    return params


# ── Model builder ─────────────────────────────────────────────────────────────


def _build_tool_definition(raw: dict) -> ToolDefinition:
    """Convert a raw tool dict into a ToolDefinition Pydantic model."""
    parameters = [
        ToolParameter(
            name=p["name"],
            type=p.get("type", "string"),
            description=p.get("description", ""),
            required=p.get("required", False),
            has_max_length=p.get("has_max_length", False),
            has_pattern=p.get("has_pattern", False),
            has_enum=p.get("has_enum", False),
            constraints=p.get("constraints", {}),
        )
        for p in raw.get("parameters", [])
    ]

    return ToolDefinition(
        name=raw["name"],
        description=raw.get("description", ""),
        file_path=raw.get("file_path", ""),
        line_number=raw.get("line_number", 0),
        parameters=parameters,
        raw_schema=raw.get("raw_schema", {}),
        has_output_schema=raw.get("has_output_schema", False),
    )


# ── Public API ────────────────────────────────────────────────────────────────


def extract_tools(manifest: FileManifest) -> list[ToolDefinition]:
    """
    Extract all MCP tool definitions from every file in *manifest*.

    Dispatches to the appropriate extractor per language:
      - Python  → AST parser (parsing.py)
      - JS/TS   → regex extractor
      - JSON    → config / manifest parser

    Returns a deduplicated list of ToolDefinition objects.
    """
    raw_tools: list[dict] = []

    for scanned_file in manifest.files:
        if scanned_file.language == "python":
            raw_tools.extend(
                parse_python_tools(scanned_file.content, scanned_file.path)
            )
        elif scanned_file.language in ("javascript", "typescript"):
            raw_tools.extend(
                _extract_js_tools(scanned_file.content, scanned_file.path)
            )
        elif scanned_file.language == "json":
            raw_tools.extend(
                _extract_json_tools(scanned_file.content, scanned_file.path)
            )

    # Build ToolDefinition objects, deduplicating by (name, file_path)
    seen: set[tuple[str, str]] = set()
    tools: list[ToolDefinition] = []

    for raw in raw_tools:
        key = (raw.get("name", ""), raw.get("file_path", ""))
        if key in seen:
            continue
        seen.add(key)
        tools.append(_build_tool_definition(raw))

    return tools
