"""
MCPry core parsing — AST-based tool definition extraction for Python files.

Walks the Python AST of a source file and finds every function (sync or async)
that is decorated with a recognised MCP tool decorator pattern:
  @mcp.tool(...)
  @server.tool(...)
  @app.tool(...)
  @tool(...)   ← bare decorator imported from an MCP library

For each such function the parser extracts:
  - Tool name (from decorator argument or function name)
  - Description (from decorator docstring argument or function docstring)
  - Parameters (from the JSON schema dict passed to the decorator, if present)
  - Line number and file path

Returns a list of raw tool data dicts that extraction.py turns into ToolDefinition objects.
"""

from __future__ import annotations

import ast
from typing import Any

# ── Decorator name matching ────────────────────────────────────────────────────

_TOOL_DECORATOR_NAMES = {
    "tool",          # bare @tool
    "mcp.tool",      # @mcp.tool
    "server.tool",   # @server.tool
    "app.tool",      # @app.tool
    "fastmcp.tool",  # @fastmcp.tool
}


def _decorator_is_tool(node: ast.expr) -> bool:
    """Return True if *node* is a recognised MCP tool decorator."""
    if isinstance(node, ast.Name):
        return node.id in _TOOL_DECORATOR_NAMES
    if isinstance(node, ast.Attribute):
        # e.g.  mcp.tool  →  node.attr == "tool"
        if node.attr == "tool":
            return True
    if isinstance(node, ast.Call):
        return _decorator_is_tool(node.func)
    return False


# ── Keyword / literal helpers ─────────────────────────────────────────────────


def _ast_literal(node: ast.expr) -> Any:
    """
    Safely evaluate a simple AST constant / container to a Python value.
    Returns None for anything too complex to evaluate statically.
    """
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return None


def _extract_decorator_kwargs(decorator: ast.expr) -> dict[str, Any]:
    """Extract keyword arguments from a decorator Call node."""
    if not isinstance(decorator, ast.Call):
        return {}
    kwargs: dict[str, Any] = {}
    for kw in decorator.keywords:
        if kw.arg is not None:
            val = _ast_literal(kw.value)
            if val is not None:
                kwargs[kw.arg] = val
    return kwargs


# ── Parameter extraction ──────────────────────────────────────────────────────


def _parse_json_schema_params(schema: dict) -> list[dict]:
    """
    Parse an MCP input_schema dict and return a list of parameter info dicts.

    Expected shape:
        {
            "type": "object",
            "properties": {
                "param_name": {
                    "type": "string",
                    "description": "...",
                    "maxLength": 100,
                    ...
                }
            },
            "required": ["param_name"]
        }
    """
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
                    k: v
                    for k, v in prop.items()
                    if k not in ("type", "description")
                },
            }
        )

    return params


def _parse_function_annotations(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[dict]:
    """
    Fallback: extract parameter names from the function signature when no
    JSON schema is available in the decorator.
    """
    params: list[dict] = []
    args = func.args

    # Collect all arg names (skip 'self', 'cls', 'ctx', 'context')
    _skip = {"self", "cls", "ctx", "context"}

    all_args = args.posonlyargs + args.args + args.kwonlyargs
    defaults_map: dict[str, bool] = {}

    # Positional-only / regular args that have no default are "required"
    n_defaults = len(args.defaults)
    n_regular = len(args.posonlyargs) + len(args.args)
    for i, arg in enumerate(args.posonlyargs + args.args):
        has_default = i >= (n_regular - n_defaults)
        defaults_map[arg.arg] = not has_default

    for arg in args.kwonlyargs:
        defaults_map[arg.arg] = False  # kwonly with kw_defaults handled below

    for idx, arg in enumerate(args.kwonlyargs):
        kw_default = args.kw_defaults[idx] if idx < len(args.kw_defaults) else None
        defaults_map[arg.arg] = kw_default is None

    for arg in all_args:
        if arg.arg in _skip:
            continue

        annotation_str = ""
        if arg.annotation:
            try:
                annotation_str = ast.unparse(arg.annotation)
            except Exception:
                annotation_str = "unknown"

        params.append(
            {
                "name": arg.arg,
                "type": annotation_str or "string",
                "description": "",
                "required": defaults_map.get(arg.arg, False),
                "has_max_length": False,
                "has_pattern": False,
                "has_enum": False,
                "constraints": {},
            }
        )

    return params


# ── Main AST walker ───────────────────────────────────────────────────────────


def parse_python_tools(source: str, file_path: str) -> list[dict]:
    """
    Parse *source* (Python source code) and return a list of raw tool dicts.

    Each dict has the keys expected by extraction.py to build a ToolDefinition:
        name, description, file_path, line_number, parameters, raw_schema,
        has_output_schema
    """
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return []

    tools: list[dict] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Find any MCP tool decorator on this function
        tool_decorator = None
        for dec in node.decorator_list:
            if _decorator_is_tool(dec):
                tool_decorator = dec
                break

        if tool_decorator is None:
            continue

        # -- Extract name --
        kwargs = _extract_decorator_kwargs(tool_decorator)
        tool_name: str = kwargs.get("name", node.name)

        # -- Extract description --
        description: str = kwargs.get("description", "")
        if not description:
            # Fall back to the function's docstring
            docstring = ast.get_docstring(node) or ""
            description = docstring

        # -- Extract parameters --
        raw_schema: dict = {}
        has_output_schema = False

        if "input_schema" in kwargs and isinstance(kwargs["input_schema"], dict):
            raw_schema = kwargs["input_schema"]
            parameters = _parse_json_schema_params(raw_schema)
            has_output_schema = "output_schema" in kwargs
        else:
            parameters = _parse_function_annotations(node)

        tools.append(
            {
                "name": tool_name,
                "description": description,
                "file_path": file_path,
                "line_number": node.lineno,
                "parameters": parameters,
                "raw_schema": raw_schema,
                "has_output_schema": has_output_schema,
            }
        )

    return tools
