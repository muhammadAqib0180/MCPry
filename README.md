# 🔍 MCPry

**Pry open your MCP server's security flaws before attackers do.**

MCPry is a production-grade security scanner for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers. It performs static pattern analysis + LLM-powered semantic reasoning to detect vulnerabilities, hallucination-based risks, and OWASP MCP Top 10 violations — then explains every finding in plain English with concrete fixes.

---

## ✨ Features

- **🛡️ OWASP MCP Top 10 Coverage** — Checks mapped to the industry standard framework
- **🔬 Static Analysis** — AST-based (Python) and regex-based (JS/TS) vulnerability detection
- **🧠 LLM Semantic Analysis** — Gemini-powered detection of hallucination-based vulnerabilities (HBVs)
- **📝 Explanation-First** — Every finding includes a plain-English explanation + concrete fix
- **📊 A-F Grading** — Instant security score with severity-ranked findings
- **🎨 Beautiful Reports** — Rich terminal output, structured JSON, and stunning dark-mode HTML reports
- **⚡ Zero Config** — Single command, no setup required
- **🔓 Offline Mode** — Static-only analysis works without any API key

## 🚀 Quick Start

```bash
# Install
pip install mcpry

# Scan a local MCP server
mcpry scan ./my-mcp-server

# Scan a GitHub repository
mcpry scan https://github.com/user/mcp-server

# Generate an HTML report
mcpry scan ./my-mcp-server --format html --output report.html

# Static-only mode (no API key needed)
mcpry scan ./my-mcp-server --no-llm
```

## 📋 OWASP MCP Top 10 Coverage

| Category | Title | Status |
|----------|-------|--------|
| MCP01 | Token Mismanagement & Secret Exposure | ✅ |
| MCP02 | Privilege Escalation via Scope Creep | ✅ |
| MCP03 | Tool Poisoning | ✅ |
| MCP05 | Command Injection & Execution | ✅ |
| MCP07 | Insufficient Authentication & Authorization | ✅ |
| MCP10 | Context Injection & Over-Sharing | ✅ |

## 🏗️ Architecture

```
mcpry/
├── src/mcpry/
│   ├── core/          # Ingestion, parsing, extraction
│   ├── analyzers/
│   │   ├── static/    # Pattern-based vulnerability checks
│   │   └── semantic/  # LLM-powered analysis
│   ├── reporters/     # Terminal, JSON, HTML output
│   ├── scoring/       # A-F grading system
│   ├── cli.py         # Typer CLI interface
│   ├── config.py      # Configuration & constants
│   └── models.py      # Pydantic data models
├── web/               # Web dashboard
├── test-server/       # Deliberately vulnerable MCP server
└── tests/             # Test suite
```

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
