"""Configuration constants and settings for MCPry."""

import os
from pathlib import Path


# ── Version ──────────────────────────────────────────────────────────────────
VERSION = "1.0.0"
APP_NAME = "MCPry"
APP_TAGLINE = "Pry open your MCP server's security flaws before attackers do."

# ── File Extensions to Scan ──────────────────────────────────────────────────
PYTHON_EXTENSIONS = {".py"}
JS_TS_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".mts", ".cts"}
JSON_EXTENSIONS = {".json"}
ALL_SCANNABLE_EXTENSIONS = PYTHON_EXTENSIONS | JS_TS_EXTENSIONS | JSON_EXTENSIONS

# ── Directories to Skip ──────────────────────────────────────────────────────
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
    ".egg-info", ".tox", ".nox", "htmlcov", ".coverage",
}

# ── Max File Size (skip files larger than this) ──────────────────────────────
MAX_FILE_SIZE_BYTES = 1_000_000  # 1 MB

# ── LLM Configuration ───────────────────────────────────────────────────────
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = os.environ.get("MCPRY_GEMINI_MODEL", "gemini-2.5-flash")
LLM_MAX_RETRIES = 3
LLM_RETRY_DELAY_SECONDS = 2
LLM_TIMEOUT_SECONDS = 30
LLM_MAX_TOKENS_PER_REQUEST = 8000

# ── Scoring Thresholds ───────────────────────────────────────────────────────
GRADE_THRESHOLDS = {
    "A": 90,
    "B": 75,
    "C": 60,
    "D": 40,
    "F": 0,
}

SEVERITY_DEDUCTIONS = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 0,
}

# ── Temp Directory for Cloning ───────────────────────────────────────────────
TEMP_CLONE_DIR = Path.home() / ".mcpry_temp"

# ── Report Defaults ──────────────────────────────────────────────────────────
DEFAULT_OUTPUT_FORMAT = "terminal"
SUPPORTED_OUTPUT_FORMATS = {"terminal", "json", "html"}

# ── Credential Patterns ─────────────────────────────────────────────────────
# High-confidence regex patterns for detecting hardcoded secrets
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['\"][A-Za-z0-9/+=]{40}['\"]",
    "Generic API Key Assignment": r"(?i)(?:api[_\-]?key|apikey|api_secret)\s*[=:]\s*['\"][A-Za-z0-9\-_.]{16,}['\"]",
    "Generic Token Assignment": r"(?i)(?:auth[_\-]?token|access[_\-]?token|bearer[_\-]?token|secret[_\-]?token)\s*[=:]\s*['\"][A-Za-z0-9\-_.]{16,}['\"]",
    "Generic Password Assignment": r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
    "GitHub Token": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Token": r"xox[bporas]-[0-9]{10,}-[A-Za-z0-9\-]+",
    "Private Key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
    "OpenAI API Key": r"sk-[A-Za-z0-9]{32,}",
    "Anthropic API Key": r"sk-ant-[A-Za-z0-9\-_]{32,}",
    "Base64 Encoded Secret (long)": r"(?i)(?:secret|key|token|password)\s*[=:]\s*['\"][A-Za-z0-9+/]{40,}={0,2}['\"]",
}

# ── Dangerous Function Patterns ──────────────────────────────────────────────
PYTHON_DANGEROUS_SINKS = {
    "eval", "exec", "compile", "execfile",
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "os.system", "os.popen", "os.exec", "os.execvp",
    "os.spawn", "os.spawnl", "os.spawnle",
}

JS_DANGEROUS_SINKS = {
    "eval",
    "Function(",
    "child_process.exec",
    "child_process.execSync",
    "child_process.spawn",
    "child_process.spawnSync",
    "require('child_process')",
}

# ── Tool Poisoning Patterns ──────────────────────────────────────────────────
POISONING_KEYWORDS = [
    "ignore previous",
    "ignore above",
    "disregard",
    "override",
    "system prompt",
    "you are now",
    "forget everything",
    "new instructions",
    "act as",
    "pretend",
    "jailbreak",
    "do anything now",
    "developer mode",
    "ignore all previous instructions",
    "bypass",
    "unrestricted",
]
