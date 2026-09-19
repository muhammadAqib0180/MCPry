"""
Pydantic data models for MCPry.

Defines the core data structures used throughout the scanner pipeline:
findings, reports, severity levels, OWASP categories, and tool definitions.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, computed_field


# ── Enums ────────────────────────────────────────────────────────────────────


class Severity(str, Enum):
    """Severity levels for security findings, ordered from most to least severe."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def emoji(self) -> str:
        return {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "⚪",
        }[self.value]

    @property
    def color(self) -> str:
        """Rich console color name."""
        return {
            "CRITICAL": "red",
            "HIGH": "bright_red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim",
        }[self.value]

    @property
    def html_color(self) -> str:
        """Hex color for HTML reports."""
        return {
            "CRITICAL": "#ff4757",
            "HIGH": "#ff6b35",
            "MEDIUM": "#ffa502",
            "LOW": "#3742fa",
            "INFO": "#747d8c",
        }[self.value]


class Confidence(str, Enum):
    """Confidence level of a finding."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class OWASPCategory(str, Enum):
    """OWASP MCP Top 10 categories (2025)."""

    MCP01 = "MCP01"
    MCP02 = "MCP02"
    MCP03 = "MCP03"
    MCP04 = "MCP04"
    MCP05 = "MCP05"
    MCP06 = "MCP06"
    MCP07 = "MCP07"
    MCP08 = "MCP08"
    MCP09 = "MCP09"
    MCP10 = "MCP10"

    @property
    def title(self) -> str:
        return {
            "MCP01": "Token Mismanagement & Secret Exposure",
            "MCP02": "Privilege Escalation via Scope Creep",
            "MCP03": "Tool Poisoning",
            "MCP04": "Supply Chain Attacks & Dependency Tampering",
            "MCP05": "Command Injection & Execution",
            "MCP06": "Prompt Injection via Contextual Payloads",
            "MCP07": "Insufficient Authentication & Authorization",
            "MCP08": "Lack of Audit and Telemetry",
            "MCP09": "Shadow MCP Servers",
            "MCP10": "Context Injection & Over-Sharing",
        }[self.value]

    @property
    def description(self) -> str:
        return {
            "MCP01": "Hard-coded credentials, long-lived tokens, or secrets stored in model memory/logs.",
            "MCP02": "Permissions granted to an agent expand beyond the principle of least privilege.",
            "MCP03": "Malicious instructions injected into tool descriptions or parameter schemas.",
            "MCP04": "Compromise of MCP server dependencies or the broader software supply chain.",
            "MCP05": "Insecure input handling enabling unauthorized command or code execution.",
            "MCP06": "Malicious payloads hidden within the context passed to the model.",
            "MCP07": "Missing or weak identity verification and authorization boundary enforcement.",
            "MCP08": "Insufficient logging and monitoring to detect or respond to attacks.",
            "MCP09": "Unauthorized, unmanaged MCP servers that bypass security oversight.",
            "MCP10": "Excessive or inappropriate context injected into the model's communication flow.",
        }[self.value]


class AnalysisSource(str, Enum):
    """Where a finding originated."""

    STATIC = "STATIC"
    SEMANTIC = "SEMANTIC"
    COMBINED = "COMBINED"


# ── Tool Definition Model ────────────────────────────────────────────────────


class ToolParameter(BaseModel):
    """A parameter from an MCP tool's input schema."""

    name: str
    type: str = "string"
    description: str = ""
    required: bool = False
    has_max_length: bool = False
    has_pattern: bool = False
    has_enum: bool = False
    constraints: dict = Field(default_factory=dict)


class ToolDefinition(BaseModel):
    """An extracted MCP tool definition from source code."""

    name: str
    description: str = ""
    file_path: str = ""
    line_number: int = 0
    parameters: list[ToolParameter] = Field(default_factory=list)
    raw_schema: dict = Field(default_factory=dict)
    has_output_schema: bool = False

    @property
    def has_description(self) -> bool:
        return bool(self.description.strip())

    @property
    def unbounded_string_params(self) -> list[ToolParameter]:
        """Parameters that are unbounded strings (no maxLength, no pattern, no enum)."""
        return [
            p
            for p in self.parameters
            if p.type == "string"
            and not p.has_max_length
            and not p.has_pattern
            and not p.has_enum
        ]


# ── File Manifest Model ─────────────────────────────────────────────────────


class ScannedFile(BaseModel):
    """A file discovered during ingestion."""

    path: str
    relative_path: str
    language: str  # "python", "javascript", "typescript", "json"
    size_bytes: int = 0
    content: str = ""

    @property
    def extension(self) -> str:
        from pathlib import Path as _Path

        return _Path(self.path).suffix.lower()


class FileManifest(BaseModel):
    """The complete set of files discovered for scanning."""

    target_path: str
    is_git_repo: bool = False
    files: list[ScannedFile] = Field(default_factory=list)

    @property
    def python_files(self) -> list[ScannedFile]:
        return [f for f in self.files if f.language == "python"]

    @property
    def js_ts_files(self) -> list[ScannedFile]:
        return [f for f in self.files if f.language in ("javascript", "typescript")]

    @property
    def json_files(self) -> list[ScannedFile]:
        return [f for f in self.files if f.language == "json"]


# ── Finding Model ────────────────────────────────────────────────────────────


class Finding(BaseModel):
    """A single security finding detected by MCPry."""

    title: str
    severity: Severity
    owasp_category: OWASPCategory
    file_path: str = ""
    line_number: int = 0
    code_snippet: str = ""
    description: str = ""
    remediation: str = ""
    confidence: Confidence = Confidence.HIGH
    source: AnalysisSource = AnalysisSource.STATIC
    analyzer_name: str = ""
    tool_name: str = ""

    @computed_field
    @property
    def id(self) -> str:
        """Generate a unique deterministic ID for this finding."""
        content = f"{self.title}:{self.file_path}:{self.line_number}:{self.owasp_category}"
        return hashlib.sha256(content.encode()).hexdigest()[:12]


# ── OWASP Coverage ──────────────────────────────────────────────────────────


class OWASPCoverageItem(BaseModel):
    """Coverage status for a single OWASP MCP category."""

    category: OWASPCategory
    checked: bool = False
    findings_count: int = 0
    status: str = "not_checked"  # "pass", "fail", "not_checked"


# ── Scan Report Model ───────────────────────────────────────────────────────


class ScanReport(BaseModel):
    """The complete output of an MCPry scan."""

    # Metadata
    target: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scan_duration_seconds: float = 0.0
    engine_version: str = "1.0.0"
    llm_enabled: bool = False

    # Results
    grade: str = "?"
    score: int = 100
    findings: list[Finding] = Field(default_factory=list)
    owasp_coverage: list[OWASPCoverageItem] = Field(default_factory=list)

    # Stats
    files_scanned: int = 0
    tools_discovered: int = 0
    tool_definitions: list[ToolDefinition] = Field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def severity_summary(self) -> dict[str, int]:
        return {
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "info": self.info_count,
        }

    def findings_by_owasp(self) -> dict[OWASPCategory, list[Finding]]:
        result: dict[OWASPCategory, list[Finding]] = {}
        for finding in self.findings:
            result.setdefault(finding.owasp_category, []).append(finding)
        return result

    def findings_by_file(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for finding in self.findings:
            result.setdefault(finding.file_path, []).append(finding)
        return result
