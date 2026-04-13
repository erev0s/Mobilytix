"""Findings management tools — add, list, summarize, and report on findings.

These tools allow the LLM to manually add findings from its own analysis,
query existing findings, and generate reports.
"""

from __future__ import annotations

from typing import Any, Optional

from mcp_server.findings_store import FindingsStore
from mcp_server.models.enums import FindingCategory, Severity
from mcp_server.models.finding import Finding
from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool


class AddFindingTool(BaseTool):
    """Manually add a security finding to the current session.

    Use this when you discover a vulnerability through manual analysis
    that wasn't automatically detected by other tools. Include concrete
    evidence (code snippets, configuration values) in every finding.
    """

    name = "add_finding"
    description = (
        "Manually add a security finding to the session. Use when you discover "
        "a vulnerability through manual code review or analysis. Provide concrete "
        "evidence and assign appropriate severity and CWE IDs."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "title": {
                    "type": "string",
                    "description": "Short descriptive title for the finding",
                },
                "severity": {
                    "type": "string",
                    "description": "Severity level",
                    "enum": [s.value for s in Severity],
                },
                "category": {
                    "type": "string",
                    "description": "Finding category",
                    "enum": [c.value for c in FindingCategory],
                },
                "description": {
                    "type": "string",
                    "description": "Detailed description of the vulnerability",
                },
                "evidence": {
                    "type": "string",
                    "description": "Concrete evidence (code snippet, config value, etc.)",
                },
                "location": {
                    "type": "string",
                    "description": "File path, component name, or URL where the issue was found",
                },
                "cwe_id": {
                    "type": "string",
                    "description": "CWE identifier (e.g. 'CWE-312')",
                },
                "recommendation": {
                    "type": "string",
                    "description": "How to fix or mitigate the issue",
                },
            },
            "required": [
                "session_id",
                "title",
                "severity",
                "category",
                "description",
                "evidence",
                "location",
            ],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        finding = Finding(
            title=kwargs["title"],
            severity=Severity(kwargs["severity"]),
            category=FindingCategory(kwargs["category"]),
            description=kwargs["description"],
            evidence=kwargs["evidence"],
            location=kwargs["location"],
            cwe_id=kwargs.get("cwe_id"),
            recommendation=kwargs.get("recommendation"),
            tool="manual",
            phase=session.current_phase.value,
        )
        created = session.add_finding(finding)

        return {
            "finding_id": finding.id,
            "title": finding.title,
            "severity": finding.severity.value,
            "created": created,
            "total_findings": len(session.findings),
        }


class ListFindingsTool(BaseTool):
    """List all findings in the current session, optionally filtered by severity or category."""

    name = "list_findings"
    description = (
        "List all security findings discovered so far in this session. "
        "Optionally filter by severity or category to focus on specific issues."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "severity": {
                    "type": "string",
                    "description": "Filter by severity level",
                    "enum": [s.value for s in Severity],
                },
                "category": {
                    "type": "string",
                    "description": "Filter by finding category",
                    "enum": [c.value for c in FindingCategory],
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        findings = session.findings

        severity_filter = kwargs.get("severity")
        if severity_filter:
            findings = [f for f in findings if f.severity.value == severity_filter]

        category_filter = kwargs.get("category")
        if category_filter:
            findings = [f for f in findings if f.category.value == category_filter]

        return {
            "total": len(findings),
            "findings": [f.to_dict() for f in findings],
        }


class GetFindingsSummaryTool(BaseTool):
    """Get a high-level summary of all findings in the session."""

    name = "get_findings_summary"
    description = (
        "Get a summary of all findings: counts by severity and category, "
        "which tools found them, and overall risk assessment."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        return FindingsStore.get_summary(session)


class GenerateReportTool(BaseTool):
    """Generate a penetration test report from accumulated findings."""

    name = "generate_report"
    description = (
        "Generate a structured penetration test report from all findings. "
        "Call this after completing all analysis phases. Returns a Markdown "
        "or JSON report with executive summary, finding details, and recommendations."
    )

    def __init__(self, findings_store: Optional[FindingsStore] = None) -> None:
        self._store = findings_store or FindingsStore()

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "format": {
                    "type": "string",
                    "description": "Report format",
                    "enum": ["markdown", "json"],
                    "default": "markdown",
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        fmt = kwargs.get("format", "markdown")

        if fmt == "json":
            return {
                "format": "json",
                "report": session.to_dict(),
            }

        report = FindingsStore.generate_markdown_report(session)
        return {
            "format": "markdown",
            "report": report,
        }


class GetAnalysisStatusTool(BaseTool):
    """Get the current analysis status — phase, tools called, progress."""

    name = "get_analysis_status"
    description = (
        "Get the current state of the analysis session: current phase, "
        "tools already called, findings count by severity, and what "
        "hasn't been analyzed yet. Helpful for orienting yourself in long sessions."
    )

    # All available tool names grouped by phase
    PHASE_TOOLS = {
        "recon": [
            "get_apk_metadata",
            "get_manifest",
            "list_exported_components",
            "check_manifest_security",
        ],
        "static": [
            "decompile_apk",
            "search_source",
            "scan_secrets",
            "run_sast",
            "find_crypto_issues",
            "analyze_certificate",
        ],
        "dynamic_setup": [
            "start_dynamic_session",
            "install_apk",
            "launch_app",
        ],
        "runtime": [
            "list_loaded_classes",
            "run_frida_script",
            "run_frida_codeshare_script",
        ],
        "traffic": [
            "start_traffic_capture",
            "stop_traffic_capture",
            "get_captured_requests",
            "get_captured_flow_body",
            "find_sensitive_traffic",
        ],
        "storage": [
            "pull_app_data",
            "read_shared_preferences",
            "query_app_database",
            "list_app_files",
        ],
    }

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        called = set(session.tools_called)
        not_called = {}
        for phase, tools in self.PHASE_TOOLS.items():
            remaining = [t for t in tools if t not in called]
            if remaining:
                not_called[phase] = remaining

        summary = FindingsStore.get_summary(session)

        return {
            "session_id": session.id,
            "package_name": session.package_name,
            "current_phase": session.current_phase.value,
            "tools_called": list(called),
            "tools_not_yet_called": not_called,
            "findings_summary": summary,
            "device_connected": session.device_id is not None,
            "decompiled": session.decompiled_path is not None,
        }
