"""Findings store — accumulation and querying of security findings.

Wraps session-level findings access with convenience methods for
cross-session queries and summary generation.
"""

from __future__ import annotations

from collections import Counter
from typing import Optional

from loguru import logger

from .models.enums import FindingCategory, Severity
from .models.finding import Finding
from .models.session import AnalysisSession


class FindingsStore:
    """Query and manage findings across sessions."""

    def __init__(self) -> None:
        # Findings are stored on sessions; this provides cross-session queries
        pass

    @staticmethod
    def add_finding(session: AnalysisSession, finding: Finding) -> Finding:
        """Add a finding to a session and return it."""
        added = session.add_finding(finding)
        if added:
            logger.info(
                "[{}] New finding: [{}] {} in {}",
                session.id[:8],
                finding.severity.value.upper(),
                finding.title,
                finding.location,
            )
        return finding

    @staticmethod
    def get_findings(
        session: AnalysisSession,
        severity: Optional[Severity] = None,
        category: Optional[FindingCategory] = None,
        tool: Optional[str] = None,
    ) -> list[Finding]:
        """Query findings with optional filters."""
        results = session.findings
        if severity:
            results = [f for f in results if f.severity == severity]
        if category:
            results = [f for f in results if f.category == category]
        if tool:
            results = [f for f in results if f.tool == tool]
        return results

    @staticmethod
    def get_summary(session: AnalysisSession) -> dict:
        """Generate a findings summary for the session."""
        findings = session.findings
        severity_counts = Counter(f.severity.value for f in findings)
        category_counts = Counter(f.category.value for f in findings)
        tools_used = Counter(f.tool for f in findings if f.tool)

        return {
            "session_id": session.id,
            "total_findings": len(findings),
            "by_severity": dict(severity_counts),
            "by_category": dict(category_counts),
            "by_tool": dict(tools_used),
            "critical_count": severity_counts.get("critical", 0),
            "high_count": severity_counts.get("high", 0),
            "medium_count": severity_counts.get("medium", 0),
            "low_count": severity_counts.get("low", 0),
            "info_count": severity_counts.get("info", 0),
        }

    @staticmethod
    def generate_markdown_report(session: AnalysisSession) -> str:
        """Generate a Markdown penetration test report from session findings."""
        findings = sorted(
            session.findings,
            key=lambda f: ["critical", "high", "medium", "low", "info"].index(
                f.severity.value
            ),
        )

        severity_counts = Counter(f.severity.value for f in findings)

        lines = [
            f"# Mobilytix Security Assessment Report",
            "",
            f"**Package:** {session.package_name or 'Unknown'}",
            f"**App Name:** {session.app_name or 'Unknown'}",
            f"**APK Path:** {session.apk_path}",
            f"**Session ID:** {session.id}",
            f"**Date:** {session.created_at.strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            "## Executive Summary",
            "",
            f"This automated security assessment identified **{len(findings)}** "
            f"findings across the analyzed Android application.",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                lines.append(f"| {sev.upper()} | {count} |")

        lines.extend(["", "## Findings", ""])

        for i, finding in enumerate(findings, 1):
            lines.extend(
                [
                    f"### {i}. [{finding.severity.value.upper()}] {finding.title}",
                    "",
                    f"**Category:** {finding.category.value}",
                    f"**Location:** {finding.location}",
                ]
            )
            if finding.cwe_id:
                lines.append(f"**CWE:** {finding.cwe_id}")
            if finding.cvss_score is not None:
                lines.append(f"**CVSS:** {finding.cvss_score}")
            lines.extend(
                [
                    "",
                    finding.description,
                    "",
                    "**Evidence:**",
                    "```",
                    finding.evidence,
                    "```",
                    "",
                ]
            )
            if finding.recommendation:
                lines.extend(
                    [
                        "**Recommendation:**",
                        finding.recommendation,
                        "",
                    ]
                )
            lines.append("---")
            lines.append("")

        return "\n".join(lines)
