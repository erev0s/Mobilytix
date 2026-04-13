"""AnalysisSession dataclass — represents a single APK analysis session."""

from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .enums import AnalysisPhase, Severity
from .finding import Finding


@dataclass
class AnalysisSession:
    """An active APK analysis session.

    Tracks the APK being analyzed, paths to decompiled/decoded artifacts,
    the current analysis phase, accumulated findings, and arbitrary metadata
    from tool outputs.
    """

    apk_path: str  # Path to APK inside container
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    package_name: Optional[str] = None
    app_name: Optional[str] = None
    workspace_dir: Optional[str] = None  # Absolute path to workspace dir
    decompiled_path: Optional[str] = None  # Where jadx output lives
    decoded_path: Optional[str] = None  # Where apktool output lives
    device_id: Optional[str] = None  # adb serial when dynamic active
    current_phase: AnalysisPhase = AnalysisPhase.RECON
    findings: list[Finding] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)  # Arbitrary tool outputs
    tools_called: list[str] = field(default_factory=list)  # Track tool usage
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @staticmethod
    def _finding_key(finding: Finding) -> tuple:
        """Return a stable key for semantic deduplication of findings."""
        return (
            finding.title,
            finding.severity.value,
            finding.category.value,
            finding.description,
            finding.evidence,
            finding.location,
            finding.cwe_id,
            finding.cvss_score,
            finding.recommendation,
            finding.tool,
            finding.phase,
        )

    def add_finding(self, finding: Finding) -> bool:
        """Add a finding if it is not already present.

        Returns True when the finding was added, False when an equivalent
        finding already exists in the session.
        """
        key = self._finding_key(finding)
        for existing in self.findings:
            if self._finding_key(existing) == key:
                return False
        self.findings.append(finding)
        return True

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Return all findings matching the given severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_category(self, category: str) -> list[Finding]:
        """Return all findings matching the given category."""
        return [f for f in self.findings if f.category.value == category]

    def record_tool_call(self, tool_name: str) -> None:
        """Record that a tool was called in this session."""
        self.tools_called.append(tool_name)

    def to_summary_dict(self) -> dict:
        """Return a high-level summary of this session."""
        severity_counts = Counter(f.severity.value for f in self.findings)
        category_counts = Counter(f.category.value for f in self.findings)
        return {
            "session_id": self.id,
            "apk_path": self.apk_path,
            "package_name": self.package_name,
            "app_name": self.app_name,
            "current_phase": self.current_phase.value,
            "total_findings": len(self.findings),
            "findings_by_severity": dict(severity_counts),
            "findings_by_category": dict(category_counts),
            "device_connected": self.device_id is not None,
            "decompiled": self.decompiled_path is not None,
            "decoded": self.decoded_path is not None,
            "workspace_dir": self.workspace_dir,
            "tools_called": list(set(self.tools_called)),
            "apk_hash": self.metadata.get("apk_hash"),
            "created_at": self.created_at.isoformat(),
        }

    def to_dict(self) -> dict:
        """Full serialization of the session."""
        return {
            **self.to_summary_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
        }
