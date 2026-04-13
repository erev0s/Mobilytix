"""Finding dataclass — represents a single security finding."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .enums import FindingCategory, Severity


@dataclass
class Finding:
    """A security finding discovered during analysis.

    Each finding has a title, severity, category, and evidence proving
    the vulnerability. Findings are accumulated in the session and used
    to generate the final penetration test report.
    """

    title: str
    severity: Severity
    category: FindingCategory
    description: str
    evidence: str  # The actual code/data proving the finding
    location: str  # File path, component name, or URL
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    cwe_id: Optional[str] = None  # e.g. "CWE-312"
    cvss_score: Optional[float] = None
    recommendation: Optional[str] = None
    tool: Optional[str] = None  # Which tool discovered this
    phase: Optional[str] = None  # Which analysis phase
    raw_output: Optional[str] = None  # Full raw tool output if useful
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        """Serialize finding to a dictionary suitable for JSON output."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "description": self.description,
            "evidence": self.evidence,
            "location": self.location,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "recommendation": self.recommendation,
            "tool": self.tool,
            "phase": self.phase,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        """Deserialize a finding from a dictionary."""
        timestamp_raw = data.get("timestamp")
        if isinstance(timestamp_raw, str):
            try:
                timestamp = datetime.fromisoformat(timestamp_raw)
            except ValueError:
                timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

        return cls(
            title=data["title"],
            severity=Severity(data["severity"]),
            category=FindingCategory(data["category"]),
            description=data["description"],
            evidence=data["evidence"],
            location=data["location"],
            id=data.get("id", str(uuid.uuid4())),
            cwe_id=data.get("cwe_id"),
            cvss_score=data.get("cvss_score"),
            recommendation=data.get("recommendation"),
            tool=data.get("tool"),
            phase=data.get("phase"),
            raw_output=data.get("raw_output"),
            timestamp=timestamp,
        )
