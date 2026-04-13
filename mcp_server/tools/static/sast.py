"""SAST (Static Application Security Testing) tools.

Runs semgrep with Android-specific rules against decompiled source code.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from loguru import logger

from mcp_server.backends.local_backend import run_local, read_file_content
from mcp_server.models.enums import FindingCategory, Severity, AnalysisPhase
from mcp_server.models.finding import Finding
from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool
from mcp_server.tools.static.routing import get_wrapper_only_warning
from mcp_server.tools.workspace import session_workspace


def _workspace_path(session: AnalysisSession) -> str:
    return str(session_workspace(session))


# Map semgrep severity to our severity
SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

# Map semgrep rule metadata to finding categories
def _map_category(rule_id: str, metadata: dict) -> FindingCategory:
    """Map a semgrep rule to a FindingCategory."""
    rule_lower = rule_id.lower()
    cwe = metadata.get("cwe", "")
    cwe_str = str(cwe).lower() if cwe else ""

    if "hardcoded" in rule_lower or "secret" in rule_lower or "credential" in rule_lower:
        return FindingCategory.HARDCODED_SECRET
    elif "crypto" in rule_lower or "cipher" in rule_lower or "hash" in rule_lower:
        return FindingCategory.WEAK_CRYPTOGRAPHY
    elif "sql" in rule_lower or "injection" in rule_lower:
        return FindingCategory.CODE_INJECTION
    elif "webview" in rule_lower or "javascript" in rule_lower:
        return FindingCategory.CODE_INJECTION
    elif "ssl" in rule_lower or "tls" in rule_lower or "http" in rule_lower:
        return FindingCategory.INSECURE_COMMUNICATION
    elif "storage" in rule_lower or "preference" in rule_lower or "database" in rule_lower:
        return FindingCategory.INSECURE_DATA_STORAGE
    elif "export" in rule_lower or "intent" in rule_lower or "broadcast" in rule_lower:
        return FindingCategory.EXPORTED_COMPONENT
    elif "auth" in rule_lower:
        return FindingCategory.IMPROPER_AUTHENTICATION
    else:
        return FindingCategory.OTHER


class RunSastTool(BaseTool):
    """Run semgrep with Android security rules on decompiled source.

    Parses findings into structured objects with mapped severity and
    categories. Creates Finding objects for each result.
    """

    name = "run_sast"
    description = (
        "Run semgrep SAST scanner with Android-specific rules against the "
        "decompiled source code. Creates findings for each detected issue "
        "with appropriate severity and CWE mappings."
    )

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        if not session.decompiled_path:
            return {"error": "APK not yet decompiled. Run decompile_apk first."}

        ws = _workspace_path(session)
        output_json = f"{ws}/semgrep_output.json"

        # Run semgrep with Android ruleset
        stdout, stderr, rc = await run_local(
            [
                "semgrep",
                "--config", "p/android",
                "--json",
                "--output", output_json,
                "--timeout", "120",
                session.decompiled_path,
            ],
            timeout=300,
        )

        # Read JSON output
        json_stdout, _, json_rc = await read_file_content(output_json)

        findings_created = []
        semgrep_results = []

        if json_rc == 0 and json_stdout.strip():
            try:
                data = json.loads(json_stdout)
                semgrep_results = data.get("results", [])
            except json.JSONDecodeError:
                logger.warning("Could not parse semgrep JSON output")
        elif stdout.strip():
            # Try parsing stdout directly
            try:
                data = json.loads(stdout)
                semgrep_results = data.get("results", [])
            except json.JSONDecodeError:
                pass

        for result in semgrep_results:
            check_id = result.get("check_id", "unknown")
            message = result.get("extra", {}).get("message", "")
            severity_str = result.get("extra", {}).get("severity", "WARNING")
            metadata = result.get("extra", {}).get("metadata", {})
            path = result.get("path", "").replace(session.decompiled_path + "/", "")
            start_line = result.get("start", {}).get("line", 0)
            end_line = result.get("end", {}).get("line", 0)
            matched_code = result.get("extra", {}).get("lines", "")

            severity = SEMGREP_SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
            category = _map_category(check_id, metadata)

            # Extract CWE if available
            cwe_id = None
            cwe_data = metadata.get("cwe", [])
            if isinstance(cwe_data, list) and cwe_data:
                cwe_str = str(cwe_data[0])
                if "CWE-" in cwe_str:
                    cwe_id = cwe_str.split(":")[0].strip() if ":" in cwe_str else cwe_str
            elif isinstance(cwe_data, str) and "CWE-" in cwe_data:
                cwe_id = cwe_data.split(":")[0].strip() if ":" in cwe_data else cwe_data

            finding = Finding(
                title=f"[semgrep] {check_id.split('.')[-1]}",
                severity=severity,
                category=category,
                description=message or f"Semgrep rule {check_id} matched",
                evidence=matched_code[:500] if matched_code else f"Rule: {check_id}",
                location=f"{path}:{start_line}-{end_line}" if start_line else path,
                tool="run_sast",
                phase=AnalysisPhase.STATIC.value,
                cwe_id=cwe_id,
                recommendation=metadata.get("fix", "Review and fix the flagged code."),
            )
            if session.add_finding(finding):
                findings_created.append(finding.to_dict())

        # Summary by severity
        from collections import Counter
        severity_counts = Counter(f["severity"] for f in findings_created)

        result = {
            "total": len(findings_created),
            "by_severity": dict(severity_counts),
            "findings": findings_created[:30],  # Limit output size
            "truncated": len(findings_created) > 30,
        }
        warning = get_wrapper_only_warning(session, self.name)
        if warning:
            result["warning"] = warning
        return result
