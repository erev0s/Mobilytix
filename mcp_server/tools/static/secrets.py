"""Secret and key detection tools.

Scans APKs and decompiled source for hardcoded secrets, API keys,
and embedded credentials using apkleaks and pattern matching.
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
from mcp_server.tools.workspace import session_workspace


def _workspace_path(session: AnalysisSession) -> str:
    return str(session_workspace(session))


# Map apkleaks pattern types to severity
SECRET_SEVERITY_MAP = {
    "AWS": Severity.HIGH,
    "Amazon": Severity.HIGH,
    "Google": Severity.HIGH,
    "Firebase": Severity.HIGH,
    "Slack": Severity.HIGH,
    "Twilio": Severity.HIGH,
    "Twitter": Severity.HIGH,
    "Facebook": Severity.HIGH,
    "GitHub": Severity.HIGH,
    "Private Key": Severity.CRITICAL,
    "RSA": Severity.CRITICAL,
    "SSH": Severity.CRITICAL,
    "password": Severity.HIGH,
    "secret": Severity.HIGH,
    "token": Severity.HIGH,
    "api_key": Severity.HIGH,
    "apikey": Severity.HIGH,
    "URL": Severity.INFO,
    "IP Address": Severity.INFO,
    "Email": Severity.INFO,
}


def _get_severity_for_secret(secret_type: str) -> Severity:
    """Determine severity based on the type of secret found."""
    secret_lower = secret_type.lower()
    for key, severity in SECRET_SEVERITY_MAP.items():
        if key.lower() in secret_lower:
            return severity
    return Severity.MEDIUM


class ScanSecretsTool(BaseTool):
    """Scan the APK for hardcoded secrets, API keys, and credentials.

    Uses apkleaks to detect secrets in the APK. Creates Finding objects
    for each discovered secret with appropriate severity levels.
    """

    name = "scan_secrets"
    description = (
        "Scan the APK for hardcoded secrets, API keys, tokens, and credentials "
        "using apkleaks. Creates findings for each secret found, with severity "
        "based on type (API keys = HIGH, URLs = INFO, etc.)."
    )

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        ws = _workspace_path(session)
        apk = f"{ws}/app.apk"
        output_json = f"{ws}/apkleaks_output.json"

        # Run apkleaks
        stdout, stderr, rc = await run_local(
            ["apkleaks", "-f", apk, "-o", output_json, "--json"],
            timeout=120,
        )

        findings_created = []

        # Try to read JSON output
        json_stdout, _, json_rc = await read_file_content(output_json)

        secrets = []
        if json_rc == 0 and json_stdout.strip():
            try:
                data = json.loads(json_stdout)
                if isinstance(data, dict):
                    results = data.get("results", data)
                    if isinstance(results, list):
                        for item in results:
                            secrets.append(item)
                    elif isinstance(results, dict):
                        for secret_type, values in results.items():
                            if isinstance(values, list):
                                for val in values:
                                    secrets.append({
                                        "type": secret_type,
                                        "value": val if isinstance(val, str) else str(val),
                                    })
            except json.JSONDecodeError:
                logger.warning("Could not parse apkleaks JSON output")

        # If JSON parsing failed, try parsing stdout
        if not secrets and stdout.strip():
            current_type = "Unknown"
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith("["):
                    current_type = line.strip("[]")
                elif line and not line.startswith("="):
                    secrets.append({"type": current_type, "value": line})

        # Deduplicate
        seen = set()
        unique_secrets = []
        for s in secrets:
            key = f"{s.get('type', '')}:{s.get('value', '')}"
            if key not in seen:
                seen.add(key)
                unique_secrets.append(s)

        # Create findings
        for secret in unique_secrets:
            secret_type = secret.get("type", "Unknown")
            value = secret.get("value", "")

            # Skip very common false positives
            if secret_type.lower() in ("url", "ip address") and len(value) < 15:
                continue

            severity = _get_severity_for_secret(secret_type)

            finding = Finding(
                title=f"Hardcoded {secret_type}",
                severity=severity,
                category=FindingCategory.HARDCODED_SECRET,
                description=(
                    f"A {secret_type} was found hardcoded in the APK. "
                    f"Hardcoded secrets can be extracted by anyone who has the APK."
                ),
                evidence=value[:500],  # Truncate very long values
                location="APK resources/code",
                tool="scan_secrets",
                phase=AnalysisPhase.STATIC.value,
                cwe_id="CWE-798",
                recommendation=(
                    "Move secrets to a secure backend service, use environment "
                    "variables, or use Android Keystore for cryptographic keys."
                ),
            )
            if session.add_finding(finding):
                findings_created.append(finding.to_dict())

        return {
            "total_secrets": len(unique_secrets),
            "findings_created": len(findings_created),
            "findings": findings_created,
            "by_type": {
                s.get("type", "Unknown"): sum(
                    1 for x in unique_secrets if x.get("type") == s.get("type")
                )
                for s in unique_secrets
            },
        }
