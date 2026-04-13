"""Certificate and cryptography analysis tools.

Analyzes APK signing certificates and searches for weak cryptography
patterns in decompiled source code.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from loguru import logger

from mcp_server.backends.local_backend import run_local, read_file_content
from mcp_server.models.enums import AnalysisPhase, FindingCategory, Severity
from mcp_server.models.finding import Finding
from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool
from mcp_server.tools.static.code import _ensure_decompiled
from mcp_server.tools.workspace import session_workspace


def _workspace_path(session: AnalysisSession) -> str:
    return str(session_workspace(session))


class AnalyzeCertificateTool(BaseTool):
    """Analyze the APK's signing certificate for security issues.

    Checks signing scheme versions, certificate subject info, validity dates,
    and flags debug certificates, expired certs, and v1-only signing.
    """

    name = "analyze_certificate"
    description = (
        "Analyze the APK signing certificate: signing schemes (v1/v2/v3/v4), "
        "certificate subject, issuer, validity, SHA-256 fingerprint. "
        "Flags debug certificates, expired certs, and v1-only signing "
        "(vulnerable to Janus attack)."
    )

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        ws = _workspace_path(session)
        apk = f"{ws}/app.apk"

        stdout, stderr, rc = await run_local(
            ["apksigner", "verify", "--verbose", "--print-certs", apk],
            timeout=30,
        )

        if rc != 0:
            return {"error": f"apksigner failed: {stderr[:500]}"}

        result: dict[str, Any] = {
            "signing_schemes": {},
            "cert_subject": "",
            "cert_issuer": "",
            "cert_validity": {},
            "cert_fingerprint_sha256": "",
        }
        findings_created = []

        # Parse output
        schemes = {}
        for line in stdout.splitlines():
            line = line.strip()

            if "Verified using v1 scheme" in line:
                schemes["v1"] = "true" in line.lower()
            elif "Verified using v2 scheme" in line:
                schemes["v2"] = "true" in line.lower()
            elif "Verified using v3 scheme" in line:
                schemes["v3"] = "true" in line.lower()
            elif "Verified using v4 scheme" in line:
                schemes["v4"] = "true" in line.lower()
            elif "certificate DN:" in line:
                dn = line.split(":", 1)[1].strip()
                if "Signer #1 certificate DN:" in line:
                    result["cert_subject"] = dn
                elif "issuer" in line.lower():
                    result["cert_issuer"] = dn
            elif "certificate SHA-256" in line:
                result["cert_fingerprint_sha256"] = line.split(":", 1)[1].strip()
            elif "certificate SHA-1" in line:
                result["cert_fingerprint_sha1"] = line.split(":", 1)[1].strip()

        result["signing_schemes"] = schemes

        # Check for debug certificate
        cert_subject = result.get("cert_subject", "")
        if "CN=Android Debug" in cert_subject or "O=Android" in cert_subject:
            f = Finding(
                title="APK signed with debug certificate",
                severity=Severity.HIGH,
                category=FindingCategory.CONFIGURATION_ISSUE,
                description=(
                    "The APK is signed with a debug certificate (CN=Android Debug). "
                    "This indicates a development build that should not be distributed. "
                    "Debug-signed apps have known key material."
                ),
                evidence=f"Certificate DN: {cert_subject}",
                location="APK signing certificate",
                tool="analyze_certificate",
                phase=AnalysisPhase.STATIC.value,
                cwe_id="CWE-489",
                recommendation="Sign the APK with a proper release key.",
            )
            if session.add_finding(f):
                findings_created.append(f.to_dict())

        # Check for v1-only signing (vulnerable to Janus)
        if schemes.get("v1") and not schemes.get("v2") and not schemes.get("v3"):
            f = Finding(
                title="APK uses v1-only signing (vulnerable to Janus attack)",
                severity=Severity.HIGH,
                category=FindingCategory.CONFIGURATION_ISSUE,
                description=(
                    "The APK is signed with APK Signature Scheme v1 only. "
                    "v1-only signed APKs are vulnerable to the Janus vulnerability "
                    "(CVE-2017-13156), which allows prepending a DEX file to the APK "
                    "without invalidating the signature."
                ),
                evidence=f"Signing schemes: v1={schemes.get('v1')}, v2={schemes.get('v2')}, v3={schemes.get('v3')}",
                location="APK signing",
                tool="analyze_certificate",
                phase=AnalysisPhase.STATIC.value,
                cwe_id="CWE-347",
                recommendation="Sign the APK with v2 or v3 signing scheme in addition to v1.",
            )
            if session.add_finding(f):
                findings_created.append(f.to_dict())

        result["findings_created"] = len(findings_created)
        result["findings"] = findings_created
        return result


# Patterns for weak cryptography detection
CRYPTO_PATTERNS = [
    {
        "pattern": r"\"ECB\"",
        "name": "ECB mode usage",
        "severity": Severity.HIGH,
        "cwe": "CWE-327",
        "description": (
            "ECB (Electronic Codebook) mode is used for encryption. ECB mode "
            "does not hide data patterns — identical plaintext blocks produce "
            "identical ciphertext blocks."
        ),
        "recommendation": "Use CBC, GCM, or another authenticated mode instead of ECB.",
    },
    {
        "pattern": r"\"DES\"|DESede|DES/|/DES",
        "name": "DES/3DES usage",
        "severity": Severity.HIGH,
        "cwe": "CWE-327",
        "description": (
            "DES or 3DES encryption is used. These algorithms have been deprecated "
            "due to short key lengths (DES) or performance and security concerns (3DES)."
        ),
        "recommendation": "Use AES-256-GCM instead of DES/3DES.",
    },
    {
        "pattern": r"MessageDigest\.getInstance\(\s*\"MD5\"\s*\)",
        "name": "MD5 hash usage",
        "severity": Severity.MEDIUM,
        "cwe": "CWE-328",
        "description": (
            "MD5 is used for hashing. MD5 has known collision vulnerabilities "
            "and should not be used for security-sensitive operations."
        ),
        "recommendation": "Use SHA-256 or SHA-3 for hashing.",
    },
    {
        "pattern": r"MessageDigest\.getInstance\(\s*\"SHA-?1\"\s*\)",
        "name": "SHA-1 hash usage in security context",
        "severity": Severity.MEDIUM,
        "cwe": "CWE-328",
        "description": (
            "SHA-1 is used for hashing. SHA-1 has known collision attacks "
            "and is deprecated for security-sensitive operations."
        ),
        "recommendation": "Use SHA-256 or SHA-3 for security-sensitive hashing.",
    },
    {
        "pattern": r"SecureRandom.*setSeed\s*\(",
        "name": "SecureRandom with explicit seed",
        "severity": Severity.HIGH,
        "cwe": "CWE-330",
        "description": (
            "SecureRandom is being seeded with a constant or predictable value. "
            "This makes the random number generator predictable."
        ),
        "recommendation": "Let SecureRandom self-seed from the system entropy source.",
    },
    {
        "pattern": r"IvParameterSpec\s*\(\s*(?:new\s+byte\s*\[|\")",
        "name": "Hardcoded IV for encryption",
        "severity": Severity.HIGH,
        "cwe": "CWE-330",
        "description": (
            "An initialization vector (IV) appears to be hardcoded. "
            "Reusing IVs with the same key breaks semantic security."
        ),
        "recommendation": "Generate a random IV for each encryption operation.",
    },
    {
        "pattern": r"SSLContext\.getInstance\(\s*\"SSL\"\s*\)|\"TLSv1\"|\"TLSv1\.0\"|\"TLSv1\.1\"",
        "name": "Weak TLS version",
        "severity": Severity.HIGH,
        "cwe": "CWE-326",
        "description": (
            "The application uses SSL or an outdated TLS version (1.0/1.1). "
            "These protocols have known vulnerabilities."
        ),
        "recommendation": "Use TLS 1.2 or TLS 1.3.",
    },
    {
        "pattern": r"TrustManager|X509TrustManager.*checkServerTrusted.*\{\s*\}",
        "name": "Custom TrustManager with empty validation",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-295",
        "description": (
            "A custom TrustManager appears to have empty certificate validation. "
            "This bypasses all SSL/TLS certificate checking, allowing man-in-the-middle attacks."
        ),
        "recommendation": "Use the default TrustManager or implement proper certificate validation.",
    },
]


class FindCryptoIssuesTool(BaseTool):
    """Search decompiled source for weak cryptography patterns.

    Checks for ECB mode, DES, MD5, SHA-1, hardcoded IVs,
    weak TLS versions, and empty TrustManagers.
    """

    name = "find_crypto_issues"
    description = (
        "Search decompiled source for weak cryptography patterns: ECB mode, "
        "DES/3DES, MD5/SHA-1, hardcoded IVs, seeded SecureRandom, weak TLS, "
        "and empty TrustManagers. Creates findings for each issue."
    )

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        # Auto-decompile if needed (handles parallel-call race condition)
        try:
            await _ensure_decompiled(session)
        except RuntimeError as e:
            return {"error": f"Cannot decompile APK: {e}"}

        findings_created = []

        for pattern_info in CRYPTO_PATTERNS:
            # Search using ripgrep
            stdout, stderr, rc = await run_local(
                [
                    "rg",
                    "--json",
                    "-C", "2",
                    "--max-count", "10",
                    "-g", "*.java",
                    pattern_info["pattern"],
                    session.decompiled_path,
                ],
                timeout=30,
            )

            if rc >= 2:
                continue  # Search error, skip this pattern

            # Parse matches
            matches = []
            for line in stdout.splitlines():
                try:
                    obj = json.loads(line)
                    if obj.get("type") == "match":
                        data = obj["data"]
                        match_path = data["path"]["text"].replace(
                            session.decompiled_path + "/", ""
                        )
                        match_text = data["lines"]["text"].rstrip("\n")
                        line_num = data["line_number"]
                        matches.append({
                            "file": match_path,
                            "line": line_num,
                            "code": match_text,
                        })
                except json.JSONDecodeError:
                    continue

            if matches:
                # Create one finding per pattern (with all matches as evidence)
                evidence_lines = []
                for m in matches[:5]:  # Show up to 5 matches
                    evidence_lines.append(f"{m['file']}:{m['line']}: {m['code']}")

                finding = Finding(
                    title=pattern_info["name"],
                    severity=pattern_info["severity"],
                    category=FindingCategory.WEAK_CRYPTOGRAPHY,
                    description=pattern_info["description"],
                    evidence="\n".join(evidence_lines),
                    location=matches[0]["file"],
                    tool="find_crypto_issues",
                    phase=AnalysisPhase.STATIC.value,
                    cwe_id=pattern_info["cwe"],
                    recommendation=pattern_info["recommendation"],
                )
                if session.add_finding(finding):
                    findings_created.append({
                        **finding.to_dict(),
                        "match_count": len(matches),
                    })

        return {
            "total_issues": len(findings_created),
            "findings": findings_created,
            "patterns_checked": len(CRYPTO_PATTERNS),
        }
