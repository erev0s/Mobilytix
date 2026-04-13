"""APK tampering detection tool — powered by apkInspector.

Uses apkInspector to detect ZIP-level and AndroidManifest-level tampering
indicators that are commonly employed by malware APKs to evade static analysis.

These techniques include:
  - Multiple EOCD records (confuse ZIP parsers)
  - Path collisions in ZIP entries
  - Compression method mismatches between local/central headers
  - Fake manifest headers, invalid string pool counts
  - Extra data between manifest XML elements

Reference: https://github.com/erev0s/apkInspector
"""

from __future__ import annotations

import io
import os
from typing import Any, Optional

from loguru import logger

from mcp_server.models.enums import FindingCategory, Severity
from mcp_server.models.finding import Finding
from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool
from mcp_server.tools.workspace import session_workspace


# ---------------------------------------------------------------------------
# Severity classification for known tampering indicators
# ---------------------------------------------------------------------------

# ZIP-level indicators → severity + explanation
ZIP_INDICATOR_SEVERITY: dict[str, dict] = {
    "eocd_count": {
        "severity": "HIGH",
        "title": "Multiple EOCD Records",
        "description": (
            "The APK contains multiple End-of-Central-Directory records. "
            "This is a well-known evasion technique: different ZIP parsers "
            "may interpret the archive differently, allowing malicious "
            "entries to be hidden from static analysis tools."
        ),
        "check": lambda v: v is not None and v > 1,
        "format": lambda v: f"Found {v} EOCD records (expected: 1)",
    },
    "empty_keys": {
        "severity": "MEDIUM",
        "title": "Empty Filename Entries",
        "description": (
            "ZIP entries with empty filenames were detected. These can "
            "confuse ZIP parsers and may be used to hide extra data or "
            "exploit parser vulnerabilities."
        ),
        "check": lambda v: v is True or (isinstance(v, int) and v > 0),
        "format": lambda v: "Empty filename entries present in ZIP",
    },
    "unique_entries": {
        "severity": "MEDIUM",
        "title": "Duplicate ZIP Entries",
        "description": (
            "The central directory contains duplicate filenames. ZIP "
            "parsers handle duplicates inconsistently — some use the "
            "first entry, others the last. This can be used to show "
            "different content to different analysis tools."
        ),
        "check": lambda v: v is False,
        "format": lambda _: "Non-unique filenames in central directory",
    },
    "path_collisions": {
        "severity": "HIGH",
        "title": "Path Collisions Detected",
        "description": (
            "File/directory path collisions found (e.g., a file and a "
            "directory share the same path prefix). This can cause "
            "extraction tools to overwrite files, potentially replacing "
            "legitimate components with malicious ones."
        ),
        "check": lambda v: isinstance(v, dict) and len(v) > 0,
        "format": lambda v: f"Path collisions: {list(v.keys())[:5]}",
    },
    "local_and_central_header_discrepancies": {
        "severity": "HIGH",
        "title": "Header Discrepancies (Local vs Central Directory)",
        "description": (
            "Mismatches between local file headers and central directory "
            "entries. This is a classic static analysis evasion: the "
            "central directory may claim a file is stored while the "
            "local header says it's deflated (or vice versa). Different "
            "tools read different headers, producing different content."
        ),
        "check": lambda v: isinstance(v, dict) and len(v) > 0,
        "format": lambda v: (
            f"{len(v)} entries with header discrepancies"
            if isinstance(v, dict)
            else str(v)
        ),
    },
}

# Manifest-level indicators → severity + explanation
MANIFEST_INDICATOR_SEVERITY: dict[str, dict] = {
    "unexpected_starting_signature": {
        "severity": "HIGH",
        "title": "Unexpected Manifest Signature",
        "description": (
            "The binary AndroidManifest.xml starts with an unexpected "
            "magic signature. This may indicate a hand-crafted manifest "
            "designed to confuse AXML parsers."
        ),
        "check": lambda v: v is True or (isinstance(v, str) and v),
        "format": lambda v: f"Unexpected manifest start signature: {v}",
    },
    "string_pool": {
        "severity": "MEDIUM",
        "title": "String Pool Count Mismatch",
        "description": (
            "The declared string pool count doesn't match the actual "
            "number of strings. This technique can hide strings from "
            "analysis tools that trust the declared count."
        ),
        "check": lambda v: v is not None and v,
        "format": lambda v: f"String pool anomaly: {v}",
    },
    "invalid_data_between_elements": {
        "severity": "MEDIUM",
        "title": "Invalid Data Between XML Elements",
        "description": (
            "Extra bytes found between XML chunk elements in the binary "
            "manifest. This padding can confuse AXML parsers and may "
            "hide malicious content."
        ),
        "check": lambda v: v is True or (isinstance(v, (list, dict)) and len(v) > 0),
        "format": lambda v: "Extra data found between manifest XML elements",
    },
    "zero_size_header": {
        "severity": "MEDIUM",
        "title": "Zero-Size Header Chunk",
        "description": (
            "A manifest chunk declares a size of zero. This violates "
            "the AXML specification and can crash or mislead parsers."
        ),
        "check": lambda v: v is True,
        "format": lambda _: "Zero-size header chunk in manifest",
    },
    "unknown_chunk_type": {
        "severity": "LOW",
        "title": "Unknown Chunk Type in Manifest",
        "description": (
            "An unrecognised chunk type was found in the binary manifest. "
            "Could be a newer format feature or an attempt to evade parsers."
        ),
        "check": lambda v: v is True or (isinstance(v, (list, dict)) and len(v) > 0),
        "format": lambda v: f"Unknown chunk types in manifest: {v}",
    },
    "unexpected_attribute_size": {
        "severity": "MEDIUM",
        "title": "Unexpected Attribute Size",
        "description": (
            "Attributes in the binary manifest have unexpected sizes. "
            "This can cause parsers to misread attribute boundaries."
        ),
        "check": lambda v: v is True or (isinstance(v, (list, dict)) and len(v) > 0),
        "format": lambda v: "Manifest attributes with unexpected sizes",
    },
    "unexpected_attribute_start": {
        "severity": "MEDIUM",
        "title": "Unexpected Attribute Start Offset",
        "description": (
            "Attribute start offsets in the manifest are non-standard. "
            "Combined with other indicators, this suggests deliberate "
            "structural manipulation."
        ),
        "check": lambda v: v is True or (isinstance(v, (list, int)) and v),
        "format": lambda v: f"Non-standard attribute start offsets: {v}",
    },
    "unexpected_attribute_names": {
        "severity": "MEDIUM",
        "title": "Unexpected Attribute Names",
        "description": (
            "Attribute name references point to invalid or unexpected "
            "string pool indices. This may represent hidden attributes "
            "or parser confusion attempts."
        ),
        "check": lambda v: isinstance(v, (list, dict)) and len(v) > 0,
        "format": lambda v: f"Unexpected attribute names: {v}",
    },
}


def _classify_indicators(
    indicators: dict,
    severity_map: dict[str, dict],
) -> list[dict]:
    """Check indicator results against the severity map, return flagged items."""
    flagged = []
    for key, meta in severity_map.items():
        value = indicators.get(key)
        if value is None:
            continue
        try:
            if meta["check"](value):
                flagged.append({
                    "indicator": key,
                    "severity": meta["severity"],
                    "title": meta["title"],
                    "description": meta["description"],
                    "detail": meta["format"](value),
                    "raw_value": _safe_repr(value),
                })
        except Exception:
            # If the lambda check fails, skip rather than crashing
            pass
    return flagged


def _safe_repr(v: Any) -> str:
    """Safe string representation that truncates long values."""
    s = repr(v)
    if len(s) > 500:
        return s[:497] + "..."
    return s


def _severity_priority(sev: str) -> int:
    """Map severity string to numeric order for sorting (higher = worse)."""
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(sev, -1)


def _overall_assessment(zip_flagged: list, manifest_flagged: list) -> dict:
    """Produce a summary assessment from flagged indicators."""
    all_flagged = zip_flagged + manifest_flagged
    if not all_flagged:
        return {
            "verdict": "CLEAN",
            "risk_level": "NONE",
            "summary": (
                "No tampering indicators detected. The APK's ZIP structure "
                "and AndroidManifest.xml binary format appear to follow "
                "standard specifications."
            ),
        }

    # Count by severity
    counts: dict[str, int] = {}
    for f in all_flagged:
        sev = f["severity"]
        counts[sev] = counts.get(sev, 0) + 1

    high_or_critical = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
    total = len(all_flagged)

    if high_or_critical >= 3:
        verdict = "HIGHLY SUSPICIOUS"
        risk_level = "CRITICAL"
        summary = (
            f"Detected {total} tampering indicators ({high_or_critical} HIGH/CRITICAL). "
            "This APK shows strong signs of deliberate structural manipulation "
            "consistent with malware evasion techniques. Static analysis results "
            "from other tools may be unreliable — they might be seeing different "
            "content than what actually executes on device."
        )
    elif high_or_critical >= 1:
        verdict = "SUSPICIOUS"
        risk_level = "HIGH"
        summary = (
            f"Detected {total} tampering indicators ({high_or_critical} HIGH). "
            "The APK uses structural techniques that can mislead static analysis "
            "tools. Results from other tools should be cross-verified. "
            "Dynamic analysis is recommended to observe actual runtime behaviour."
        )
    else:
        verdict = "ANOMALOUS"
        risk_level = "MEDIUM"
        summary = (
            f"Detected {total} minor structural anomalies. These may be "
            "artifacts of unusual build tools or deliberate obfuscation. "
            "Proceed with analysis but note that some tools may have "
            "inconsistencies in their output."
        )

    return {
        "verdict": verdict,
        "risk_level": risk_level,
        "summary": summary,
        "indicator_counts": counts,
    }


# ---------------------------------------------------------------------------
# Tool definition
# ---------------------------------------------------------------------------

class CheckApkTamperingTool(BaseTool):
    """Detect ZIP-level and manifest-level APK tampering indicators.

    Uses apkInspector to examine the low-level structure of the APK for
    signs of deliberate manipulation designed to evade static analysis.

    This should be run early in the analysis — ideally right after
    create_session and detect_framework — because tampering can make
    results from *all* other static analysis tools unreliable.
    """

    name = "check_apk_tampering"
    description = (
        "Detect if the APK has been structurally tampered with to evade "
        "static analysis. Checks for ZIP-level manipulation (multiple EOCD "
        "records, header mismatches, path collisions) and AndroidManifest "
        "binary format tampering (invalid signatures, string pool "
        "mismatches, hidden data). Returns a verdict: CLEAN, ANOMALOUS, "
        "SUSPICIOUS, or HIGHLY SUSPICIOUS with detailed indicators. "
        "Run this early — tampering can make ALL other tool results unreliable."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "strict": {
                    "type": "boolean",
                    "description": (
                        "If true, use strict comparison mode — even tiny "
                        "discrepancies between headers are flagged. Default: false."
                    ),
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session. Call create_session first."}

        ws = str(session_workspace(session))
        apk_path = f"{ws}/app.apk"

        if not os.path.isfile(apk_path):
            return {"error": f"APK not found at {apk_path}"}

        strict = kwargs.get("strict", False)

        try:
            result = self._check_tampering(apk_path, strict)
        except Exception as e:
            logger.error("apkInspector tampering check failed: {}", e)
            return {
                "error": f"Tampering check failed: {e}",
                "hint": "The APK may be corrupted or use an unsupported format.",
            }

        # Store in session metadata
        session.metadata["tampering"] = result

        # Auto-create findings for HIGH/CRITICAL indicators
        all_indicators = result.get("zip_indicators", []) + result.get("manifest_indicators", [])
        for ind in all_indicators:
            if ind["severity"] in ("HIGH", "CRITICAL"):
                sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH}
                finding = Finding(
                    title=f"APK Tampering: {ind['title']}",
                    description=f"{ind['description']}\n\nDetail: {ind['detail']}",
                    severity=sev_map.get(ind["severity"], Severity.HIGH),
                    category=FindingCategory.OTHER,
                    evidence=ind["detail"],
                    tool="check_apk_tampering",
                )
                session.add_finding(finding)

        return result

    def _check_tampering(self, apk_path: str, strict: bool) -> dict:
        """Run apkInspector tampering checks on the APK.

        ZIP and manifest checks are done independently so that a failure
        in one doesn't prevent the other from completing.
        """
        from apkInspector.indicators import zip_tampering_indicators, manifest_tampering_indicators
        from apkInspector.headers import ZipEntry

        with open(apk_path, "rb") as f:
            apk_bytes = io.BytesIO(f.read())

        # --- ZIP-level checks ---
        zip_raw: dict = {}
        zip_error: str | None = None
        try:
            apk_bytes.seek(0)
            zip_raw = zip_tampering_indicators(apk_bytes, strict=strict)
        except Exception as exc:
            logger.warning("ZIP tampering check failed: {}", exc)
            zip_error = str(exc)

        # --- Manifest-level checks ---
        manifest_raw: dict = {}
        manifest_error: str | None = None
        try:
            apk_bytes.seek(0)
            zip_entry = ZipEntry.parse(apk_bytes)
            manifest_bytes = zip_entry.read("AndroidManifest.xml")
            manifest_raw = manifest_tampering_indicators(manifest_bytes)
        except Exception as exc:
            logger.warning("Manifest tampering check failed: {}", exc)
            manifest_error = str(exc)

        # Classify each indicator
        zip_flagged = _classify_indicators(zip_raw, ZIP_INDICATOR_SEVERITY)
        manifest_flagged = _classify_indicators(manifest_raw, MANIFEST_INDICATOR_SEVERITY)

        # Sort by severity (worst first)
        zip_flagged.sort(key=lambda x: _severity_priority(x["severity"]), reverse=True)
        manifest_flagged.sort(key=lambda x: _severity_priority(x["severity"]), reverse=True)

        assessment = _overall_assessment(zip_flagged, manifest_flagged)

        result: dict[str, Any] = {
            "assessment": assessment,
            "zip_indicators": zip_flagged,
            "manifest_indicators": manifest_flagged,
            "total_indicators": len(zip_flagged) + len(manifest_flagged),
            "strict_mode": strict,
        }

        # Include any partial-failure notes so the LLM knows what happened
        errors = {}
        if zip_error:
            errors["zip_check"] = zip_error
        if manifest_error:
            errors["manifest_check"] = manifest_error
        if errors:
            result["partial_errors"] = errors

        return result
