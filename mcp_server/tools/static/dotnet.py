"""Managed assembly (.NET / Xamarin / Unity Mono) static analysis tool."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Optional

from mcp_server.backends.local_backend import run_local
from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool
from mcp_server.tools.static.routing import (
    ensure_artifact_index,
    ensure_framework_metadata,
    extract_artifact_to_workspace,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ILSPY_PATH_ENV = "ILSPY_PATH"
DEFAULT_ILSPY_PATH = "/opt/ilspy/ilspycmd"

# Assemblies to skip for deep scan — framework glue, not app logic
FRAMEWORK_ASSEMBLY_PREFIXES = (
    "mscorlib",
    "Mono.",
    "System.",
    "Xamarin.",
    "Microsoft.",
    "UnityEngine.",
    "Unity.",
    "netstandard",
    "Java.Interop",
    "Android.Runtime",
    "Accessibility",
    "WindowsBase",
    "PresentationCore",
)

MAX_PRIORITY_ASSEMBLIES = 5
MAX_SCAN_BYTES = 2 * 1024 * 1024  # 2 MB per decompiled output
MAX_CATEGORY_ITEMS = 25
MAX_LINE_SAMPLES = 8

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
STORAGE_RE = re.compile(
    r"[A-Za-z0-9_.:-]*(?:sharedpref|sqlite|realm|database|keychain|securestorage|token|credential)[A-Za-z0-9_.:-]*",
    re.IGNORECASE,
)
KEYWORD_GROUPS = {
    "auth_terms": ["auth", "bearer", "jwt", "login", "oauth", "refresh", "session", "token"],
    "crypto_terms": ["aes", "cipher", "encrypt", "decrypt", "hmac", "keystore", "md5", "rsa", "sha"],
    "trust_terms": ["certificate", "hostnameverifier", "pinning", "ssl", "tls", "trust", "x509"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ilspy_path() -> Path:
    return Path(os.environ.get(ILSPY_PATH_ENV, DEFAULT_ILSPY_PATH))


def _is_priority_assembly(name: str) -> bool:
    lower = name.lower()
    for prefix in FRAMEWORK_ASSEMBLY_PREFIXES:
        if lower.startswith(prefix.lower()):
            return False
    return True


def _scan_decompiled_text(text: str) -> dict[str, Any]:
    results: dict[str, list] = {
        "urls": [], "storage_identifiers": [],
        "auth_terms": [], "crypto_terms": [], "trust_terms": [],
    }
    line_samples: dict[str, list] = {k: [] for k in ("auth_terms", "crypto_terms", "trust_terms")}
    seen: dict[str, set] = {k: set() for k in results}
    seen_lines: dict[str, set] = {k: set() for k in line_samples}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        for m in URL_RE.findall(line):
            if len(results["urls"]) < MAX_CATEGORY_ITEMS and m not in seen["urls"]:
                seen["urls"].add(m)
                results["urls"].append(m)

        for m in STORAGE_RE.findall(line):
            if len(results["storage_identifiers"]) < MAX_CATEGORY_ITEMS and m not in seen["storage_identifiers"]:
                seen["storage_identifiers"].add(m)
                results["storage_identifiers"].append(m)

        lower = line.lower()
        for key, keywords in KEYWORD_GROUPS.items():
            if any(kw in lower for kw in keywords):
                tokens = re.findall(r"[A-Za-z0-9_.:/-]{3,}", line)
                for token in tokens:
                    if any(kw in token.lower() for kw in keywords):
                        if len(results[key]) < MAX_CATEGORY_ITEMS and token not in seen[key]:
                            seen[key].add(token)
                            results[key].append(token)
                if len(line_samples[key]) < MAX_LINE_SAMPLES and line not in seen_lines[key]:
                    seen_lines[key].add(line)
                    line_samples[key].append(line[:300])

    return {
        **results,
        "auth_lines": line_samples["auth_terms"],
        "crypto_lines": line_samples["crypto_terms"],
        "trust_lines": line_samples["trust_terms"],
    }


def _merge_signals(signal_list: list[dict[str, Any]]) -> dict[str, Any]:
    merged: dict[str, list] = {}
    for signals in signal_list:
        for key, values in signals.items():
            bucket = merged.setdefault(key, [])
            seen = set(bucket)
            for v in values:
                if v not in seen:
                    bucket.append(v)
                    seen.add(v)
                if len(bucket) >= MAX_CATEGORY_ITEMS and not key.endswith("_lines"):
                    break
    return merged


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------

class AnalyzeManagedAssembliesTool(BaseTool):
    """Decompile and triage .NET / Xamarin / Unity Mono managed assemblies."""

    name = "analyze_managed_assemblies"
    description = (
        "Analyze .NET or Xamarin managed assemblies in an APK. "
        "Identifies priority app assemblies (filtering out framework glue), "
        "decompiles them with ilspycmd, and extracts endpoints, auth/crypto/trust signals, "
        "and storage identifiers. Falls back gracefully when ilspycmd is not installed. "
        "Applies to Xamarin/.NET (dotnet route) and Unity Mono (unity_mono route)."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "max_assemblies": {
                    "type": "integer",
                    "description": f"Maximum number of priority assemblies to decompile. Default: {MAX_PRIORITY_ASSEMBLIES}.",
                    "default": MAX_PRIORITY_ASSEMBLIES,
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        framework = ensure_framework_metadata(session)
        primary = framework.get("primary_framework", "")
        route_key = framework.get("route_key", "")
        if primary not in {"Xamarin", "Unity"} and route_key not in {"dotnet", "unity_mono"}:
            return {
                "error": "This tool applies to Xamarin/.NET and Unity Mono APKs.",
                "primary_framework": primary,
            }

        artifact_index = ensure_artifact_index(session)
        assemblies = artifact_index.get("artifacts", {}).get("managed_assemblies", [])
        if not assemblies:
            return {
                "error": "No managed assemblies found in this APK.",
                "hint": "Use list_static_artifacts to verify the assembly layout.",
            }

        # Partition into priority (app logic) vs deferred (framework glue)
        priority: list[dict[str, Any]] = []
        deferred: list[dict[str, Any]] = []
        for a in assemblies:
            name = Path(a["path"]).name
            if _is_priority_assembly(name):
                priority.append(a)
            else:
                deferred.append(a)

        max_assemblies = int(kwargs.get("max_assemblies", MAX_PRIORITY_ASSEMBLIES))
        to_decompile = priority[:max_assemblies]

        ilspy = _ilspy_path()
        ilspy_available = ilspy.is_file()

        if not ilspy_available:
            session.metadata.setdefault("managed_assemblies", {})["analysis"] = {
                "primary_framework": primary,
                "ilspy_available": False,
                "priority_count": len(priority),
            }
            return {
                "ilspy_available": False,
                "ilspy_path": str(ilspy),
                "error": "ilspycmd is not installed in the static container.",
                "hint": (
                    "Install with: dotnet tool install ilspycmd --tool-path /opt/ilspy "
                    "and set ILSPY_PATH=/opt/ilspy/ilspycmd."
                ),
                "priority_assemblies": [a["path"] for a in priority],
                "deferred_assemblies": [a["path"] for a in deferred[:20]],
                "dynamic_hypotheses": [
                    "Confirm auth, network, and storage flows whose names surface in assembly metadata strings.",
                    "Use analyze_native_strings on Mono runtime libraries for additional hints.",
                ],
            }

        # Decompile each priority assembly and collect signals
        all_signals: list[dict[str, Any]] = []
        decompiled_results: list[dict[str, Any]] = []
        for artifact in to_decompile:
            try:
                local_dll = extract_artifact_to_workspace(session, artifact["path"])
            except (FileNotFoundError, ValueError) as exc:
                decompiled_results.append({"path": artifact["path"], "error": str(exc)})
                continue

            stdout, stderr, rc = await run_local(
                [str(ilspy), "--outputdir", "-", str(local_dll)],
                timeout=120,
            )
            if rc != 0 or not stdout.strip():
                decompiled_results.append({
                    "path": artifact["path"],
                    "error": f"ilspycmd exited {rc}",
                    "stderr": stderr[:500],
                })
                continue

            text = stdout[:MAX_SCAN_BYTES]
            signals = _scan_decompiled_text(text)
            all_signals.append(signals)
            decompiled_results.append({"path": artifact["path"], "decompiled": True})

        merged = _merge_signals(all_signals)

        result: dict[str, Any] = {
            "ilspy_available": True,
            "primary_framework": primary,
            "priority_assemblies": [a["path"] for a in priority],
            "deferred_assemblies": [a["path"] for a in deferred[:20]],
            "decompiled": decompiled_results,
            "recovered": {
                "urls": merged.get("urls", []),
                "storage_identifiers": merged.get("storage_identifiers", []),
                "auth_terms": merged.get("auth_terms", []),
                "crypto_terms": merged.get("crypto_terms", []),
                "trust_terms": merged.get("trust_terms", []),
            },
            "signal_lines": {
                "auth": merged.get("auth_lines", []),
                "crypto": merged.get("crypto_lines", []),
                "trust": merged.get("trust_lines", []),
            },
            "dynamic_hypotheses": [
                "Intercept API calls and auth flows identified in decompiled assembly output.",
                "Validate certificate pinning and TLS trust logic at runtime.",
                "Confirm storage key names recovered from assemblies via on-device inspection.",
            ],
            "hint": (
                "Correlate recovered endpoints and auth terms with the Android manifest, "
                "native library strings, and dynamic traffic capture."
            ),
        }

        session.metadata.setdefault("managed_assemblies", {})["analysis"] = {
            "primary_framework": primary,
            "priority_count": len(priority),
            "decompiled_count": sum(1 for r in decompiled_results if r.get("decompiled")),
        }
        return result
