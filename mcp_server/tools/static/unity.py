"""Unity IL2CPP metadata analysis tool."""

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
from mcp_server.tools.workspace import ensure_session_artifact_path, session_workspace

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IL2CPP_DUMPER_ENV = "IL2CPPDUMPER_PATH"
DEFAULT_IL2CPPDUMPER_PATH = "/usr/local/bin/il2cppdumper"

GLOBAL_METADATA_PATH = "assets/bin/Data/Managed/Metadata/global-metadata.dat"
IL2CPP_LIB_PATTERN = "libil2cpp.so"

MAX_CATEGORY_ITEMS = 30
MAX_OUTPUT_BYTES = 4 * 1024 * 1024  # 4 MB

# Security-relevant keywords to filter recovered names
SECURITY_CATEGORIES: dict[str, list[str]] = {
    "auth": ["auth", "login", "token", "jwt", "oauth", "credential", "session", "password", "biometric"],
    "network": ["http", "url", "endpoint", "request", "response", "socket", "ssl", "tls", "certificate", "pinning"],
    "crypto": ["aes", "rsa", "hmac", "md5", "sha", "encrypt", "decrypt", "cipher", "key", "hash"],
    "storage": ["storage", "prefs", "preference", "database", "sqlite", "file", "cache", "keychain"],
    "anti_tamper": ["root", "frida", "debug", "hook", "integrity", "tamper", "emulator", "detect", "check"],
    "webview": ["webview", "javascript", "bridge", "interface"],
    "payment": ["payment", "purchase", "iap", "billing", "checkout", "stripe", "braintree"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _il2cppdumper_path() -> Path:
    return Path(os.environ.get(IL2CPP_DUMPER_ENV, DEFAULT_IL2CPPDUMPER_PATH))


def _categorize_names(names: list[str]) -> dict[str, list[str]]:
    """Bucket a list of IL2CPP recovered names into security categories."""
    categorized: dict[str, list[str]] = {cat: [] for cat in SECURITY_CATEGORIES}
    for name in names:
        lower = name.lower()
        for cat, keywords in SECURITY_CATEGORIES.items():
            if any(kw in lower for kw in keywords):
                if len(categorized[cat]) < MAX_CATEGORY_ITEMS:
                    categorized[cat].append(name)
    return categorized


def _parse_il2cpp_output(text: str) -> dict[str, Any]:
    """Parse Il2CppDumper output (dump.cs) for type and method names."""
    type_names: list[str] = []
    method_names: list[str] = []
    field_names: list[str] = []

    seen_types: set[str] = set()
    seen_methods: set[str] = set()
    seen_fields: set[str] = set()

    # Patterns for dump.cs format
    class_re = re.compile(r"(?:public|private|protected|internal)?\s*(?:class|interface|struct|enum)\s+([A-Za-z0-9_<>]+)")
    method_re = re.compile(r"(?:public|private|protected|internal)[\w\s]*\s+([A-Za-z0-9_]+)\s*\(")
    field_re = re.compile(r"(?:public|private|protected|internal)\s+\S+\s+([A-Za-z0-9_]+)\s*[;=]")

    for line in text.splitlines():
        stripped = line.strip()
        for m in class_re.findall(stripped):
            if m and m not in seen_types and len(type_names) < MAX_CATEGORY_ITEMS * 10:
                seen_types.add(m)
                type_names.append(m)
        for m in method_re.findall(stripped):
            if m and m not in seen_methods and len(method_names) < MAX_CATEGORY_ITEMS * 10:
                seen_methods.add(m)
                method_names.append(m)
        for m in field_re.findall(stripped):
            if m and m not in seen_fields and len(field_names) < MAX_CATEGORY_ITEMS * 10:
                seen_fields.add(m)
                field_names.append(m)

    return {
        "type_names": type_names,
        "method_names": method_names,
        "field_names": field_names,
    }


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------

class AnalyzeUnityMetadataTool(BaseTool):
    """Triage Unity IL2CPP global-metadata.dat using Il2CppDumper."""

    name = "analyze_unity_metadata"
    description = (
        "Analyze a Unity IL2CPP APK by extracting and parsing global-metadata.dat. "
        "Runs Il2CppDumper to recover type, method, and field names from the IL2CPP "
        "metadata. Filters recovered names for security-relevant patterns: auth, network, "
        "crypto, storage, anti-tamper, WebView, and payment. "
        "Falls back gracefully when Il2CppDumper is not installed. "
        "Only applicable to the unity_il2cpp route."
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

        framework = ensure_framework_metadata(session)
        primary = framework.get("primary_framework", "")
        if primary != "Unity":
            return {
                "error": "This tool only applies to Unity APKs.",
                "primary_framework": primary,
            }

        unity_backend = framework.get("format_hints", {}).get("unity_backend")
        if unity_backend != "il2cpp":
            return {
                "error": "analyze_unity_metadata only applies to Unity IL2CPP builds.",
                "unity_backend": unity_backend,
                "hint": "For Unity Mono builds, use analyze_managed_assemblies instead.",
            }

        artifact_index = ensure_artifact_index(session)

        # Locate global-metadata.dat and libil2cpp.so
        engine_assets = artifact_index.get("artifacts", {}).get("engine_assets", [])
        metadata_artifact = next(
            (a for a in engine_assets if "global-metadata.dat" in a["path"]),
            None,
        )
        if not metadata_artifact:
            return {
                "error": "global-metadata.dat not found in this APK.",
                "hint": "Verify this is a Unity IL2CPP build with list_static_artifacts.",
            }

        native_libs = artifact_index.get("artifacts", {}).get("native_libs", [])
        libil2cpp_artifact = next(
            (a for a in native_libs if IL2CPP_LIB_PATTERN in a["path"]),
            None,
        )

        dumper = _il2cppdumper_path()
        dumper_available = dumper.is_file()

        if not dumper_available:
            return {
                "il2cppdumper_available": False,
                "il2cppdumper_path": str(dumper),
                "error": "Il2CppDumper is not installed in the static container.",
                "hint": (
                    "Install Il2CppDumper and set IL2CPPDUMPER_PATH to its binary. "
                    "Docker image should have /usr/local/bin/il2cppdumper."
                ),
                "metadata_path": metadata_artifact["path"],
                "libil2cpp_path": libil2cpp_artifact["path"] if libil2cpp_artifact else None,
                "dynamic_hypotheses": [
                    "Intercept network and anti-tamper behaviour at runtime — IL2CPP metadata not statically recovered.",
                    "Use Frida to hook libil2cpp.so entry points for auth and network flows.",
                    "Run analyze_native_strings on libil2cpp.so for partial string recovery.",
                ],
            }

        # Extract artifacts to workspace
        try:
            local_metadata = extract_artifact_to_workspace(session, metadata_artifact["path"])
        except (FileNotFoundError, ValueError) as exc:
            return {"error": f"Could not extract global-metadata.dat: {exc}"}

        local_il2cpp: Path | None = None
        if libil2cpp_artifact:
            try:
                local_il2cpp = extract_artifact_to_workspace(session, libil2cpp_artifact["path"])
            except (FileNotFoundError, ValueError):
                pass

        if local_il2cpp is None:
            return {
                "il2cppdumper_available": True,
                "error": (
                    "metadata-only layout: libil2cpp.so was not found in this APK. "
                    "Il2CppDumper requires both the native library and global-metadata.dat."
                ),
                "hint": (
                    "Verify the APK layout with list_static_artifacts. "
                    "If libil2cpp.so exists under a non-standard ABI directory, "
                    "use analyze_native_strings on it directly."
                ),
                "metadata_path": metadata_artifact["path"],
                "dynamic_hypotheses": [
                    "Use Frida to hook managed code at runtime — metadata-only layout cannot be statically dumped.",
                    "Check for libil2cpp.so under non-standard ABI directories with list_static_artifacts.",
                ],
            }

        output_dir = ensure_session_artifact_path(session, "unity_il2cpp", "dumper_output")
        output_dir.mkdir(parents=True, exist_ok=True)

        # Run Il2CppDumper: <dumper> <libil2cpp.so> <global-metadata.dat> <output_dir>
        stdout, stderr, rc = await run_local(
            [str(dumper), str(local_il2cpp), str(local_metadata), str(output_dir)],
            timeout=300,
        )

        if rc != 0:
            return {
                "il2cppdumper_available": True,
                "error": f"Il2CppDumper exited with code {rc}",
                "stderr": stderr[:2000],
                "stdout": stdout[:1000],
                "metadata_path": metadata_artifact["path"],
            }

        # Read dump.cs output
        dump_cs = output_dir / "dump.cs"
        if not dump_cs.is_file():
            return {
                "il2cppdumper_available": True,
                "error": "Il2CppDumper ran but did not produce dump.cs",
                "output_dir": str(output_dir),
            }

        text = dump_cs.read_text(errors="replace")[:MAX_OUTPUT_BYTES]
        parsed = _parse_il2cpp_output(text)

        all_names = parsed["type_names"] + parsed["method_names"] + parsed["field_names"]
        security_categories = _categorize_names(all_names)

        result: dict[str, Any] = {
            "il2cppdumper_available": True,
            "metadata_path": metadata_artifact["path"],
            "libil2cpp_path": libil2cpp_artifact["path"] if libil2cpp_artifact else None,
            "output_dir": str(output_dir),
            "recovered_types": len(parsed["type_names"]),
            "recovered_methods": len(parsed["method_names"]),
            "recovered_fields": len(parsed["field_names"]),
            "security_categories": security_categories,
            "dynamic_hypotheses": [
                "Hook auth and session methods recovered from IL2CPP metadata at runtime.",
                "Intercept network calls from classes in the 'network' category.",
                "Test anti-tamper detection by name — hook the detected methods with Frida.",
                "Confirm payment and storage flows dynamically using recovered class names.",
            ],
            "hint": (
                "Use recovered type and method names to guide Frida hooks and traffic interception. "
                "Correlate with analyze_native_strings output for additional string-level context."
            ),
        }

        session.metadata.setdefault("unity_il2cpp", {})["metadata_analysis"] = {
            "recovered_types": result["recovered_types"],
            "recovered_methods": result["recovered_methods"],
            "security_category_counts": {k: len(v) for k, v in security_categories.items()},
        }
        return result
