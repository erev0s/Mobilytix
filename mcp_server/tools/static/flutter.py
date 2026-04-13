"""Flutter-specific static analysis tools."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Optional

from mcp_server.backends.local_backend import run_local
from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool
from mcp_server.tools.static.manifest import _ensure_decoded
from mcp_server.tools.static.routing import (
    ensure_artifact_index,
    ensure_framework_metadata,
    _read_apk_entry_bytes,
)
from mcp_server.tools.workspace import ensure_session_artifact_path, session_workspace


DEFAULT_FLUTTER_AOT_ARCH = "arm64-v8a"
SUPPORTED_FLUTTER_AOT_ARCHS = {DEFAULT_FLUTTER_AOT_ARCH}
BLUTTER_HOME_ENV = "BLUTTER_HOME"
DEFAULT_BLUTTER_HOME = "/opt/blutter"
DEFAULT_BLUTTER_TIMEOUT_SECONDS = 7200
MAX_ERROR_OUTPUT_CHARS = 4000

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
CHANNEL_RE = re.compile(r"(plugins\.flutter\.io/[A-Za-z0-9._/-]+|flutter/[A-Za-z0-9._/-]+)")
ROUTE_RE = re.compile(r"(?<!https:)(?<!http:)(/[A-Za-z0-9._/-]{2,})")
STORAGE_TOKEN_SCAN_RE = re.compile(
    r"[A-Za-z0-9_.:-]*(?:token|session|prefs?|preference|storage|securestorage|hive|sqlite|realm|db)[A-Za-z0-9_.:-]*",
    re.IGNORECASE,
)

KEYWORD_GROUPS = {
    "auth_terms": ["auth", "bearer", "jwt", "login", "oauth", "refresh", "session", "token"],
    "crypto_terms": ["aes", "cipher", "encrypt", "decrypt", "hmac", "keystore", "md5", "rsa", "sha"],
    "trust_terms": ["certificate", "hostnameverifier", "pinning", "ssl", "tls", "trust", "x509"],
}

MAX_CATEGORY_ITEMS = 20
MAX_LINE_SAMPLES = 8
BLUTTER_OLD_DART_MARKERS = (
    "Dart version <2.15",
    "kLinkedHashSetCid",
    "UntaggedObject",
)


def _blutter_home() -> Path:
    return Path(os.environ.get(BLUTTER_HOME_ENV, DEFAULT_BLUTTER_HOME))


def _blutter_script() -> Path:
    return _blutter_home() / "blutter.py"


def _aot_output_dir(session: AnalysisSession, architecture: str) -> Path:
    return ensure_session_artifact_path(session, "flutter_aot", architecture)


def _truncate_output(text: str, limit: int = MAX_ERROR_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-(limit // 2) :]
    return f"{head}\n...\n{tail}"


def _classify_blutter_failure(stdout: str, stderr: str) -> dict[str, Any]:
    combined = f"{stdout}\n{stderr}"
    if any(marker in combined for marker in BLUTTER_OLD_DART_MARKERS):
        return {
            "failure_category": "blutter_dart_sdk_incompatible",
            "likely_cause": (
                "The target APK uses an older Dart runtime, and the bundled blutter build path "
                "failed to compile against that SDK."
            ),
            "hint": (
                "Current blutter builds are geared toward recent Dart versions. Fall back to "
                "flutter_assets review, native string extraction from libapp.so/libflutter.so, "
                "and dynamic platform-channel/network tracing."
            ),
            "fallback_recommended_tools": [
                "list_static_artifacts",
                "read_static_artifact",
                "search_static_artifacts",
                "analyze_native_strings",
                "get_security_overview",
            ],
        }
    return {}


def _scan_text_file(path: Path) -> dict[str, list[str]]:
    results = {
        "urls": [],
        "channel_names": [],
        "routes": [],
        "storage_identifiers": [],
        "auth_terms": [],
        "crypto_terms": [],
        "trust_terms": [],
    }
    line_samples = {
        "auth_terms": [],
        "crypto_terms": [],
        "trust_terms": [],
    }

    if not path.is_file():
        return {**results, "auth_lines": [], "crypto_lines": [], "trust_lines": []}

    seen = {key: set() for key in results}
    seen_lines = {key: set() for key in line_samples}

    with open(path, "r", errors="replace") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue

            for match in URL_RE.findall(line):
                if len(seen["urls"]) < MAX_CATEGORY_ITEMS and match not in seen["urls"]:
                    seen["urls"].add(match)
                    results["urls"].append(match)

            for match in CHANNEL_RE.findall(line):
                if len(seen["channel_names"]) < MAX_CATEGORY_ITEMS and match not in seen["channel_names"]:
                    seen["channel_names"].add(match)
                    results["channel_names"].append(match)

            if "http://" not in line and "https://" not in line:
                for match in ROUTE_RE.findall(line):
                    if len(match) < 3 or match == "/":
                        continue
                    if len(seen["routes"]) < MAX_CATEGORY_ITEMS and match not in seen["routes"]:
                        seen["routes"].add(match)
                        results["routes"].append(match)

            for token in STORAGE_TOKEN_SCAN_RE.findall(line):
                if len(seen["storage_identifiers"]) < MAX_CATEGORY_ITEMS and token not in seen["storage_identifiers"]:
                    seen["storage_identifiers"].add(token)
                    results["storage_identifiers"].append(token)

            lower = line.lower()
            for key, keywords in KEYWORD_GROUPS.items():
                if any(keyword in lower for keyword in keywords):
                    tokens = re.findall(r"[A-Za-z0-9_.:/-]{3,}", line)
                    for token in tokens:
                        token_lower = token.lower()
                        if any(keyword in token_lower for keyword in keywords):
                            if len(seen[key]) < MAX_CATEGORY_ITEMS and token not in seen[key]:
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


def _merge_signal_maps(signal_maps: list[dict[str, list[str]]]) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for signal_map in signal_maps:
        for key, values in signal_map.items():
            bucket = merged.setdefault(key, [])
            seen = set(bucket)
            for value in values:
                if value not in seen:
                    bucket.append(value)
                    seen.add(value)
                if len(bucket) >= MAX_CATEGORY_ITEMS and not key.endswith("_lines"):
                    break
    return merged


def _collect_output_files(output_dir: Path) -> dict[str, Any]:
    asm_dir = output_dir / "asm"
    asm_files = sorted(str(path.relative_to(output_dir)) for path in asm_dir.glob("*")) if asm_dir.is_dir() else []
    files = {
        "objs_txt": (output_dir / "objs.txt").is_file(),
        "pp_txt": (output_dir / "pp.txt").is_file(),
        "frida_script": (output_dir / "blutter_frida.js").is_file(),
        "asm_dir": asm_dir.is_dir(),
        "asm_file_count": len(asm_files),
        "asm_files_preview": asm_files[:10],
    }
    return files


def _flutter_asset_configs(artifact_index: dict[str, Any]) -> list[str]:
    return [
        artifact["path"]
        for artifact in artifact_index.get("artifacts", {}).get("config", [])
        if artifact["path"].startswith("assets/flutter_assets/")
    ][:15]


def _pick_architecture(framework: dict[str, Any], requested_architecture: str | None) -> tuple[str, list[str]]:
    available = framework.get("format_hints", {}).get("native_abis", [])
    if requested_architecture:
        return requested_architecture, available
    if DEFAULT_FLUTTER_AOT_ARCH in available:
        return DEFAULT_FLUTTER_AOT_ARCH, available
    return DEFAULT_FLUTTER_AOT_ARCH, available


class AnalyzeFlutterAotTool(BaseTool):
    """Run blutter against a Flutter release/AOT APK and summarize the output."""

    name = "analyze_flutter_aot"
    description = (
        "Analyze a Flutter release/AOT APK with blutter. Supports Android arm64 libapp.so builds. "
        "Runs blutter on the selected ABI, parses pp.txt/objs.txt, and returns recovered endpoints, "
        "channel names, storage identifiers, and trust/auth/crypto hints."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "architecture": {
                    "type": "string",
                    "description": "Native ABI to analyze. Default: arm64-v8a.",
                    "default": DEFAULT_FLUTTER_AOT_ARCH,
                },
                "rebuild": {
                    "type": "boolean",
                    "description": "Pass --rebuild to blutter to force a rebuild for the detected Dart version.",
                    "default": False,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Maximum seconds to allow blutter to run. Default: 7200.",
                    "default": DEFAULT_BLUTTER_TIMEOUT_SECONDS,
                    "minimum": 1,
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        framework = ensure_framework_metadata(session)
        if framework.get("primary_framework") != "Flutter":
            return {"error": "This tool only applies to Flutter APKs."}

        flutter_mode = framework.get("format_hints", {}).get("flutter_mode")
        if flutter_mode != "release_aot":
            return {
                "error": "Flutter AOT analysis only applies to Flutter release/AOT builds.",
                "flutter_mode": flutter_mode,
            }

        requested_architecture = kwargs.get("architecture")
        architecture, available_abis = _pick_architecture(framework, requested_architecture)
        if architecture not in SUPPORTED_FLUTTER_AOT_ARCHS:
            return {
                "error": f"blutter currently supports only {DEFAULT_FLUTTER_AOT_ARCH}.",
                "requested_architecture": architecture,
                "available_abis": available_abis,
            }
        if available_abis and architecture not in available_abis:
            return {
                "error": f"ABI {architecture} is not present in this APK.",
                "available_abis": available_abis,
            }

        try:
            decoded_path = await _ensure_decoded(session)
        except RuntimeError as exc:
            return {"error": f"APK decode failed before Flutter AOT analysis: {exc}"}

        lib_dir = Path(decoded_path) / "lib" / architecture
        libapp = lib_dir / "libapp.so"
        libflutter = lib_dir / "libflutter.so"
        if not libapp.is_file():
            return {"error": f"Flutter AOT target not found: {libapp}"}
        if not libflutter.is_file():
            return {"error": f"Flutter engine library not found: {libflutter}"}

        output_dir = _aot_output_dir(session, architecture)
        output_dir.mkdir(parents=True, exist_ok=True)

        rebuild = kwargs.get("rebuild", False)
        timeout = int(kwargs.get("timeout_seconds", DEFAULT_BLUTTER_TIMEOUT_SECONDS))
        if timeout <= 0:
            return {"error": "timeout_seconds must be greater than 0."}

        outputs = _collect_output_files(output_dir)
        if not rebuild and outputs["objs_txt"] and outputs["pp_txt"]:
            parsed = self._build_result(session, architecture, output_dir, framework)
            parsed["cached"] = True
            return parsed

        blutter_script = _blutter_script()
        if not blutter_script.is_file():
            return {
                "error": "blutter is not installed in the static container.",
                "expected_path": str(blutter_script),
                "hint": "Install blutter and its build dependencies, then rerun analyze_flutter_aot.",
            }

        command = ["python3", str(blutter_script), str(lib_dir), str(output_dir)]
        if rebuild:
            command.append("--rebuild")

        stdout, stderr, rc = await run_local(
            command,
            cwd=str(_blutter_home()),
            timeout=timeout,
        )
        if rc != 0:
            outputs = _collect_output_files(output_dir)
            failure_details = _classify_blutter_failure(stdout, stderr)
            return {
                "error": "blutter failed",
                "architecture": architecture,
                "timeout_seconds": timeout,
                "generated_outputs": outputs,
                "stdout": _truncate_output(stdout, 2000),
                "stderr": _truncate_output(stderr, MAX_ERROR_OUTPUT_CHARS),
                **failure_details,
            }

        parsed = self._build_result(session, architecture, output_dir, framework)
        parsed["cached"] = False
        parsed["blutter_stdout"] = stdout[:2000]
        return parsed

    def _build_result(
        self,
        session: AnalysisSession,
        architecture: str,
        output_dir: Path,
        framework: dict[str, Any],
    ) -> dict[str, Any]:
        outputs = _collect_output_files(output_dir)
        signal_maps = [
            _scan_text_file(output_dir / "pp.txt"),
            _scan_text_file(output_dir / "objs.txt"),
        ]
        merged = _merge_signal_maps(signal_maps)

        artifact_index = ensure_artifact_index(session)
        flutter_assets = _flutter_asset_configs(artifact_index)

        analysis = {
            "tool": "blutter",
            "blutter_available": _blutter_script().is_file(),
            "architecture": architecture,
            "output_dir": str(output_dir),
            "supported_architectures": sorted(SUPPORTED_FLUTTER_AOT_ARCHS),
            "available_abis": framework.get("format_hints", {}).get("native_abis", []),
            "generated_outputs": outputs,
            "flutter_asset_configs": flutter_assets,
            "recovered": {
                "urls": merged.get("urls", []),
                "channel_names": merged.get("channel_names", []),
                "routes": merged.get("routes", []),
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
            "hint": (
                "Correlate recovered URLs, channel names, and storage identifiers with flutter_assets, "
                "manifest findings, and dynamic interception."
            ),
        }

        flutter_meta = session.metadata.setdefault("flutter_aot", {"tool": "blutter", "analyses": {}})
        flutter_meta["tool"] = "blutter"
        flutter_meta["blutter_home"] = str(_blutter_home())
        flutter_meta["last_architecture"] = architecture
        flutter_meta["analyses"][architecture] = analysis

        return analysis


# ---------------------------------------------------------------------------
# Flutter debug / recoverable asset analysis
# ---------------------------------------------------------------------------

_PLUGIN_REGISTRANT_RE = re.compile(
    r"(?:GeneratedPluginRegistrant|registerWith|PluginRegistry)\s*[\.\(]"
    r".*?[\"']?([A-Za-z0-9_.$]+(?:Plugin|Channel|Module))[\"']?",
    re.IGNORECASE,
)
_CHANNEL_NAME_RE = re.compile(
    r"MethodChannel\s*\(\s*[\"']([^\"']+)[\"']|"
    r"EventChannel\s*\(\s*[\"']([^\"']+)[\"']|"
    r"BasicMessageChannel\s*\(\s*[\"']([^\"']+)[\"']",
)
_MAX_DEBUG_ASSET_FILES = 30
_MAX_DEBUG_ASSET_BYTES = 256 * 1024


class AnalyzeFlutterDebugTool(BaseTool):
    """Structured plugin/channel analysis for Flutter debug or recoverable builds."""

    name = "analyze_flutter_debug"
    description = (
        "Analyze a Flutter debug or less-optimized APK. "
        "Scans flutter_assets/ for channel names, routes, URLs, and storage identifiers. "
        "Reads decompiled wrapper code for GeneratedPluginRegistrant entries and "
        "MethodChannel/EventChannel declarations. "
        "Returns a structured plugin_map, recovered signals, and wrapper_correlation notes. "
        "Only applicable when flutter_mode is 'debug_or_recoverable'."
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
        if framework.get("primary_framework") != "Flutter":
            return {"error": "This tool only applies to Flutter APKs."}

        flutter_mode = framework.get("format_hints", {}).get("flutter_mode")
        if flutter_mode != "debug_or_recoverable":
            return {
                "error": "analyze_flutter_debug only applies to Flutter debug/recoverable builds.",
                "flutter_mode": flutter_mode,
                "hint": "For release/AOT builds, use analyze_flutter_aot instead.",
            }

        try:
            decoded_path = await _ensure_decoded(session)
        except RuntimeError as exc:
            return {"error": f"APK decode failed: {exc}"}

        artifact_index = ensure_artifact_index(session)

        # Scan flutter_assets config files
        flutter_asset_files = [
            a for a in artifact_index.get("artifacts", {}).get("config", [])
            if a["path"].startswith("assets/flutter_assets/") and a.get("text_compatible")
        ][:_MAX_DEBUG_ASSET_FILES]

        apk_path = f"{session_workspace(session)}/app.apk"
        signal_maps = []
        for artifact in flutter_asset_files:
            raw = _read_apk_entry_bytes(apk_path, artifact["path"], max_bytes=_MAX_DEBUG_ASSET_BYTES)
            if raw:
                text = raw.decode("utf-8", errors="replace")
                signal_maps.append(_scan_text_from_string(text))

        merged = _merge_signal_maps(signal_maps) if signal_maps else {}

        # Scan decompiled wrapper source for plugin registrations and channel names
        plugin_names: list[str] = []
        channel_names: list[str] = []
        wrapper_files_scanned: list[str] = []

        decoded = Path(decoded_path)
        source_dirs = ["sources", "java"]
        for src_dir_name in source_dirs:
            src_dir = decoded / src_dir_name
            if not src_dir.is_dir():
                continue
            for java_file in list(src_dir.rglob("*.java"))[:50]:
                try:
                    text = java_file.read_text(errors="replace")
                except OSError:
                    continue
                wrapper_files_scanned.append(str(java_file.relative_to(decoded)))
                for m in _PLUGIN_REGISTRANT_RE.findall(text):
                    if m and m not in plugin_names and len(plugin_names) < MAX_CATEGORY_ITEMS:
                        plugin_names.append(m)
                for m in _CHANNEL_NAME_RE.findall(text):
                    for name in m:
                        if name and name not in channel_names and len(channel_names) < MAX_CATEGORY_ITEMS:
                            channel_names.append(name)

        # Also scan flutter_assets text files for channel name patterns
        channel_names_from_assets: list[str] = merged.get("channel_names", [])
        for cn in channel_names_from_assets:
            if cn not in channel_names and len(channel_names) < MAX_CATEGORY_ITEMS:
                channel_names.append(cn)

        # Build plugin_map
        plugin_map: dict[str, str] = {name: "detected in wrapper source" for name in plugin_names}

        # Flag high-risk channel names
        high_risk_channels = [
            cn for cn in channel_names
            if any(kw in cn.lower() for kw in ["payment", "auth", "biometric", "camera", "file", "storage", "location"])
        ]

        _blob = _read_apk_entry_bytes(apk_path, "assets/flutter_assets/kernel_blob.bin", max_bytes=4)
        kernel_blob_present = _blob is not None

        analysis: dict[str, Any] = {
            "flutter_mode": flutter_mode,
            "flutter_assets_scanned": len(flutter_asset_files),
            "wrapper_files_scanned": len(wrapper_files_scanned),
            "kernel_blob_present": kernel_blob_present,
            "plugin_map": plugin_map,
            "channel_names": channel_names,
            "high_risk_channels": high_risk_channels,
            "recovered": {
                "urls": merged.get("urls", []),
                "channel_names": channel_names,
                "routes": merged.get("routes", []),
                "storage_identifiers": merged.get("storage_identifiers", []),
                "auth_terms": merged.get("auth_terms", []),
                "crypto_terms": merged.get("crypto_terms", []),
                "trust_terms": merged.get("trust_terms", []),
            },
            "wrapper_correlation": (
                f"Found {len(plugin_names)} plugin registrations and {len(channel_names)} "
                f"channel names in wrapper source ({len(wrapper_files_scanned)} files scanned)."
            ),
            "dynamic_hypotheses": [
                "Hook platform-channel calls for high-risk channels identified above.",
                "Intercept backend endpoints recovered from flutter_assets.",
                "Validate certificate pinning and root-detection paths dynamically.",
                "Test plugin permission usage at runtime (camera, file, storage).",
            ],
            "hint": (
                "Correlate channel names with flutter_assets routes and wrapper bridge code. "
                "Use get_security_overview(scan_mode='bytecode') for bridge call triage."
            ),
        }

        session.metadata.setdefault("flutter_debug", {})["analysis"] = {
            "flutter_mode": flutter_mode,
            "plugin_count": len(plugin_names),
            "channel_count": len(channel_names),
        }
        return analysis


def _scan_text_from_string(text: str) -> dict:
    """Scan signal map from an in-memory string (used for flutter_assets content)."""
    results = {
        "urls": [], "channel_names": [], "routes": [], "storage_identifiers": [],
        "auth_terms": [], "crypto_terms": [], "trust_terms": [],
    }
    line_samples = {"auth_terms": [], "crypto_terms": [], "trust_terms": []}
    seen = {key: set() for key in results}
    seen_lines = {key: set() for key in line_samples}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        for match in URL_RE.findall(line):
            if len(seen["urls"]) < MAX_CATEGORY_ITEMS and match not in seen["urls"]:
                seen["urls"].add(match)
                results["urls"].append(match)
        for match in CHANNEL_RE.findall(line):
            if len(seen["channel_names"]) < MAX_CATEGORY_ITEMS and match not in seen["channel_names"]:
                seen["channel_names"].add(match)
                results["channel_names"].append(match)
        if "http://" not in line and "https://" not in line:
            for match in ROUTE_RE.findall(line):
                if len(match) < 3 or match == "/":
                    continue
                if len(seen["routes"]) < MAX_CATEGORY_ITEMS and match not in seen["routes"]:
                    seen["routes"].add(match)
                    results["routes"].append(match)
        for token in STORAGE_TOKEN_SCAN_RE.findall(line):
            if len(seen["storage_identifiers"]) < MAX_CATEGORY_ITEMS and token not in seen["storage_identifiers"]:
                seen["storage_identifiers"].add(token)
                results["storage_identifiers"].append(token)
        lower = line.lower()
        for key, keywords in KEYWORD_GROUPS.items():
            if any(keyword in lower for keyword in keywords):
                tokens = re.findall(r"[A-Za-z0-9_.:/-]{3,}", line)
                for token in tokens:
                    if any(keyword in token.lower() for keyword in keywords):
                        if len(seen[key]) < MAX_CATEGORY_ITEMS and token not in seen[key]:
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
