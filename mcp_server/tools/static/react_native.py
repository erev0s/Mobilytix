"""React Native static analysis tools."""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import Any, Optional

from mcp_server.backends.local_backend import run_local
from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool
from mcp_server.tools.static.routing import (
    _read_apk_entry_bytes,
    ensure_artifact_index,
    ensure_framework_metadata,
    extract_artifact_to_workspace,
)
from mcp_server.tools.workspace import session_artifact_path, session_workspace

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HERMES_MAGIC = b"HBC\x00"
HERMES_MAGIC_ALT = bytes.fromhex("c61fbc03")
HERMES_DEC_ENV = "HERMES_DEC_PATH"
HERMES_FILE_PARSER = "hbc-file-parser"
HERMES_DISASSEMBLER = "hbc-disassembler"
HERMES_DECOMPILER = "hbc-decompiler"
DEFAULT_HERMES_DEC = f"/opt/hermes-dec/{HERMES_DECOMPILER}"
DEFAULT_HERMES_TIMEOUT_SECONDS = 300

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
NATIVE_MODULE_RE = re.compile(
    r"(?:NativeModules|TurboModuleRegistry\.get|requireNativeComponent|NativeEventEmitter)"
    r"(?:\.([A-Za-z0-9_]+)|[\s\S]{0,60}?[\"']([A-Za-z0-9_]+)[\"'])"
)
STORAGE_RE = re.compile(
    r"[A-Za-z0-9_.:-]*(?:AsyncStorage|MMKV|SecureStore|keychain|storage|prefs?|preference)[A-Za-z0-9_.:-]*",
    re.IGNORECASE,
)
OTA_RE = re.compile(
    r"(?:CodePush|expo-updates|expo\.modules\.updates|__fbBatchedBridgeConfig|"
    r"hotupdate|ota_update|bundle_url|bundleUrl)",
    re.IGNORECASE,
)
ROUTE_RE = re.compile(r"(?<!https:)(?<!http:)(/[A-Za-z0-9._/-]{2,})")
QUOTED_TOKEN_RE = re.compile(r"[\"']([A-Za-z0-9_.:/-]{3,120})[\"']")

KEYWORD_GROUPS = {
    "auth_terms": ["auth", "bearer", "jwt", "login", "oauth", "refresh", "session", "token"],
    "crypto_terms": [
        "aes",
        "cipher",
        "encrypt",
        "decrypt",
        "hmac",
        "keystore",
        "md5",
        "rsa",
        "sha",
    ],
    "trust_terms": [
        "certificate",
        "hostnameverifier",
        "pinning",
        "ssl",
        "tls",
        "trust",
        "x509",
    ],
}

MAX_BUNDLE_BYTES = 8 * 1024 * 1024  # 8 MB scan limit
MAX_CATEGORY_ITEMS = 25
MAX_LINE_SAMPLES = 8
MAX_ERROR_OUTPUT_CHARS = 4000
SIGNAL_MAP_KEYS = (
    "urls",
    "native_modules",
    "storage_identifiers",
    "ota_patterns",
    "routes",
    "auth_terms",
    "crypto_terms",
    "trust_terms",
    "auth_lines",
    "crypto_lines",
    "trust_lines",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hermes_tool_path() -> Path:
    return _resolve_hermes_tool(HERMES_DECOMPILER) or Path(
        os.environ.get(HERMES_DEC_ENV, DEFAULT_HERMES_DEC)
    )


def _resolve_hermes_tool(tool_name: str) -> Path | None:
    configured = os.environ.get(HERMES_DEC_ENV)
    candidates: list[Path] = []

    if configured:
        configured_path = Path(configured)
        if configured_path.is_dir():
            candidates.append(configured_path / tool_name)
        elif tool_name == HERMES_DECOMPILER:
            candidates.append(configured_path)
        else:
            candidates.append(configured_path.with_name(tool_name))

    default_path = Path(DEFAULT_HERMES_DEC)
    candidates.append(
        default_path if tool_name == HERMES_DECOMPILER else default_path.with_name(tool_name)
    )

    which = shutil.which(tool_name)
    if which:
        candidates.append(Path(which))

    seen: set[str] = set()
    for candidate in candidates:
        candidate_str = str(candidate)
        if candidate_str in seen:
            continue
        seen.add(candidate_str)
        if candidate.is_file():
            return candidate
    return None


def _hermes_tool_paths() -> dict[str, Path | None]:
    return {
        "file_parser": _resolve_hermes_tool(HERMES_FILE_PARSER),
        "disassembler": _resolve_hermes_tool(HERMES_DISASSEMBLER),
        "decompiler": _resolve_hermes_tool(HERMES_DECOMPILER),
    }


def _is_hermes(header: bytes) -> bool:
    return header[:4] == HERMES_MAGIC or header[:4] == HERMES_MAGIC_ALT


def _find_bundle_path(artifact_index: dict[str, Any]) -> str | None:
    for artifact in artifact_index.get("artifacts", {}).get("js_bundle", []):
        if (
            artifact["path"].endswith((".bundle", ".hbc"))
            or artifact["path"].endswith("index.android.bundle")
        ):
            return artifact["path"]
    return None


def _scan_bundle_text(content: str) -> dict[str, Any]:
    results: dict[str, list] = {
        "urls": [],
        "native_modules": [],
        "storage_identifiers": [],
        "ota_patterns": [],
        "routes": [],
        "auth_terms": [],
        "crypto_terms": [],
        "trust_terms": [],
    }
    line_samples: dict[str, list] = {k: [] for k in ("auth_terms", "crypto_terms", "trust_terms")}
    seen: dict[str, set] = {k: set() for k in results}
    seen_lines: dict[str, set] = {k: set() for k in line_samples}

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        for m in URL_RE.findall(line):
            if len(results["urls"]) < MAX_CATEGORY_ITEMS and m not in seen["urls"]:
                seen["urls"].add(m)
                results["urls"].append(m)

        for groups in NATIVE_MODULE_RE.findall(line):
            m = groups[0] or groups[1]
            if (
                m
                and len(results["native_modules"]) < MAX_CATEGORY_ITEMS
                and m not in seen["native_modules"]
            ):
                seen["native_modules"].add(m)
                results["native_modules"].append(m)

        storage_matches = STORAGE_RE.findall(line)
        for m in storage_matches:
            if (
                len(results["storage_identifiers"]) < MAX_CATEGORY_ITEMS
                and m not in seen["storage_identifiers"]
            ):
                seen["storage_identifiers"].add(m)
                results["storage_identifiers"].append(m)
        if storage_matches:
            for token in QUOTED_TOKEN_RE.findall(line):
                if token.startswith(("http://", "https://")):
                    continue
                if (
                    len(results["storage_identifiers"]) < MAX_CATEGORY_ITEMS
                    and token not in seen["storage_identifiers"]
                ):
                    seen["storage_identifiers"].add(token)
                    results["storage_identifiers"].append(token)

        for m in OTA_RE.findall(line):
            if len(results["ota_patterns"]) < MAX_CATEGORY_ITEMS and m not in seen["ota_patterns"]:
                seen["ota_patterns"].add(m)
                results["ota_patterns"].append(m)

        if "http://" not in line and "https://" not in line:
            for m in ROUTE_RE.findall(line):
                if len(m) < 3 or m == "/":
                    continue
                if len(results["routes"]) < MAX_CATEGORY_ITEMS and m not in seen["routes"]:
                    seen["routes"].add(m)
                    results["routes"].append(m)

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


def _empty_signal_map() -> dict[str, list[str]]:
    return {key: [] for key in SIGNAL_MAP_KEYS}


def _merge_signal_maps(signal_maps: list[dict[str, list[str]]]) -> dict[str, list[str]]:
    merged = _empty_signal_map()
    seen = {key: set() for key in SIGNAL_MAP_KEYS}

    for signal_map in signal_maps:
        for key in SIGNAL_MAP_KEYS:
            values = signal_map.get(key, [])
            bucket = merged[key]
            limit = MAX_LINE_SAMPLES if key.endswith("_lines") else MAX_CATEGORY_ITEMS
            for value in values:
                if value in seen[key]:
                    continue
                seen[key].add(value)
                bucket.append(value)
                if len(bucket) >= limit:
                    break

    return merged


def _scan_text_file(path: Path) -> dict[str, list[str]]:
    if not path.is_file():
        return _empty_signal_map()
    try:
        return _scan_bundle_text(path.read_text("utf-8", errors="replace"))
    except OSError:
        return _empty_signal_map()


def _truncate_output(text: str, limit: int = MAX_ERROR_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-(limit // 2) :]
    return f"{head}\n...\n{tail}"


def _hermes_output_dir(session: AnalysisSession, bundle_path: str) -> Path:
    output_dir = session_artifact_path(session, "react_native", "hermes", *Path(bundle_path).parts)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def _hermes_generated_outputs(output_dir: Path) -> dict[str, Any]:
    file_parser = output_dir / "file_parser.txt"
    disassembly = output_dir / "bundle.hasm"
    decompiled = output_dir / "bundle.dec.js"
    return {
        "output_dir": str(output_dir),
        "file_parser": str(file_parser) if file_parser.is_file() else None,
        "disassembly": str(disassembly) if disassembly.is_file() else None,
        "decompiled": str(decompiled) if decompiled.is_file() else None,
    }


async def _run_hermes_dec(
    session: AnalysisSession,
    bundle_path: str,
    *,
    rebuild: bool,
    timeout_seconds: int,
) -> dict[str, Any]:
    tool_paths = _hermes_tool_paths()
    decompiler = tool_paths["decompiler"]
    output_dir = _hermes_output_dir(session, bundle_path)
    bundle_file = extract_artifact_to_workspace(session, bundle_path)
    file_parser_output = output_dir / "file_parser.txt"
    disassembly_output = output_dir / "bundle.hasm"
    decompiled_output = output_dir / "bundle.dec.js"

    backend = {
        "tool": "hermes-dec",
        "available": decompiler is not None,
        "tool_paths": {name: str(path) if path else None for name, path in tool_paths.items()},
        "bundle_file": str(bundle_file),
        "output_dir": str(output_dir),
        "generated_outputs": _hermes_generated_outputs(output_dir),
        "commands": {},
        "status": "not_installed",
    }
    if decompiler is None:
        return backend

    if not rebuild and decompiled_output.is_file():
        backend["status"] = "cached"
        backend["generated_outputs"] = _hermes_generated_outputs(output_dir)
        return backend

    parser = tool_paths["file_parser"]
    if parser is not None:
        stdout, stderr, rc = await run_local(
            [str(parser), str(bundle_file)],
            timeout=timeout_seconds,
        )
        parser_text = stdout.strip() or stderr.strip()
        if parser_text:
            file_parser_output.write_text(parser_text, encoding="utf-8")
        cmd = {"rc": rc}
        if rc != 0:
            if stdout.strip():
                cmd["stdout"] = _truncate_output(stdout)
            if stderr.strip():
                cmd["stderr"] = _truncate_output(stderr)
        backend["commands"]["file_parser"] = cmd

    disassembler = tool_paths["disassembler"]
    if disassembler is not None:
        stdout, stderr, rc = await run_local(
            [str(disassembler), str(bundle_file), str(disassembly_output)],
            timeout=timeout_seconds,
        )
        cmd = {"rc": rc}
        if rc != 0:
            if stdout.strip():
                cmd["stdout"] = _truncate_output(stdout)
            if stderr.strip():
                cmd["stderr"] = _truncate_output(stderr)
        backend["commands"]["disassembler"] = cmd

    stdout, stderr, rc = await run_local(
        [str(decompiler), str(bundle_file), str(decompiled_output)],
        timeout=timeout_seconds,
    )
    decompiler_cmd = {"rc": rc}
    if rc != 0:
        if stdout.strip():
            decompiler_cmd["stdout"] = _truncate_output(stdout)
        if stderr.strip():
            decompiler_cmd["stderr"] = _truncate_output(stderr)
    backend["commands"]["decompiler"] = decompiler_cmd

    generated = _hermes_generated_outputs(output_dir)
    backend["generated_outputs"] = generated
    if generated["decompiled"]:
        backend["status"] = "success"
    elif generated["disassembly"] or generated["file_parser"]:
        backend["status"] = "partial_success"
    else:
        backend["status"] = "failed"

    return backend


def _extract_hermes_strings(data: bytes) -> list[str]:
    """Best-effort string extraction from Hermes bytecode via null-terminated scan."""
    strings: list[str] = []
    seen: set[str] = set()
    i = 0
    while i < len(data) - 1:
        # Find printable ASCII run of at least 6 chars followed by null byte
        j = i
        while j < len(data) and 0x20 <= data[j] <= 0x7E:
            j += 1
        length = j - i
        if length >= 6 and j < len(data) and data[j] == 0:
            s = data[i:j].decode("ascii", errors="replace")
            if s not in seen:
                seen.add(s)
                strings.append(s)
        i = j + 1 if j > i else i + 1
    return strings[:2000]


class AnalyzeReactNativeBundleTool(BaseTool):
    """Structured signal extraction from a React Native JS bundle or Hermes bytecode."""

    name = "analyze_react_native_bundle"
    description = (
        "Analyze a React Native APK's JS bundle. "
        "For plain JS bundles, extracts endpoints, native module references, auth/crypto/trust "
        "signals, storage keys, OTA patterns, and routes. "
        "For Hermes bytecode, extracts partial strings and provides explicit dynamic follow-up "
        "hypotheses. Outputs a structured 'recovered' dict parallel to analyze_flutter_aot."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "rebuild": {
                    "type": "boolean",
                    "description": "Re-run hermes-dec even if cached Hermes outputs already exist.",
                    "default": False,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": (
                        "Maximum seconds to allow hermes-dec subcommands to run on Hermes "
                        "bundles."
                    ),
                    "default": DEFAULT_HERMES_TIMEOUT_SECONDS,
                    "minimum": 1,
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        framework = ensure_framework_metadata(session)
        primary = framework.get("primary_framework", "")
        if primary not in {"React Native", "Expo (React Native)"}:
            return {
                "error": "This tool only applies to React Native / Expo APKs.",
                "primary_framework": primary,
            }

        artifact_index = ensure_artifact_index(session)
        bundle_path = _find_bundle_path(artifact_index)
        if not bundle_path:
            return {
                "error": "No JS bundle found in this APK.",
                "hint": (
                    "Expected assets/index.android.bundle or similar. "
                    "Use list_static_artifacts to inspect."
                ),
            }

        apk_path = f"{session_workspace(session)}/app.apk"
        raw = _read_apk_entry_bytes(apk_path, bundle_path, max_bytes=MAX_BUNDLE_BYTES)
        if raw is None:
            return {"error": f"Could not read bundle from APK: {bundle_path}"}

        format_hints = framework.get("format_hints", {})
        js_bundle_type = format_hints.get("js_bundle_type", "plain_js")

        # Detect Hermes by header even if format_hints says plain_js (double-check)
        if _is_hermes(raw[:4]):
            js_bundle_type = "hermes"

        if js_bundle_type == "hermes":
            rebuild = bool(kwargs.get("rebuild", False))
            timeout_seconds = int(kwargs.get("timeout_seconds", DEFAULT_HERMES_TIMEOUT_SECONDS))
            if timeout_seconds <= 0:
                return {"error": "timeout_seconds must be greater than 0."}
            return await self._analyze_hermes(
                session,
                bundle_path,
                raw,
                format_hints,
                rebuild=rebuild,
                timeout_seconds=timeout_seconds,
            )
        else:
            return self._analyze_plain_js(session, bundle_path, raw, format_hints)

    def _analyze_plain_js(
        self,
        session: AnalysisSession,
        bundle_path: str,
        raw: bytes,
        format_hints: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            content = raw.decode("utf-8", errors="replace")
        except Exception as exc:
            return {"error": f"Failed to decode JS bundle as text: {exc}"}

        signals = _scan_bundle_text(content)
        bundle_size_kb = len(raw) // 1024
        truncated = len(raw) >= MAX_BUNDLE_BYTES

        result: dict[str, Any] = {
            "bundle_path": bundle_path,
            "bundle_type": "plain_js",
            "bundle_size_kb": bundle_size_kb,
            "truncated": truncated,
            "recovered": {
                "urls": signals["urls"],
                "native_modules": signals["native_modules"],
                "storage_identifiers": signals["storage_identifiers"],
                "ota_patterns": signals["ota_patterns"],
                "routes": signals["routes"],
                "auth_terms": signals["auth_terms"],
                "crypto_terms": signals["crypto_terms"],
                "trust_terms": signals["trust_terms"],
            },
            "signal_lines": {
                "auth": signals["auth_lines"],
                "crypto": signals["crypto_lines"],
                "trust": signals["trust_lines"],
            },
            "dynamic_hypotheses": [
                "Intercept API calls to URLs recovered from the bundle.",
                "Hook native modules to trace cross-JS-to-native data flows.",
                "Test OTA/update endpoints if CodePush or expo-updates patterns are present.",
                "Trace storage reads/writes via AsyncStorage or SecureStore hooks.",
            ],
            "hint": (
                "Correlate recovered URLs and native module names with the Android bridge "
                "classes, manifest deep links, and dynamic traffic capture."
            ),
        }

        session.metadata.setdefault("react_native", {})["bundle_analysis"] = {
            "bundle_path": bundle_path,
            "bundle_type": "plain_js",
            "bundle_size_kb": bundle_size_kb,
        }
        return result

    async def _analyze_hermes(
        self,
        session: AnalysisSession,
        bundle_path: str,
        raw: bytes,
        format_hints: dict[str, Any],
        *,
        rebuild: bool,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        hermes_backend = await _run_hermes_dec(
            session,
            bundle_path,
            rebuild=rebuild,
            timeout_seconds=timeout_seconds,
        )
        hermes_tool = _hermes_tool_path()
        hermes_tool_available = hermes_backend["available"]

        # Best-effort string extraction regardless of tool availability
        partial_strings = _extract_hermes_strings(raw)
        signal_maps = [_scan_bundle_text("\n".join(partial_strings))]
        generated_outputs = hermes_backend["generated_outputs"]
        if generated_outputs["decompiled"]:
            signal_maps.append(_scan_text_file(Path(generated_outputs["decompiled"])))
        if generated_outputs["disassembly"]:
            signal_maps.append(_scan_text_file(Path(generated_outputs["disassembly"])))
        merged = _merge_signal_maps(signal_maps)

        recovered = {
            "urls": merged["urls"],
            "native_modules": merged["native_modules"],
            "storage_identifiers": merged["storage_identifiers"],
            "ota_patterns": merged["ota_patterns"],
            "routes": merged["routes"],
            "auth_terms": merged["auth_terms"],
            "crypto_terms": merged["crypto_terms"],
            "trust_terms": merged["trust_terms"],
            # Backward-compatible aliases for the older Hermes-only response shape.
            "auth_hints": merged["auth_terms"],
            "crypto_hints": merged["crypto_terms"],
            "storage_hints": merged["storage_identifiers"],
        }

        result: dict[str, Any] = {
            "bundle_path": bundle_path,
            "bundle_type": "hermes",
            "hermes_tool_available": hermes_tool_available,
            "hermes_tool_path": str(hermes_tool),
            "bundle_size_kb": len(raw) // 1024,
            "truncated": len(raw) >= MAX_BUNDLE_BYTES,
            "partial_strings_extracted": len(partial_strings),
            "recovered": recovered,
            "signal_lines": {
                "auth": merged["auth_lines"],
                "crypto": merged["crypto_lines"],
                "trust": merged["trust_lines"],
            },
            "hermes_backend": hermes_backend,
            "generated_outputs": generated_outputs,
            "dynamic_hypotheses": [
                "Use runtime traffic capture to confirm all API endpoints not recovered "
                "statically from Hermes output.",
                "Hook bridge entry points (native modules) that accept JS-controlled data.",
                "Trace authentication flows dynamically; pseudo-code still misses some "
                "control-flow detail.",
                "Instrument AsyncStorage and SecureStore calls at runtime to recover storage keys.",
            ],
            "hint": (
                "Hermes bytecode limits static analysis. Focus on Android bridge classes, "
                "native modules (get_security_overview bytecode mode), and dynamic confirmation."
            ),
        }

        if hermes_backend["status"] in {"success", "cached"}:
            result["hint"] = (
                "hermes-dec generated pseudo-code/disassembly for this bundle. Correlate those "
                "artifacts with Android bridge classes, manifest findings, and dynamic traffic."
            )
        elif hermes_backend["status"] == "partial_success":
            result["hint"] = (
                "hermes-dec produced partial Hermes artifacts, but decompilation was incomplete. "
                "Review the generated files and confirm sensitive flows dynamically."
            )
        elif hermes_tool_available:
            result["hint"] = (
                f"hermes-dec is available at {hermes_tool}, but decompilation did not complete "
                "cleanly for this bundle. Review the command results and generated outputs."
            )

        session.metadata.setdefault("react_native", {})["bundle_analysis"] = {
            "bundle_path": bundle_path,
            "bundle_type": "hermes",
            "hermes_tool_available": hermes_tool_available,
            "hermes_status": hermes_backend["status"],
            "generated_outputs": generated_outputs,
        }
        return result
