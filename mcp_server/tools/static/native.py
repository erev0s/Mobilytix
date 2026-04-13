"""Native library (.so) analysis tools.

Provides lightweight native triage using ``strings`` and structured ELF
inspection via the radare2 suite (``rabin2``).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from mcp_server.backends.local_backend import run_local
from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool


DEFAULT_ARCHITECTURE = "arm64-v8a"
MAX_CATEGORY_ITEMS = 20
DEFAULT_RADARE2_LIMIT = 30
RADARE2_TIMEOUT_SECONDS = 90
DEFAULT_FUNCTION_ANALYSIS_MODE = "targeted"
DEFAULT_MAX_INSTRUCTIONS = 200
DEFAULT_MAX_DECOMPILE_LINES = 200
R2_FUNCTION_TIMEOUT_SECONDS = 120
R2_DECOMPILE_TIMEOUT_SECONDS = 180
VALID_ANALYSIS_MODES = {"targeted", "aa", "aaa"}
VALID_SYMBOL_RE = re.compile(r"^[A-Za-z0-9_.$:@?<>+\-/~]+$")
VALID_ADDRESS_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|\d+)$")
RADARE2_INFO_KEYS = (
    "arch",
    "bits",
    "bintype",
    "class",
    "machine",
    "os",
    "lang",
    "canary",
    "crypto",
    "nx",
    "pic",
    "relro",
    "stripped",
    "static",
    "va",
)


def _decoded_lib_root(session: AnalysisSession) -> Path | None:
    if not session.decoded_path:
        return None
    return Path(session.decoded_path) / "lib"


def _native_library_path(
    session: AnalysisSession,
    lib_name: str,
    architecture: str,
) -> tuple[Path | None, dict[str, Any] | None]:
    if not lib_name or ".." in lib_name or "/" in lib_name:
        return None, {"error": "Invalid library name"}
    if not architecture or ".." in architecture or architecture.startswith("/"):
        return None, {"error": "Invalid architecture"}
    if session.decoded_path is None:
        return None, {"error": "APK not yet decoded. Run get_manifest first."}

    lib_path = Path(session.decoded_path) / "lib" / architecture / lib_name
    if not lib_path.is_file():
        return None, {
            "error": f"Native library not found: {architecture}/{lib_name}",
            "hint": "Run list_native_libs to inspect available architectures and filenames.",
        }
    return lib_path, None


def _normalize_rabin2_info(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    if "bin" in payload and isinstance(payload["bin"], dict):
        return payload["bin"]
    if "core" in payload and isinstance(payload["core"], dict):
        return payload["core"]
    return payload


def _normalize_rabin2_list(payload: Any, keys: tuple[str, ...]) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in keys:
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def _dedupe(values: list[str], limit: int) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
        if len(result) >= limit:
            break
    return result


def _interesting_strings(all_strings: list[str], limit: int = MAX_CATEGORY_ITEMS) -> dict[str, list[str]]:
    interesting = {
        "urls": [],
        "paths": [],
        "crypto": [],
        "debug": [],
        "other": [],
    }

    for s in all_strings:
        s = s.strip()
        if len(s) < 4:
            continue
        s_lower = s.lower()
        if s.startswith("http://") or s.startswith("https://"):
            interesting["urls"].append(s)
        elif s.startswith("/") and not s.startswith("/usr") and not s.startswith("/lib"):
            interesting["paths"].append(s)
        elif any(kw in s_lower for kw in ["aes", "rsa", "sha", "md5", "encrypt", "decrypt", "key"]):
            interesting["crypto"].append(s)
        elif any(kw in s_lower for kw in ["debug", "log", "error", "warning", "password", "token"]):
            interesting["debug"].append(s)
        else:
            interesting["other"].append(s)

    return {key: _dedupe(values, limit) for key, values in interesting.items()}


def _select_named_entries(
    entries: list[dict[str, Any]],
    keys: tuple[str, ...],
    limit: int,
) -> list[str]:
    values: list[str] = []
    for entry in entries:
        for key in keys:
            value = entry.get(key)
            if isinstance(value, str) and value.strip():
                values.append(value.strip())
                break
    return _dedupe(values, limit)


def _section_summaries(entries: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    for entry in entries[:limit]:
        summary = {
            "name": entry.get("name"),
            "size": entry.get("size"),
            "vaddr": entry.get("vaddr"),
            "perm": entry.get("perm") or entry.get("flags"),
        }
        sections.append({k: v for k, v in summary.items() if v not in (None, "")})
    return sections


async def _run_rabin2_json(
    lib_path: Path,
    flag: str,
    timeout: int,
) -> tuple[Any | None, str | None]:
    stdout, stderr, rc = await run_local(["rabin2", flag, str(lib_path)], timeout=timeout)
    if rc != 0:
        return None, stderr[:300] or f"rabin2 {flag} failed"
    if not stdout.strip():
        return None, None
    try:
        return json.loads(stdout), None
    except json.JSONDecodeError:
        return None, f"rabin2 {flag} returned invalid JSON"


def _analysis_mode_or_error(mode: str | None) -> tuple[str | None, dict[str, Any] | None]:
    normalized = (mode or DEFAULT_FUNCTION_ANALYSIS_MODE).strip().lower()
    if normalized not in VALID_ANALYSIS_MODES:
        return None, {
            "error": (
                "Invalid analysis_mode. Supported values: "
                + ", ".join(sorted(VALID_ANALYSIS_MODES))
            )
        }
    return normalized, None


def _function_target_or_error(
    symbol: str | None,
    address: str | int | None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if symbol and address is not None:
        return None, {"error": "Provide either symbol or address, not both."}
    if symbol:
        if not VALID_SYMBOL_RE.fullmatch(symbol):
            return None, {"error": "Invalid symbol name"}
        return {"kind": "symbol", "value": symbol, "seek": symbol}, None
    if address is not None:
        address_text = str(address).strip()
        if not VALID_ADDRESS_RE.fullmatch(address_text):
            return None, {"error": "Invalid address. Use hex like 0x1234 or a decimal offset."}
        return {"kind": "address", "value": address_text, "seek": address_text}, None
    return None, {"error": "Provide either symbol or address."}


def _r2_prelude(mode: str) -> list[str]:
    commands = [
        "e scr.color=false",
        "e scr.utf8=false",
        "e asm.lines=false",
        "e asm.bytes=false",
        "e asm.cmt.right=false",
        "e asm.comments=false",
        "e anal.strings=false",
        "e anal.jmptbl=false",
        "e anal.hasnext=false",
        "e anal.autoname=false",
        "e anal.vars=false",
    ]
    if mode == "aa":
        commands.append("aa")
    elif mode == "aaa":
        commands.append("aaa")
    return commands


def _r2_target_commands(target: dict[str, Any]) -> list[str]:
    return [
        f"s {target['seek']}",
        "af @ $$",
    ]


async def _run_r2_text(
    lib_path: Path,
    commands: list[str],
    timeout: int,
) -> tuple[str, str | None]:
    joined = ";".join(commands)
    stdout, stderr, rc = await run_local(
        ["r2", "-q", "-e", "bin.cache=true", "-c", joined, str(lib_path)],
        timeout=timeout,
    )
    if rc != 0:
        err = stderr[:300] or stdout[:300] or "r2 command failed"
        return "", err
    return stdout, None


async def _run_r2_json(
    lib_path: Path,
    commands: list[str],
    timeout: int,
) -> tuple[Any | None, str | None]:
    stdout, error = await _run_r2_text(lib_path, commands, timeout)
    if error:
        return None, error
    if not stdout.strip():
        return None, None
    try:
        return json.loads(stdout), None
    except json.JSONDecodeError:
        return None, "r2 returned invalid JSON"


def _normalize_function_info(payload: Any) -> dict[str, Any]:
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        return payload[0]
    if isinstance(payload, dict):
        return payload
    return {}


def _function_summary(info: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "name": info.get("name"),
        "offset": info.get("offset"),
        "size": info.get("size"),
        "nbbs": info.get("nbbs"),
        "nargs": info.get("nargs"),
        "nlocals": info.get("nlocals"),
        "cc": info.get("cc"),
        "calltype": info.get("calltype"),
    }
    return {key: value for key, value in summary.items() if value not in (None, "")}


def _instruction_rows(pdf_payload: Any, max_instructions: int) -> tuple[list[dict[str, Any]], bool]:
    ops = []
    if isinstance(pdf_payload, dict):
        maybe_ops = pdf_payload.get("ops")
        if isinstance(maybe_ops, list):
            ops = [item for item in maybe_ops if isinstance(item, dict)]
    rows: list[dict[str, Any]] = []
    for op in ops[:max_instructions]:
        row = {
            "offset": op.get("offset"),
            "opcode": op.get("opcode") or op.get("disasm"),
            "type": op.get("type"),
            "jump": op.get("jump"),
            "fail": op.get("fail"),
            "bytes": op.get("bytes"),
        }
        rows.append({key: value for key, value in row.items() if value not in (None, "")})
    return rows, len(ops) > max_instructions


def _truncate_lines(text: str, max_lines: int) -> tuple[str, bool, int]:
    lines = text.splitlines()
    total = len(lines)
    if total <= max_lines:
        return text, False, total
    return "\n".join(lines[:max_lines]), True, total


def _r2dec_missing(output: str) -> bool:
    lowered = output.lower()
    return "unknown command" in lowered or "cannot find plugin" in lowered or "pdd?" in lowered


class ListNativeLibsTool(BaseTool):
    """List native libraries (.so files) in the APK."""

    name = "list_native_libs"
    description = (
        "List all native libraries (.so files) bundled in the APK, "
        "grouped by architecture. Shows file sizes and basic info."
    )

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        lib_root = _decoded_lib_root(session)
        if lib_root is None:
            return {"error": "APK not yet decoded. Run get_manifest first."}

        stdout, stderr, rc = await run_local(
            ["find", str(lib_root), "-name", "*.so", "-type", "f", "-exec", "ls", "-lh", "{}", ";"],
            timeout=15,
        )

        if rc != 0:
            return {"native_libs": [], "note": "No native libraries found in APK"}

        libs: dict[str, list[dict[str, Any]]] = {}
        for line in stdout.splitlines():
            parts = line.split()
            if len(parts) < 9:
                continue
            path = parts[-1]
            size = parts[4]
            rel_path = path.replace(str(lib_root) + "/", "")
            arch_parts = rel_path.split("/")
            arch = arch_parts[0] if len(arch_parts) > 1 else "unknown"
            lib_name = arch_parts[-1]

            libs.setdefault(arch, []).append({"name": lib_name, "size": size})

        return {
            "architectures": list(libs.keys()),
            "native_libs": libs,
            "total_libs": sum(len(v) for v in libs.values()),
        }


class AnalyzeNativeStringsTool(BaseTool):
    """Extract interesting strings from native libraries."""

    name = "analyze_native_strings"
    description = (
        "Run 'strings' on native libraries to find interesting embedded data: "
        "URLs, file paths, crypto constants, debug strings, etc."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "description": (
                "Disassemble one native function. Provide exactly one of symbol or address."
            ),
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "lib_name": {
                    "type": "string",
                    "description": "Name of the .so file to analyze (e.g. 'libnative.so')",
                },
                "architecture": {
                    "type": "string",
                    "description": "Architecture directory (e.g. 'arm64-v8a')",
                    "default": DEFAULT_ARCHITECTURE,
                },
            },
            "required": ["session_id", "lib_name"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        lib_name = kwargs["lib_name"]
        arch = kwargs.get("architecture", DEFAULT_ARCHITECTURE)
        lib_path, error = _native_library_path(session, lib_name, arch)
        if error:
            return error
        assert lib_path is not None

        stdout, stderr, rc = await run_local(["strings", "-a", str(lib_path)], timeout=30)
        if rc != 0:
            return {"error": f"strings failed: {stderr[:200]}"}

        all_strings = stdout.splitlines()
        return {
            "library": f"{arch}/{lib_name}",
            "total_strings": len(all_strings),
            "interesting_strings": _interesting_strings(all_strings),
        }


class AnalyzeNativeBinaryTool(BaseTool):
    """Extract structured native-library metadata with the radare2 suite."""

    name = "analyze_native_binary"
    description = (
        "Use the radare2 suite (rabin2) to inspect a native library and return ELF "
        "security properties, linked libraries, imports, symbols, JNI exports, sections, "
        "and filtered embedded strings."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "description": (
                "Disassemble one native function. Provide exactly one of symbol or address."
            ),
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "lib_name": {
                    "type": "string",
                    "description": "Name of the .so file to analyze (e.g. 'libnative.so')",
                },
                "architecture": {
                    "type": "string",
                    "description": "Architecture directory (e.g. 'arm64-v8a')",
                    "default": DEFAULT_ARCHITECTURE,
                },
                "max_items": {
                    "type": "integer",
                    "description": "Maximum number of imports/symbols/sections/strings to return per category.",
                    "default": DEFAULT_RADARE2_LIMIT,
                    "minimum": 1,
                    "maximum": 100,
                },
            },
            "required": ["session_id", "lib_name"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        lib_name = kwargs["lib_name"]
        arch = kwargs.get("architecture", DEFAULT_ARCHITECTURE)
        max_items = int(kwargs.get("max_items", DEFAULT_RADARE2_LIMIT))
        if max_items <= 0:
            return {"error": "max_items must be greater than 0."}

        lib_path, error = _native_library_path(session, lib_name, arch)
        if error:
            return error
        assert lib_path is not None

        info_payload, info_error = await _run_rabin2_json(lib_path, "-Ij", RADARE2_TIMEOUT_SECONDS)
        if info_error:
            if "not installed" in info_error.lower():
                return {
                    "error": "radare2 (rabin2) is not installed in the static container.",
                    "hint": "Install the radare2 package so analyze_native_binary can inspect ELF metadata.",
                }
            return {"error": f"rabin2 info failed: {info_error}"}

        imports_payload, imports_error = await _run_rabin2_json(lib_path, "-ij", RADARE2_TIMEOUT_SECONDS)
        libs_payload, libs_error = await _run_rabin2_json(lib_path, "-lj", RADARE2_TIMEOUT_SECONDS)
        symbols_payload, symbols_error = await _run_rabin2_json(lib_path, "-sj", RADARE2_TIMEOUT_SECONDS)
        sections_payload, sections_error = await _run_rabin2_json(lib_path, "-Sj", RADARE2_TIMEOUT_SECONDS)
        strings_payload, strings_error = await _run_rabin2_json(lib_path, "-zj", RADARE2_TIMEOUT_SECONDS)

        info = _normalize_rabin2_info(info_payload)
        imports = _normalize_rabin2_list(imports_payload, ("imports",))
        libraries = _normalize_rabin2_list(libs_payload, ("libs", "libraries"))
        symbols = _normalize_rabin2_list(symbols_payload, ("symbols",))
        sections = _normalize_rabin2_list(sections_payload, ("sections",))
        strings = _normalize_rabin2_list(strings_payload, ("strings",))

        symbol_names = _select_named_entries(symbols, ("demname", "name"), max_items)
        jni_symbols = [
            name for name in symbol_names
            if name.startswith(("Java_", "JNI_")) or "RegisterNatives" in name
        ][:max_items]
        import_names = _select_named_entries(imports, ("plt", "name"), max_items)
        library_names = _select_named_entries(libraries, ("name", "lib"), max_items)
        section_summaries = _section_summaries(sections, max_items)
        raw_strings = []
        for entry in strings:
            value = entry.get("string") or entry.get("name")
            if isinstance(value, str):
                raw_strings.append(value)

        warnings = [
            warning for warning in (
                imports_error,
                libs_error,
                symbols_error,
                sections_error,
                strings_error,
            ) if warning
        ]

        security_properties = {
            key: info.get(key)
            for key in RADARE2_INFO_KEYS
            if key in info and info.get(key) not in (None, "")
        }
        result = {
            "tool": "radare2",
            "backend": "rabin2",
            "library": f"{arch}/{lib_name}",
            "security_properties": security_properties,
            "linked_libraries": library_names,
            "imports": import_names,
            "symbols": symbol_names,
            "jni_symbols": jni_symbols,
            "sections": section_summaries,
            "interesting_strings": _interesting_strings(raw_strings),
            "summary": {
                "imports_count": len(import_names),
                "symbols_count": len(symbol_names),
                "jni_symbol_count": len(jni_symbols),
                "linked_library_count": len(library_names),
                "section_count": len(section_summaries),
            },
        }
        if warnings:
            result["warnings"] = warnings

        native_meta = session.metadata.setdefault("native_analysis", {})
        native_meta[f"{arch}/{lib_name}"] = {
            "tool": "radare2",
            "backend": "rabin2",
            "summary": result["summary"],
            "security_properties": security_properties,
        }
        return result


class DisassembleNativeFunctionTool(BaseTool):
    """Disassemble a single native function with targeted radare2 analysis."""

    name = "disassemble_native_function"
    description = (
        "Use radare2 to disassemble one function from a native library by symbol or address. "
        "Defaults to targeted analysis for better performance on large or obfuscated binaries."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "lib_name": {
                    "type": "string",
                    "description": "Name of the .so file to analyze (e.g. 'libnative.so')",
                },
                "architecture": {
                    "type": "string",
                    "description": "Architecture directory (e.g. 'arm64-v8a')",
                    "default": DEFAULT_ARCHITECTURE,
                },
                "symbol": {
                    "type": "string",
                    "description": "Function symbol or flag to disassemble (e.g. 'sym.Java_com_app_Native_init').",
                },
                "address": {
                    "type": "string",
                    "description": "Function address or file offset (e.g. '0x1234').",
                },
                "analysis_mode": {
                    "type": "string",
                    "enum": sorted(VALID_ANALYSIS_MODES),
                    "default": DEFAULT_FUNCTION_ANALYSIS_MODE,
                    "description": "targeted (default) avoids whole-file auto-analysis; aa and aaa are deeper but slower.",
                },
                "max_instructions": {
                    "type": "integer",
                    "default": DEFAULT_MAX_INSTRUCTIONS,
                    "minimum": 1,
                    "maximum": 1000,
                    "description": "Maximum instructions to return.",
                },
            },
            "required": ["session_id", "lib_name"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        lib_name = kwargs["lib_name"]
        arch = kwargs.get("architecture", DEFAULT_ARCHITECTURE)
        lib_path, error = _native_library_path(session, lib_name, arch)
        if error:
            return error
        assert lib_path is not None

        target, error = _function_target_or_error(kwargs.get("symbol"), kwargs.get("address"))
        if error:
            return error
        assert target is not None

        analysis_mode, error = _analysis_mode_or_error(kwargs.get("analysis_mode"))
        if error:
            return error
        assert analysis_mode is not None

        max_instructions = int(kwargs.get("max_instructions", DEFAULT_MAX_INSTRUCTIONS))
        if max_instructions <= 0:
            return {"error": "max_instructions must be greater than 0."}

        afij_payload, afij_error = await _run_r2_json(
            lib_path,
            _r2_prelude(analysis_mode) + _r2_target_commands(target) + ["afij @ $$"],
            timeout=R2_FUNCTION_TIMEOUT_SECONDS,
        )
        if afij_error:
            if "not installed" in afij_error.lower():
                return {
                    "error": "radare2 (r2) is not installed in the static container.",
                    "hint": "Install radare2 so disassemble_native_function can run targeted analysis.",
                }
            return {"error": f"r2 function analysis failed: {afij_error}"}

        function_info = _normalize_function_info(afij_payload)
        if not function_info:
            return {
                "error": "Could not resolve a function at the requested symbol/address.",
                "target": target,
                "hint": "Try analyze_native_binary first to enumerate symbols or pass an exact address.",
            }

        pdf_payload, pdf_error = await _run_r2_json(
            lib_path,
            _r2_prelude(analysis_mode) + _r2_target_commands(target) + ["pdfj @ $$"],
            timeout=R2_FUNCTION_TIMEOUT_SECONDS,
        )
        if pdf_error:
            return {"error": f"r2 disassembly failed: {pdf_error}"}

        instructions, truncated = _instruction_rows(pdf_payload, max_instructions)
        result = {
            "tool": "radare2",
            "backend": "r2",
            "library": f"{arch}/{lib_name}",
            "analysis_mode": analysis_mode,
            "target": target,
            "function": _function_summary(function_info),
            "instructions": instructions,
            "instruction_count": len(instructions),
            "truncated": truncated,
        }
        return result


class DecompileNativeFunctionTool(BaseTool):
    """Decompile a single native function with r2dec."""

    name = "decompile_native_function"
    description = (
        "Use radare2 with the r2dec plugin to decompile one function from a native library "
        "by symbol or address. Defaults to targeted analysis for better performance on "
        "large or obfuscated binaries."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "description": (
                "Decompile one native function. Provide exactly one of symbol or address."
            ),
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "lib_name": {
                    "type": "string",
                    "description": "Name of the .so file to analyze (e.g. 'libnative.so')",
                },
                "architecture": {
                    "type": "string",
                    "description": "Architecture directory (e.g. 'arm64-v8a')",
                    "default": DEFAULT_ARCHITECTURE,
                },
                "symbol": {
                    "type": "string",
                    "description": "Function symbol or flag to decompile.",
                },
                "address": {
                    "type": "string",
                    "description": "Function address or file offset (e.g. '0x1234').",
                },
                "analysis_mode": {
                    "type": "string",
                    "enum": sorted(VALID_ANALYSIS_MODES),
                    "default": DEFAULT_FUNCTION_ANALYSIS_MODE,
                    "description": "targeted (default) avoids whole-file auto-analysis; aa and aaa are deeper but slower.",
                },
                "max_lines": {
                    "type": "integer",
                    "default": DEFAULT_MAX_DECOMPILE_LINES,
                    "minimum": 1,
                    "maximum": 1000,
                    "description": "Maximum decompiled lines to return.",
                },
            },
            "required": ["session_id", "lib_name"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        lib_name = kwargs["lib_name"]
        arch = kwargs.get("architecture", DEFAULT_ARCHITECTURE)
        lib_path, error = _native_library_path(session, lib_name, arch)
        if error:
            return error
        assert lib_path is not None

        target, error = _function_target_or_error(kwargs.get("symbol"), kwargs.get("address"))
        if error:
            return error
        assert target is not None

        analysis_mode, error = _analysis_mode_or_error(kwargs.get("analysis_mode"))
        if error:
            return error
        assert analysis_mode is not None

        max_lines = int(kwargs.get("max_lines", DEFAULT_MAX_DECOMPILE_LINES))
        if max_lines <= 0:
            return {"error": "max_lines must be greater than 0."}

        afij_payload, afij_error = await _run_r2_json(
            lib_path,
            _r2_prelude(analysis_mode) + _r2_target_commands(target) + ["afij @ $$"],
            timeout=R2_FUNCTION_TIMEOUT_SECONDS,
        )
        if afij_error:
            if "not installed" in afij_error.lower():
                return {
                    "error": "radare2 (r2) is not installed in the static container.",
                    "hint": "Install radare2 so decompile_native_function can run targeted analysis.",
                }
            return {"error": f"r2 function analysis failed: {afij_error}"}

        function_info = _normalize_function_info(afij_payload)
        if not function_info:
            return {
                "error": "Could not resolve a function at the requested symbol/address.",
                "target": target,
                "hint": "Try analyze_native_binary first to enumerate symbols or pass an exact address.",
            }

        decompiled, decomp_error = await _run_r2_text(
            lib_path,
            _r2_prelude(analysis_mode)
            + [
                "e r2dec.slow=false",
                "e r2dec.blocks=false",
            ]
            + _r2_target_commands(target)
            + ["pdd"],
            timeout=R2_DECOMPILE_TIMEOUT_SECONDS,
        )
        if decomp_error:
            return {"error": f"r2dec failed: {decomp_error}"}
        if _r2dec_missing(decompiled):
            return {
                "error": "r2dec is not installed in the static container.",
                "hint": "Install the r2dec plugin so decompile_native_function can return pseudo-C output.",
            }

        decompiled_text, truncated, total_lines = _truncate_lines(decompiled.rstrip(), max_lines)
        result = {
            "tool": "radare2",
            "backend": "r2dec",
            "library": f"{arch}/{lib_name}",
            "analysis_mode": analysis_mode,
            "target": target,
            "function": _function_summary(function_info),
            "decompiled": decompiled_text,
            "line_count": min(total_lines, max_lines) if truncated else total_lines,
            "total_line_count": total_lines,
            "truncated": truncated,
        }
        return result
