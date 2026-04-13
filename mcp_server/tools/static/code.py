"""Decompilation and source code analysis tools.

Provides tools for jadx decompilation, source code search (via ripgrep),
file reading, class enumeration (via androguard), and class analysis.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from loguru import logger

from mcp_server.backends.local_backend import read_file_content, run_local
from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool
from mcp_server.tools.static.routing import get_wrapper_only_warning
from mcp_server.tools.workspace import session_workspace


def _workspace_path(session: AnalysisSession) -> str:
    """Return the workspace directory for a session inside the container."""
    return str(session_workspace(session))


async def _ensure_decompiled(session: AnalysisSession) -> str:
    """Ensure the APK has been decompiled with jadx. Returns decompiled path.

    If jadx was already run for this session, returns the cached path.
    Otherwise runs jadx now. This allows tools like find_crypto_issues and
    search_source to auto-decompile instead of requiring the user to
    explicitly call decompile_apk first.
    """
    if session.decompiled_path:
        return session.decompiled_path

    ws = _workspace_path(session)
    decompiled = f"{ws}/decompiled"

    # Check if a previous run already left jadx output on disk
    check_stdout, _, check_rc = await run_local(["ls", decompiled], timeout=5)
    if check_rc == 0:
        session.decompiled_path = decompiled
        return decompiled

    apk = f"{ws}/app.apk"
    logger.info("Auto-decompiling APK with jadx (needed by calling tool)...")
    stdout, stderr, rc = await run_local(
        ["jadx", "--deobf", "-d", decompiled, "--threads-count", "4", apk],
        timeout=300,
    )
    if rc != 0 and "ERROR" in stderr:
        logger.warning("jadx reported errors: {}", stderr[:500])

    check_stdout, _, check_rc = await run_local(["ls", decompiled], timeout=5)
    if check_rc != 0:
        raise RuntimeError(f"Auto-decompilation failed: {stderr[:1000]}")

    session.decompiled_path = decompiled
    return decompiled


class DecompileApkTool(BaseTool):
    """Decompile the APK using jadx to produce Java source code.

    This must be run before search_source, read_source_file, or any
    tool that needs decompiled code. Idempotent — if already decompiled,
    returns the existing source tree.
    """

    name = "decompile_apk"
    description = (
        "Decompile the APK with jadx to produce readable Java source. "
        "Must be called before searching or reading source code. "
        "Returns the source tree structure."
    )

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        ws = _workspace_path(session)
        decompiled = f"{ws}/decompiled"
        apk = f"{ws}/app.apk"

        # Idempotent check
        if session.decompiled_path:
            result = await self._get_source_tree(session)
            warning = get_wrapper_only_warning(session, self.name)
            if warning:
                result["warning"] = warning
            return result

        # Run jadx
        logger.info("Decompiling APK with jadx...")
        stdout, stderr, rc = await run_local(
            [
                "jadx",
                "--deobf",
                "-d", decompiled,
                "--threads-count", "4",
                apk,
            ],
            timeout=300,
        )

        if rc != 0 and "ERROR" in stderr:
            # jadx may return non-zero but still produce output
            logger.warning("jadx reported errors: {}", stderr[:500])

        # Verify output exists
        check_stdout, _, check_rc = await run_local(
            ["ls", decompiled], timeout=5
        )
        if check_rc != 0:
            return {"error": f"Decompilation failed: {stderr[:1000]}"}

        session.decompiled_path = decompiled
        result = await self._get_source_tree(session)
        warning = get_wrapper_only_warning(session, self.name)
        if warning:
            result["warning"] = warning
        return result

    async def _get_source_tree(self, session: AnalysisSession) -> dict:
        """Return the source tree structure."""
        decompiled = session.decompiled_path

        # Get all Java files
        stdout, _, rc = await run_local(
            ["find", decompiled, "-name", "*.java", "-type", "f"],
            timeout=30,
        )

        files = []
        if rc == 0 and stdout.strip():
            all_files = stdout.strip().split("\n")
            # Make paths relative to decompiled root
            rel_files = [
                f.replace(decompiled + "/", "") for f in all_files if f.strip()
            ]
            total = len(rel_files)

            # Group by top-level package
            packages: dict[str, list[str]] = {}
            for f in sorted(rel_files):
                parts = f.split("/")
                pkg = parts[0] if len(parts) > 1 else "(root)"
                if pkg not in packages:
                    packages[pkg] = []
                packages[pkg].append(f)

            # Limit output
            files = rel_files[:200]

            return {
                "decompiled_path": decompiled,
                "total_java_files": total,
                "files_shown": len(files),
                "source_tree": files,
                "packages": {k: len(v) for k, v in packages.items()},
            }

        return {
            "decompiled_path": decompiled,
            "total_java_files": 0,
            "source_tree": [],
        }


class SearchSourceTool(BaseTool):
    """Search decompiled source code for a regex pattern.

    Uses ripgrep for fast searching with context lines. Results are capped
    at 50 matches. Supports file glob filters.
    """

    name = "search_source"
    description = (
        "Search decompiled Java source for a regex pattern using ripgrep. "
        "Returns matching lines with context. Use file_filter for glob patterns "
        "(e.g. '*.java'). Max 50 results returned."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for",
                },
                "file_filter": {
                    "type": "string",
                    "description": "Glob pattern for files to search (e.g. '*.java')",
                },
                "context_lines": {
                    "type": "integer",
                    "description": "Number of context lines before/after match (default: 3)",
                    "default": 3,
                },
            },
            "required": ["session_id", "pattern"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        try:
            await _ensure_decompiled(session)
        except RuntimeError as e:
            return {"error": str(e)}

        pattern = kwargs["pattern"]
        file_filter = kwargs.get("file_filter", "")
        context_lines = kwargs.get("context_lines", 3)

        cmd = [
            "rg",
            "--json",
            "-C", str(context_lines),
            "--max-count", "50",
        ]

        if file_filter:
            cmd.extend(["-g", file_filter])

        cmd.extend([pattern, session.decompiled_path])

        stdout, stderr, rc = await run_local(
            cmd, timeout=60
        )

        # ripgrep returns 1 if no matches, 2+ for errors
        if rc >= 2:
            return {"error": f"Search failed: {stderr[:500]}"}

        # Parse JSON output
        matches = []
        total_matches = 0
        for line in stdout.splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                if obj.get("type") == "match":
                    data = obj["data"]
                    match_path = data["path"]["text"].replace(
                        session.decompiled_path + "/", ""
                    )
                    match_text = data["lines"]["text"].rstrip("\n")
                    line_num = data["line_number"]

                    # Get submatches
                    submatches = []
                    for sm in data.get("submatches", []):
                        submatches.append(sm["match"]["text"])

                    matches.append({
                        "file": match_path,
                        "line": line_num,
                        "match": match_text,
                        "submatches": submatches,
                    })
                    total_matches += 1
                elif obj.get("type") == "summary":
                    # Get total stats
                    stats = obj.get("data", {}).get("stats", {})
                    total_matches = stats.get("matches", total_matches)
            except json.JSONDecodeError:
                continue

        truncated = total_matches > 50
        result = {
            "pattern": pattern,
            "total_matches": total_matches,
            "matches_shown": len(matches),
            "truncated": truncated,
            "matches": matches[:50],
        }
        warning = get_wrapper_only_warning(session, self.name)
        if warning:
            result["warning"] = warning
        return result


class ReadSourceFileTool(BaseTool):
    """Read the contents of a decompiled source file.

    Validates the path is within the decompiled directory to prevent
    path traversal attacks.
    """

    name = "read_source_file"
    description = (
        "Read the full contents of a decompiled Java source file. "
        "Provide the file path relative to the decompiled root "
        "(as returned by decompile_apk or search_source)."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "file_path": {
                    "type": "string",
                    "description": "File path relative to the decompiled root",
                },
            },
            "required": ["session_id", "file_path"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        try:
            await _ensure_decompiled(session)
        except RuntimeError as e:
            return {"error": str(e)}

        file_path = kwargs["file_path"]

        # Security: prevent path traversal
        if ".." in file_path or file_path.startswith("/"):
            return {"error": "Invalid file path — no absolute paths or '..' allowed"}

        full_path = f"{session.decompiled_path}/{file_path}"

        stdout, stderr, rc = await read_file_content(full_path)

        if rc != 0:
            return {"error": f"Cannot read file: {stderr[:200]}"}

        # Truncate very large files
        max_chars = 50000
        truncated = len(stdout) > max_chars

        return {
            "file_path": file_path,
            "content": stdout[:max_chars],
            "truncated": truncated,
            "total_chars": len(stdout),
        }


class GetClassListTool(BaseTool):
    """Enumerate all classes in the APK's DEX files using androguard.

    Returns class names grouped by package. By default returns only a
    summary (package names + counts) to keep output manageable. Use
    ``package_filter`` to drill into a specific package and see its classes.
    """

    name = "get_class_list"
    description = (
        "List all classes in the APK's DEX files, grouped by package. "
        "Returns a summary of packages and class counts by default. "
        "Use package_filter to see classes in a specific package "
        "(e.g. 'com.example.myapp'). Filters out Android/Java framework "
        "classes to focus on the app's own code."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "package_filter": {
                    "type": "string",
                    "description": (
                        "Optional package prefix to filter by (e.g. 'com.example'). "
                        "When set, returns the actual class names in that package."
                    ),
                },
                "include_framework": {
                    "type": "boolean",
                    "description": "Include Android/Java framework classes (default: false)",
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        ws = _workspace_path(session)
        apk = f"{ws}/app.apk"
        package_filter = kwargs.get("package_filter", "")
        include_framework = kwargs.get("include_framework", False)

        # Use androguard inside the container — suppress its verbose logging
        script = f"""
from androguard.util import set_log
set_log("ERROR")
from androguard.misc import AnalyzeAPK
import json, sys

try:
    a, d, dx = AnalyzeAPK('{apk}')
    classes = sorted(set(c.name for c in dx.get_classes()))
    print(json.dumps(classes))
except Exception as e:
    print(json.dumps({{"error": str(e)}}))
    sys.exit(0)
"""

        stdout, stderr, rc = await run_local(
            ["python3", "-c", script],
            timeout=120,
        )

        if rc != 0:
            return {"error": f"androguard failed (rc={rc}): {stderr[:500]}"}

        try:
            classes = json.loads(stdout)
        except json.JSONDecodeError:
            return {"error": "Failed to parse androguard output", "raw": stdout[:1000]}

        # Handle error returned from the try/except in the script
        if isinstance(classes, dict) and "error" in classes:
            return classes

        # Framework package prefixes to filter out by default
        FRAMEWORK_PREFIXES = (
            "Landroid/", "Landroidx/", "Ljava/", "Ljavax/", "Lkotlin/",
            "Lkotlinx/", "Lcom/google/android/", "Ldalvik/", "Lorg/json/",
            "Lorg/w3c/", "Lorg/xml/", "Lsun/", "Lorg/apache/",
        )

        # Group by package, optionally filtering framework classes
        packages: dict[str, list[str]] = {}
        for cls_name in classes:
            if not include_framework and cls_name.startswith(FRAMEWORK_PREFIXES):
                continue

            # Convert Lcom/example/Class; -> com.example.Class
            clean = cls_name.replace("/", ".").strip("L;")
            parts = clean.rsplit(".", 1)
            pkg = parts[0] if len(parts) > 1 else "(default)"
            if pkg not in packages:
                packages[pkg] = []
            packages[pkg].append(clean)

        app_class_count = sum(len(v) for v in packages.values())

        # If a package filter is given, return classes for matching packages
        if package_filter:
            filtered_packages = {
                k: v for k, v in sorted(packages.items())
                if k.startswith(package_filter)
            }
            filtered_classes = []
            for class_list in filtered_packages.values():
                filtered_classes.extend(class_list)

            return {
                "total_classes_in_apk": len(classes),
                "app_classes": app_class_count,
                "filter": package_filter,
                "matching_packages": len(filtered_packages),
                "matching_classes": len(filtered_classes),
                "packages": {k: v for k, v in sorted(filtered_packages.items())},
            }

        # Default: return summary only (package names + counts)
        return {
            "total_classes_in_apk": len(classes),
            "app_classes": app_class_count,
            "package_count": len(packages),
            "packages": {k: len(v) for k, v in sorted(packages.items())},
            "hint": (
                "Use package_filter to see classes in a specific package "
                "(e.g. package_filter='com.example')."
            ),
        }


class AnalyzeClassTool(BaseTool):
    """Analyze a specific class using androguard.

    Returns detailed information: methods with signatures, fields, superclass,
    interfaces, string constants, and method calls made.
    """

    name = "analyze_class"
    description = (
        "Analyze a specific Java class: list methods with signatures, fields, "
        "superclass, interfaces, string constants, and method calls. "
        "Provide the class name in Java notation (e.g. 'com.example.LoginActivity')."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "class_name": {
                    "type": "string",
                    "description": "Fully qualified class name (e.g. 'com.example.LoginActivity')",
                },
            },
            "required": ["session_id", "class_name"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        class_name = kwargs["class_name"]
        ws = _workspace_path(session)
        apk = f"{ws}/app.apk"

        # Convert Java notation to DEX notation
        dex_name = "L" + class_name.replace(".", "/") + ";"
        apk_json = json.dumps(apk)
        dex_name_json = json.dumps(dex_name)
        class_name_json = json.dumps(class_name)

        script = f"""
from androguard.util import set_log
set_log("ERROR")
from androguard.misc import AnalyzeAPK
import json, sys

APK_PATH = {apk_json}
DEX_NAME = {dex_name_json}
CLASS_NAME = {class_name_json}

try:
    a, d, dx = AnalyzeAPK(APK_PATH)

    target_class = None
    for c in dx.get_classes():
        if c.name == DEX_NAME:
            target_class = c
            break

    if target_class is None:
        print(json.dumps({{"error": f"Class not found: {{CLASS_NAME}}"}}))
        sys.exit(0)

    result = {{
        "class_name": CLASS_NAME,
        "methods": [],
        "fields": [],
        "superclass": "",
        "interfaces": [],
        "strings": [],
        "method_calls": [],
    }}

    cls_obj = target_class.get_vm_class()

    if cls_obj:
        result["superclass"] = cls_obj.get_superclassname().replace("/", ".").strip("L;")
        result["interfaces"] = [
            i.replace("/", ".").strip("L;") for i in (cls_obj.get_interfaces() or [])
        ]

        for method in cls_obj.get_methods():
            m_info = {{
                "name": method.get_name(),
                "descriptor": method.get_descriptor(),
                "access_flags": method.get_access_flags_string(),
            }}
            result["methods"].append(m_info)

        for field in cls_obj.get_fields():
            f_info = {{
                "name": field.get_name(),
                "descriptor": field.get_descriptor(),
                "access_flags": field.get_access_flags_string(),
            }}
            result["fields"].append(f_info)

        strings_seen = set()
        calls_seen = set()
        for method in cls_obj.get_methods():
            m_analysis = dx.get_method(method)
            if m_analysis:
                for _, call, _ in m_analysis.get_xref_to():
                    if hasattr(call, 'get_name'):
                        call_str = (
                            call.get_class_name().replace("/", ".").strip("L;")
                            + "."
                            + call.get_name()
                        )
                        if len(calls_seen) < 50:
                            calls_seen.add(call_str)

        result["method_calls"] = sorted(calls_seen)[:50]

    print(json.dumps(result))
except Exception as e:
    print(json.dumps({{"error": str(e)}}))
"""

        stdout, stderr, rc = await run_local(
            ["python3", "-c", script],
            timeout=120,
        )

        if rc != 0:
            return {"error": f"Class analysis failed: {stderr[:500]}"}

        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return {"error": "Failed to parse output", "raw": stdout[:1000]}
