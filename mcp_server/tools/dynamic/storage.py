"""App data storage analysis tools.

Tools for pulling and analyzing app-private data: databases, shared
preferences, and file permissions.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Optional

from loguru import logger

from mcp_server.backends.local_backend import run_local, read_file_content
from mcp_server.config import config
from mcp_server.models.enums import AnalysisPhase, FindingCategory, Severity
from mcp_server.models.finding import Finding
from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool
from mcp_server.tools.workspace import session_workspace

# Patterns indicating sensitive data in shared preferences
SENSITIVE_PREF_PATTERNS = [
    (re.compile(r"password", re.IGNORECASE), "Password stored in SharedPreferences"),
    (re.compile(r"token", re.IGNORECASE), "Token stored in SharedPreferences"),
    (re.compile(r"api[_-]?key", re.IGNORECASE), "API key stored in SharedPreferences"),
    (re.compile(r"secret", re.IGNORECASE), "Secret stored in SharedPreferences"),
    (re.compile(r"pin(?:code)?", re.IGNORECASE), "PIN stored in SharedPreferences"),
    (re.compile(r"session[_-]?id", re.IGNORECASE), "Session ID stored in SharedPreferences"),
    (re.compile(r"credit[_-]?card|card[_-]?number", re.IGNORECASE), "Card number in SharedPreferences"),
]


async def _resolve_session_package_name(session: AnalysisSession) -> tuple[str | None, str | None]:
    """Resolve the target package name from session state or the APK itself."""
    if session.package_name:
        return session.package_name, "session"

    metadata_package = session.metadata.get("package_name")
    if isinstance(metadata_package, str) and metadata_package:
        session.package_name = metadata_package
        return metadata_package, "metadata"

    apk_metadata = session.metadata.get("apk_metadata")
    if isinstance(apk_metadata, dict):
        apk_package = apk_metadata.get("package_name")
        if isinstance(apk_package, str) and apk_package:
            session.package_name = apk_package
            return apk_package, "apk_metadata"

    manifest = session.metadata.get("manifest")
    if isinstance(manifest, dict):
        manifest_package = manifest.get("package")
        if isinstance(manifest_package, str) and manifest_package:
            session.package_name = manifest_package
            return manifest_package, "manifest"

    ws = str(session_workspace(session))
    apk = f"{ws}/app.apk"
    stdout, _, rc = await run_local(
        ["aapt2", "dump", "badging", apk],
        timeout=60,
    )
    if rc == 0:
        for line in stdout.splitlines():
            if not line.startswith("package:"):
                continue
            for part in line.split():
                if part.startswith("name="):
                    package_name = part.split("=", 1)[1].strip("'")
                    if package_name:
                        session.package_name = package_name
                        session.metadata["package_name"] = package_name
                        apk_meta = session.metadata.setdefault("apk_metadata", {})
                        if isinstance(apk_meta, dict):
                            apk_meta["package_name"] = package_name
                        return package_name, "aapt2"

    return None, None


class PullAppDataTool(BaseTool):
    """Pull the app's private data directory from the device."""

    name = "pull_app_data"
    description = (
        "Pull /data/data/<package> from the device to the workspace. "
        "Automatically resolves the package name from session state or the APK "
        "if needed. Returns a listing of databases, shared_prefs, files, and cache."
    )

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        package, package_source = await _resolve_session_package_name(session)
        if not package:
            return {
                "error": "Package name unknown.",
                "hint": (
                    "Mobilytix could not resolve the package name from the session "
                    "or APK. Run get_apk_metadata or get_manifest to populate it explicitly."
                ),
            }

        ws = str(session_workspace(session))
        dest = f"{ws}/app_data"

        # Pull data via adb (requires root or run-as)
        await run_local(
            ["mkdir", "-p", dest],
            timeout=5,
        )

        # Probe whether run-as access is available so errors are easier to explain.
        run_as_stdout, run_as_stderr, run_as_rc = await run_local(
            ["adb", "shell", "run-as", package, "ls", f"/data/data/{package}"],
            timeout=30,
        )

        stdout, stderr, rc = await run_local(
            ["adb", "pull", f"/data/data/{package}/", dest],
            timeout=60,
        )
        if rc != 0:
            hint = (
                "The app may require a rooted device or a debuggable build that supports run-as."
                if run_as_rc != 0
                else "run-as access appears available, so verify the package path and adb connectivity."
            )
            return {
                "error": f"Could not pull app data for {package}: {stderr[:500] or stdout[:500]}",
                "package": package,
                "package_name_source": package_source,
                "hint": hint,
                "run_as_check": {
                    "available": run_as_rc == 0,
                    "output": (run_as_stdout or run_as_stderr)[:500],
                },
            }

        # List what was pulled
        ls_stdout, _, _ = await run_local(
            ["find", dest, "-type", "f", "-ls"],
            timeout=15,
        )

        files = {}
        for line in ls_stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 11:
                perms = parts[2]
                size = parts[6]
                path = parts[-1].replace(dest + "/", "")

                # Categorize
                if "shared_prefs" in path:
                    cat = "shared_prefs"
                elif "databases" in path:
                    cat = "databases"
                elif "cache" in path:
                    cat = "cache"
                else:
                    cat = "files"

                if cat not in files:
                    files[cat] = []
                files[cat].append({
                    "path": path,
                    "size": size,
                    "permissions": perms,
                })

        if not files:
            return {
                "error": f"App data pull for {package} completed but no files were found.",
                "package": package,
                "package_name_source": package_source,
                "data_path": dest,
                "hint": "Verify the app has written data and that adb has permission to access its sandbox.",
                "run_as_check": {
                    "available": run_as_rc == 0,
                    "output": (run_as_stdout or run_as_stderr)[:500],
                },
            }

        session.metadata["app_data_path"] = dest
        session.current_phase = AnalysisPhase.STORAGE

        return {
            "package": package,
            "package_name_source": package_source,
            "data_path": dest,
            "categories": {k: len(v) for k, v in files.items()},
            "files": files,
            "run_as_check": {
                "available": run_as_rc == 0,
                "output": (run_as_stdout or run_as_stderr)[:500],
            },
        }


class ReadSharedPreferencesTool(BaseTool):
    """Read and analyze a SharedPreferences XML file.

    Automatically creates findings for values that look like passwords,
    tokens, keys, or PII.
    """

    name = "read_shared_preferences"
    description = (
        "Read and parse a SharedPreferences XML file from the app's data. "
        "Automatically flags sensitive values (passwords, tokens, keys)."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "pref_file": {
                    "type": "string",
                    "description": "SharedPreferences filename (e.g. 'myprefs.xml')",
                },
            },
            "required": ["session_id", "pref_file"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        pref_file = kwargs["pref_file"]

        if ".." in pref_file or "/" in pref_file:
            return {"error": "Invalid filename — no paths allowed"}

        data_path = session.metadata.get("app_data_path")
        if not data_path:
            return {"error": "App data not pulled yet. Run pull_app_data first."}

        # Find the pref file
        stdout, _, rc = await run_local(
            ["find", data_path, "-name", pref_file, "-type", "f"],
            timeout=10,
        )

        if rc != 0 or not stdout.strip():
            return {"error": f"Preferences file not found: {pref_file}"}

        pref_path = stdout.strip().splitlines()[0]

        # Read file
        content, _, rc = await read_file_content(pref_path)

        if rc != 0:
            return {"error": "Cannot read preferences file"}

        # Parse XML
        prefs = {}
        findings_created = []

        try:
            root = ET.fromstring(content)
            for elem in root:
                name = elem.get("name", "")
                value = elem.get("value", elem.text or "")
                pref_type = elem.tag
                prefs[name] = {"type": pref_type, "value": str(value)}

                # Check for sensitive values
                for pattern, title in SENSITIVE_PREF_PATTERNS:
                    if pattern.search(name):
                        finding = Finding(
                            title=title,
                            severity=Severity.HIGH,
                            category=FindingCategory.INSECURE_DATA_STORAGE,
                            description=(
                                f"Sensitive data (key: '{name}') is stored in "
                                f"SharedPreferences ({pref_file}). SharedPreferences "
                                f"are stored as plaintext XML on the device."
                            ),
                            evidence=f"{name} = {str(value)[:200]}",
                            location=f"shared_prefs/{pref_file}",
                            tool="read_shared_preferences",
                            phase=AnalysisPhase.STORAGE.value,
                            cwe_id="CWE-312",
                            recommendation=(
                                "Use EncryptedSharedPreferences or Android Keystore "
                                "for sensitive data storage."
                            ),
                        )
                        if session.add_finding(finding):
                            findings_created.append(finding.to_dict())
                        break
        except ET.ParseError as e:
            return {"error": f"XML parse error: {e}", "raw_content": content[:2000]}

        return {
            "file": pref_file,
            "entries": len(prefs),
            "preferences": prefs,
            "findings_created": len(findings_created),
        }


class QueryAppDatabaseTool(BaseTool):
    """Query an app's SQLite database with a SELECT statement.

    Only SELECT queries are allowed for safety.
    """

    name = "query_app_database"
    description = (
        "Run a SQL SELECT query against an app's SQLite database. "
        "Only SELECT queries are allowed. Returns rows as a list of dicts."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "db_name": {
                    "type": "string",
                    "description": "Database filename (e.g. 'app.db')",
                },
                "query": {
                    "type": "string",
                    "description": "SQL SELECT query to execute",
                },
            },
            "required": ["session_id", "db_name", "query"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        db_name = kwargs["db_name"]
        query = kwargs["query"].strip()

        # Security: only allow SELECT
        if not query.upper().startswith("SELECT"):
            return {"error": "Only SELECT queries are allowed for safety."}

        # Block destructive keywords
        dangerous = ["DROP", "DELETE", "INSERT", "UPDATE", "ALTER", "CREATE", "ATTACH"]
        query_upper = query.upper()
        for keyword in dangerous:
            if keyword in query_upper:
                return {"error": f"Query contains forbidden keyword: {keyword}"}

        if ".." in db_name or "/" in db_name:
            return {"error": "Invalid database name"}

        data_path = session.metadata.get("app_data_path")
        if not data_path:
            return {"error": "App data not pulled yet. Run pull_app_data first."}

        # Find the database
        stdout, _, rc = await run_local(
            ["find", data_path, "-name", db_name, "-type", "f"],
            timeout=10,
        )

        if rc != 0 or not stdout.strip():
            return {"error": f"Database not found: {db_name}"}

        db_path = stdout.strip().splitlines()[0]

        # Run query
        stdout, stderr, rc = await run_local(
            ["sqlite3", "-json", db_path, query],
            timeout=30,
        )

        if rc != 0:
            return {"error": f"Query failed: {stderr[:500]}"}

        try:
            rows = json.loads(stdout) if stdout.strip() else []
        except json.JSONDecodeError:
            # Fallback: parse CSV-like output
            rows = stdout.strip()

        return {
            "database": db_name,
            "query": query,
            "rows": rows if isinstance(rows, list) else [{"result": rows}],
            "row_count": len(rows) if isinstance(rows, list) else 1,
        }


class ListAppFilesTool(BaseTool):
    """List files in the app's data directory.

    Automatically creates findings for world-readable or world-writable files.
    """

    name = "list_app_files"
    description = (
        "List files in the app's data directory with sizes and permissions. "
        "Flags world-readable or world-writable files as findings."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "directory": {
                    "type": "string",
                    "description": "Subdirectory to list (relative to app data dir)",
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        directory = kwargs.get("directory", "")
        data_path = session.metadata.get("app_data_path", "")

        if not data_path:
            return {"error": "App data not pulled yet. Run pull_app_data first."}

        if directory:
            if ".." in directory:
                return {"error": "Invalid directory path"}
            target = f"{data_path}/{directory}"
        else:
            target = data_path

        stdout, _, rc = await run_local(
            ["find", target, "-type", "f", "-ls"],
            timeout=15,
        )

        files = []
        findings_created = []

        for line in stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 11:
                perms = parts[2]
                size = parts[6]
                path = parts[-1].replace(data_path + "/", "")

                files.append({
                    "path": path,
                    "size": size,
                    "permissions": perms,
                })

                # Check for world-readable/writable
                if len(perms) >= 10:
                    if perms[7] == "r" or perms[8] == "w":
                        finding = Finding(
                            title=f"World-accessible file: {path}",
                            severity=Severity.MEDIUM,
                            category=FindingCategory.INSECURE_DATA_STORAGE,
                            description=(
                                f"The file {path} has world-readable or world-writable "
                                f"permissions ({perms}). Other apps can access this file."
                            ),
                            evidence=f"Permissions: {perms}, Path: {path}",
                            location=path,
                            tool="list_app_files",
                            phase=AnalysisPhase.STORAGE.value,
                            cwe_id="CWE-276",
                            recommendation=(
                                "Set file permissions to MODE_PRIVATE. "
                                "Use Context.MODE_PRIVATE when creating files."
                            ),
                        )
                        if session.add_finding(finding):
                            findings_created.append(finding.to_dict())

        return {
            "total_files": len(files),
            "files": files,
            "findings_created": len(findings_created),
        }
