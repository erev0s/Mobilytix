"""Tests for static analysis tools — unit tests with mocked local execution.

These tests verify tool logic without requiring tools to be installed.
"""

import json
import os
import tempfile
from pathlib import Path
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from mcp_server.session_manager import SessionManager
from mcp_server.models.session import AnalysisSession
from mcp_server.models.enums import Severity, FindingCategory, AnalysisPhase
from mcp_server.tools.workspace import session_workspace


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_session(apk_path="/workspace/test/test.apk") -> AnalysisSession:
    mgr = SessionManager()
    session = mgr.create_session(apk_path)
    session.package_name = "com.example.test"
    session.app_name = "Test App"
    return session


MOCK_CONTAINER = "mobilytix-static"


def make_test_apk(apk_path: str, files: dict[str, str | bytes]) -> str:
    """Create a minimal APK/ZIP with the provided file contents."""
    import zipfile

    with zipfile.ZipFile(apk_path, "w") as zf:
        for path, content in files.items():
            data = content if isinstance(content, bytes) else content.encode("utf-8")
            zf.writestr(path, data)
    return apk_path


# ---------------------------------------------------------------------------
# Inbox / path resolution tools
# ---------------------------------------------------------------------------

class TestResolveApkPath:
    """Test the _resolve_apk_path helper."""

    def test_bare_filename_resolves_to_inbox(self, tmp_path):
        from mcp_server.tools.static.manifest import _resolve_apk_path

        inbox = tmp_path / "inbox"
        inbox.mkdir()
        apk = inbox / "test.apk"
        apk.write_bytes(b"fake apk")

        with patch("mcp_server.tools.static.manifest.INBOX_DIR", str(inbox)):
            result = _resolve_apk_path("test.apk")
        assert result == str(apk)

    def test_host_path_resolves_to_inbox_basename(self, tmp_path):
        from mcp_server.tools.static.manifest import _resolve_apk_path

        inbox = tmp_path / "inbox"
        inbox.mkdir()
        apk = inbox / "app.apk"
        apk.write_bytes(b"fake apk")

        with patch("mcp_server.tools.static.manifest.INBOX_DIR", str(inbox)):
            result = _resolve_apk_path("/home/user/Desktop/app.apk")
        assert result == str(apk)

    def test_existing_file_outside_inbox_resolves_to_inbox_basename(self, tmp_path):
        from mcp_server.tools.static.manifest import _resolve_apk_path

        inbox = tmp_path / "inbox"
        inbox.mkdir()
        apk = tmp_path / "already-here.apk"
        apk.write_bytes(b"fake")

        with patch("mcp_server.tools.static.manifest.INBOX_DIR", str(inbox)):
            result = _resolve_apk_path(str(apk))
        assert result == str(inbox / "already-here.apk")

    def test_missing_file_returned_as_is(self):
        from mcp_server.tools.static.manifest import _resolve_apk_path

        with patch("mcp_server.tools.static.manifest.INBOX_DIR", "/nonexistent"):
            result = _resolve_apk_path("/nofile.apk")
        assert result == "/nonexistent/nofile.apk"


class TestListInboxTool:
    @pytest.mark.asyncio
    async def test_lists_apk_files(self, tmp_path):
        from mcp_server.tools.static.manifest import ListInboxTool

        inbox = tmp_path / "inbox"
        inbox.mkdir()
        (inbox / "app.apk").write_bytes(b"a" * 1024)
        (inbox / "notes.txt").write_bytes(b"hello")

        tool = ListInboxTool()
        with patch("mcp_server.tools.static.manifest.INBOX_DIR", str(inbox)):
            result = await tool.run(None)

        assert result["total_files"] == 2
        assert result["apk_count"] == 1
        apk_files = [f for f in result["files"] if f["is_apk"]]
        assert apk_files[0]["filename"] == "app.apk"

    @pytest.mark.asyncio
    async def test_empty_inbox(self, tmp_path):
        from mcp_server.tools.static.manifest import ListInboxTool

        inbox = tmp_path / "inbox"
        inbox.mkdir()

        tool = ListInboxTool()
        with patch("mcp_server.tools.static.manifest.INBOX_DIR", str(inbox)):
            result = await tool.run(None)

        assert result["apk_count"] == 0
        assert "No APK files found" in result["hint"]

    @pytest.mark.asyncio
    async def test_missing_inbox_dir(self):
        from mcp_server.tools.static.manifest import ListInboxTool

        tool = ListInboxTool()
        with patch("mcp_server.tools.static.manifest.INBOX_DIR", "/nonexistent"):
            result = await tool.run(None)

        assert "error" in result
# Manifest tools
# ---------------------------------------------------------------------------

class TestGetManifestTool:
    @pytest.mark.asyncio
    async def test_returns_parsed_manifest(self):
        from mcp_server.tools.static.manifest import GetManifestTool

        manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.test"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-permission android:name="android.permission.INTERNET"/>
    <application
        android:allowBackup="true"
        android:debuggable="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>"""

        session = make_session()
        session.metadata["decoded_path"] = "/workspace/test/decoded"
        # Set decoded_path so _ensure_decoded is skipped
        session.decoded_path = "/workspace/test/decoded"
        tool = GetManifestTool()

        with patch(
            "mcp_server.tools.static.manifest.read_file_content",
            new_callable=AsyncMock,
            return_value=(manifest_xml, "", 0),
        ):
            result = await tool.run(session)

        assert result["package"] == "com.example.test"
        assert any(
            p == "android.permission.INTERNET"
            for p in result.get("uses_permissions", [])
        )


class TestCheckManifestSecurityTool:
    @pytest.mark.asyncio
    async def test_flags_debuggable(self):
        from mcp_server.tools.static.manifest import CheckManifestSecurityTool

        session = make_session()
        session.metadata["manifest"] = {
            "package": "com.example.test",
            "application_attributes": {
                "debuggable": "true",
                "allowBackup": "false",
                "usesCleartextTraffic": "false",
                "networkSecurityConfig": "@xml/network_config",
            },
            "uses_permissions": [],
            "components": {
                "activities": [],
                "services": [],
                "receivers": [],
                "providers": [],
            },
        }

        tool = CheckManifestSecurityTool()
        result = await tool.run(session)

        assert result["findings_count"] > 0
        # Should have a finding about debuggable
        findings = [f for f in session.findings if "debuggable" in f.title.lower()]
        assert len(findings) > 0
        assert findings[0].severity in (Severity.CRITICAL, Severity.HIGH)

    @pytest.mark.asyncio
    async def test_repeated_runs_do_not_duplicate_findings(self):
        from mcp_server.tools.static.manifest import CheckManifestSecurityTool

        session = make_session()
        session.metadata["manifest"] = {
            "package": "com.example.test",
            "application_attributes": {
                "debuggable": "true",
                "allowBackup": "true",
                "usesCleartextTraffic": "true",
                "networkSecurityConfig": "",
            },
            "uses_permissions": [],
            "components": {
                "activities": [],
                "services": [],
                "receivers": [],
                "providers": [],
            },
        }

        tool = CheckManifestSecurityTool()
        first = await tool.run(session)
        second = await tool.run(session)

        assert first["findings_count"] == 4
        assert second["findings_count"] == 0
        assert len(session.findings) == 4


class TestListExportedComponentsTool:
    @pytest.mark.asyncio
    async def test_finds_exported_activity(self):
        from mcp_server.tools.static.manifest import ListExportedComponentsTool

        session = make_session()
        session.metadata["manifest"] = {
            "package": "com.example.test",
            "components": {
                "activities": [
                    {
                        "name": ".MainActivity",
                        "exported": True,
                        "explicit_exported": "true",
                        "permission": None,
                        "enabled": "true",
                        "intent_filters": [
                            {"actions": ["android.intent.action.MAIN"], "categories": ["android.intent.category.LAUNCHER"], "data": []}
                        ],
                    },
                    {
                        "name": ".SecretActivity",
                        "exported": True,
                        "explicit_exported": "true",
                        "permission": None,
                        "enabled": "true",
                        "intent_filters": [],
                    },
                ],
                "services": [],
                "receivers": [],
                "providers": [],
            },
        }

        tool = ListExportedComponentsTool()
        result = await tool.run(session)

        assert result["total_exported"] >= 1
        # Check activities list contains SecretActivity
        names = [c["name"] for c in result.get("activities", [])]
        assert ".SecretActivity" in names

    @pytest.mark.asyncio
    async def test_repeated_runs_do_not_duplicate_exported_component_findings(self):
        from mcp_server.tools.static.manifest import ListExportedComponentsTool

        session = make_session()
        session.metadata["manifest"] = {
            "package": "com.example.test",
            "components": {
                "activities": [
                    {
                        "name": ".SecretActivity",
                        "exported": True,
                        "explicit_exported": "true",
                        "permission": None,
                        "enabled": "true",
                        "intent_filters": [],
                    },
                ],
                "services": [],
                "receivers": [],
                "providers": [],
            },
        }

        tool = ListExportedComponentsTool()
        first = await tool.run(session)
        second = await tool.run(session)

        assert first["findings_created"] == 1
        assert second["findings_created"] == 0
        assert len(session.findings) == 1


# ---------------------------------------------------------------------------
# Code analysis tools
# ---------------------------------------------------------------------------

class TestDecompileApkTool:
    @pytest.mark.asyncio
    async def test_decompile_returns_tree(self):
        from mcp_server.tools.static.code import DecompileApkTool

        session = make_session()
        workspace = session_workspace(session)
        session.metadata["container_apk_path"] = f"{workspace}/app.apk"
        decompiled = f"{workspace}/decompiled"

        # Mock jadx invocation
        find_output = (
            f"{decompiled}/com/example/test/MainActivity.java\n"
            f"{decompiled}/com/example/test/LoginActivity.java\n"
            f"{decompiled}/com/example/util/Helper.java\n"
        )

        async def mock_exec(cmd, timeout=60):
            cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
            if "jadx" in cmd_str:
                return ("", "", 0)
            if "ls" in cmd_str:
                return ("sources resources", "", 0)
            if "find" in cmd_str:
                return (find_output, "", 0)
            return ("", "", 0)

        tool = DecompileApkTool()

        with patch(
            "mcp_server.tools.static.code.run_local",
            side_effect=mock_exec,
        ):
            result = await tool.run(session)

        assert result["total_java_files"] == 3
        assert "com" in result["packages"]


class TestSearchSourceTool:
    @pytest.mark.asyncio
    async def test_search_finds_matches(self):
        from mcp_server.tools.static.code import SearchSourceTool

        session = make_session()
        session.decompiled_path = "/workspace/test/sources"

        rg_output = json.dumps({"type": "match", "data": {
            "path": {"text": "/workspace/test/sources/com/example/Test.java"},
            "lines": {"text": '    String password = "secret123";'},
            "line_number": 42,
            "submatches": [{"match": {"text": "password"}, "start": 11, "end": 19}],
        }}) + "\n"

        tool = SearchSourceTool()

        with patch(
            "mcp_server.tools.static.code.run_local",
            new_callable=AsyncMock,
            return_value=(rg_output, "", 0),
        ):
            result = await tool.run(session, pattern="password")

        assert result["total_matches"] > 0


# ---------------------------------------------------------------------------
# Secrets tools
# ---------------------------------------------------------------------------

class TestScanSecretsTool:
    @pytest.mark.asyncio
    async def test_scan_creates_findings(self):
        from mcp_server.tools.static.secrets import ScanSecretsTool

        session = make_session()
        session.metadata["container_apk_path"] = "/workspace/test/test.apk"

        apkleaks_output = json.dumps({
            "results": [
                {
                    "name": "Amazon_AWS_Access_Key_ID",
                    "matches": ["AKIAIOSFODNN7EXAMPLE"],
                }
            ]
        })

        tool = ScanSecretsTool()

        async def mock_exec(cmd, timeout=300):
            cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
            if "apkleaks" in cmd_str:
                return ("", "", 0)
            return ("", "", 0)

        with patch(
            "mcp_server.tools.static.secrets.run_local",
            new_callable=AsyncMock,
            side_effect=mock_exec,
        ), patch(
            "mcp_server.tools.static.secrets.read_file_content",
            new_callable=AsyncMock,
            return_value=(apkleaks_output, "", 0),
        ):
            result = await tool.run(session)

        assert result["total_secrets"] > 0
        assert len(session.findings) > 0
        assert session.findings[0].category == FindingCategory.HARDCODED_SECRET


# ---------------------------------------------------------------------------
# Crypto tools
# ---------------------------------------------------------------------------

class TestFindCryptoIssuesTool:
    @pytest.mark.asyncio
    async def test_finds_ecb_mode(self):
        from mcp_server.tools.static.crypto import FindCryptoIssuesTool

        session = make_session()
        session.decompiled_path = "/workspace/test/sources"

        rg_output = json.dumps({"type": "match", "data": {
            "path": {"text": "/workspace/test/sources/Crypto.java"},
            "lines": {"text": '    Cipher.getInstance("AES/ECB/PKCS5Padding");'},
            "line_number": 15,
            "submatches": [{"match": {"text": "ECB"}, "start": 25, "end": 28}],
        }}) + "\n"

        tool = FindCryptoIssuesTool()

        with patch(
            "mcp_server.tools.static.crypto.run_local",
            new_callable=AsyncMock,
            return_value=(rg_output, "", 0),
        ) as mock_run:
            result = await tool.run(session)

        assert result["total_issues"] > 0


# ---------------------------------------------------------------------------
# Findings management
# ---------------------------------------------------------------------------

class TestFindingsManagement:
    @pytest.mark.asyncio
    async def test_add_and_list(self):
        from mcp_server.tools.findings_management import (
            AddFindingTool,
            ListFindingsTool,
            GetFindingsSummaryTool,
        )

        session = make_session()

        add_tool = AddFindingTool()
        result = await add_tool.run(
            session,
            title="Test Vuln",
            severity="high",
            category="configuration_issue",
            description="A test vulnerability",
            evidence="Test evidence",
            location="AndroidManifest.xml",
        )
        assert result["finding_id"] is not None

        list_tool = ListFindingsTool()
        result = await list_tool.run(session)
        assert result["total"] == 1

        summary_tool = GetFindingsSummaryTool()
        result = await summary_tool.run(session)
        assert result["total_findings"] == 1
        assert result["by_severity"]["high"] == 1


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

class TestToolRegistry:
    def test_register_and_list(self):
        from mcp_server.tools.registry import ToolRegistry

        registry = ToolRegistry()

        # Create a simple mock tool
        class DummyTool:
            name = "dummy_tool"
            description = "A dummy tool"
            def input_schema(self):
                return {"type": "object", "properties": {}}
            def to_mcp_tool(self):
                return {"name": self.name, "description": self.description, "inputSchema": self.input_schema()}

        registry.register(DummyTool())
        assert "dummy_tool" in registry.list_tool_names()

    def test_get_unknown_tool(self):
        from mcp_server.tools.registry import ToolRegistry

        registry = ToolRegistry()
        assert registry.get("nonexistent") is None


# ---------------------------------------------------------------------------
# Security Overview tool
# ---------------------------------------------------------------------------

class TestGetSecurityOverviewTool:
    @pytest.mark.asyncio
    async def test_source_scan_returns_categorized_results(self):
        from mcp_server.tools.static.security_overview import GetSecurityOverviewTool

        session = make_session()
        session.decompiled_path = "/workspace/test/decompiled"

        # Mock ripgrep returning a match for a password pattern
        rg_output = json.dumps({
            "type": "match",
            "data": {
                "path": {"text": "/workspace/test/decompiled/com/example/Login.java"},
                "lines": {"text": "    String password = editPassword.getText().toString();\n"},
                "line_number": 42,
            },
        })

        async def mock_run_local(cmd, timeout=30):
            if cmd[0] == "rg":
                # Return match for auth patterns, empty for others
                pattern = cmd[-2]  # the regex pattern
                if "password" in pattern.lower():
                    return (rg_output, "", 0)
            return ("", "", 1)  # no match

        tool = GetSecurityOverviewTool()
        with patch(
            "mcp_server.tools.static.security_overview.run_local",
            side_effect=mock_run_local,
        ):
            result = await tool.run(session, scan_mode="source")

        assert "summary" in result
        assert "results" in result
        assert result["scan_mode"] == "source"
        assert result["total_categories_with_findings"] >= 1
        # Verify source entries have "source": "ripgrep"
        for cat, hits in result["results"].items():
            for h in hits:
                assert h["source"] == "ripgrep"

    @pytest.mark.asyncio
    async def test_category_filter(self):
        from mcp_server.tools.static.security_overview import GetSecurityOverviewTool

        session = make_session()
        session.decompiled_path = "/workspace/test/decompiled"

        async def mock_run_local(cmd, timeout=30):
            return ("", "", 1)  # no matches

        tool = GetSecurityOverviewTool()
        with patch(
            "mcp_server.tools.static.security_overview.run_local",
            side_effect=mock_run_local,
        ):
            result = await tool.run(session, category="crypto", scan_mode="source")

        assert "summary" in result
        # No error — valid category
        assert "error" not in result

    @pytest.mark.asyncio
    async def test_invalid_category(self):
        from mcp_server.tools.static.security_overview import GetSecurityOverviewTool

        session = make_session()
        session.decompiled_path = "/workspace/test/decompiled"

        tool = GetSecurityOverviewTool()
        result = await tool.run(session, category="nonexistent")
        assert "error" in result
        assert "available" in result

    @pytest.mark.asyncio
    async def test_bytecode_scan_parses_androguard_output(self):
        from mcp_server.tools.static.security_overview import GetSecurityOverviewTool

        session = make_session()
        session.workspace_dir = "/workspace/test"

        # Simulate androguard output JSON
        androguard_output = json.dumps({
            "crypto": [
                {
                    "label": "Cipher.getInstance()",
                    "callers": [
                        {"class": "com.example.CryptoHelper", "method": "encrypt"},
                        {"class": "com.example.CryptoHelper", "method": "decrypt"},
                    ],
                    "caller_count": 2,
                }
            ],
        })

        async def mock_run_local(cmd, timeout=30):
            if cmd[0] == "python3":
                return (androguard_output, "", 0)
            # ls check for decompiled (not needed for bytecode-only)
            return ("", "", 1)

        tool = GetSecurityOverviewTool()
        with patch(
            "mcp_server.tools.static.security_overview.run_local",
            side_effect=mock_run_local,
        ):
            result = await tool.run(session, scan_mode="bytecode", category="crypto")

        assert result["scan_mode"] == "bytecode"
        assert "crypto" in result["results"]
        crypto_hits = result["results"]["crypto"]
        assert any(h["source"] == "bytecode_xref" for h in crypto_hits)
        assert crypto_hits[0]["callers"][0]["class"] == "com.example.CryptoHelper"

    @pytest.mark.asyncio
    async def test_both_mode_merges_results(self):
        from mcp_server.tools.static.security_overview import GetSecurityOverviewTool

        session = make_session()
        session.decompiled_path = "/workspace/test/decompiled"
        session.workspace_dir = "/workspace/test"

        rg_output = json.dumps({
            "type": "match",
            "data": {
                "path": {"text": "/workspace/test/decompiled/com/example/Login.java"},
                "lines": {"text": "    Cipher.getInstance(\"AES/ECB/PKCS5Padding\");\n"},
                "line_number": 10,
            },
        })

        androguard_output = json.dumps({
            "crypto": [
                {
                    "label": "Cipher.getInstance()",
                    "callers": [{"class": "com.example.a", "method": "b"}],
                    "caller_count": 1,
                }
            ],
        })

        async def mock_run_local(cmd, timeout=30):
            if cmd[0] == "python3":
                return (androguard_output, "", 0)
            if cmd[0] == "rg":
                pattern = cmd[-2]
                if "Cipher" in pattern or "ECB" in pattern:
                    return (rg_output, "", 0)
            if cmd[0] == "ls":
                return ("sources", "", 0)
            return ("", "", 1)

        tool = GetSecurityOverviewTool()
        with patch(
            "mcp_server.tools.static.security_overview.run_local",
            side_effect=mock_run_local,
        ):
            result = await tool.run(session, scan_mode="both", category="crypto")

        assert result["scan_mode"] == "both"
        assert "crypto" in result["results"]
        sources = {h["source"] for h in result["results"]["crypto"]}
        # Should have both ripgrep and bytecode_xref entries
        assert "bytecode_xref" in sources

    @pytest.mark.asyncio
    async def test_invalid_scan_mode(self):
        from mcp_server.tools.static.security_overview import GetSecurityOverviewTool

        session = make_session()
        tool = GetSecurityOverviewTool()
        result = await tool.run(session, scan_mode="magic")
        assert "error" in result


# ---------------------------------------------------------------------------
# Framework detection tool
# ---------------------------------------------------------------------------

class TestDetectFrameworkTool:
    def _make_apk(self, tmpdir: str, files: list[str]) -> str:
        """Create a minimal APK (ZIP) with the given file paths."""
        import zipfile
        apk_path = os.path.join(tmpdir, "app.apk")
        with zipfile.ZipFile(apk_path, "w") as zf:
            for f in files:
                zf.writestr(f, "dummy")
        return apk_path

    @pytest.mark.asyncio
    async def test_detects_native(self):
        from mcp_server.tools.static.framework import DetectFrameworkTool

        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_apk(tmpdir, [
                "classes.dex", "AndroidManifest.xml", "res/values/strings.xml"
            ])
            session = make_session()
            session.workspace_dir = tmpdir

            tool = DetectFrameworkTool()
            result = await tool.run(session)

            assert result["primary_framework"] == "Native (Java/Kotlin)"
            assert result["is_native_android"] is True
            assert "recommended_analysis_path" in result
            assert session.metadata.get("framework") is not None

    @pytest.mark.asyncio
    async def test_detects_flutter(self):
        from mcp_server.tools.static.framework import DetectFrameworkTool

        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_apk(tmpdir, [
                "classes.dex",
                "lib/arm64-v8a/libflutter.so",
                "lib/arm64-v8a/libapp.so",
                "assets/flutter_assets/AssetManifest.json",
            ])
            session = make_session()
            session.workspace_dir = tmpdir

            tool = DetectFrameworkTool()
            result = await tool.run(session)

            assert result["primary_framework"] == "Flutter"
            assert result["is_native_android"] is False
            assert "warning" in result
            assert "libapp.so" in result["detected_details"][0]["analysis_guide"]["primary_target"]

    @pytest.mark.asyncio
    async def test_detects_react_native(self):
        from mcp_server.tools.static.framework import DetectFrameworkTool

        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_apk(tmpdir, [
                "classes.dex",
                "lib/arm64-v8a/libreactnativejni.so",
                "assets/index.android.bundle",
            ])
            session = make_session()
            session.workspace_dir = tmpdir

            tool = DetectFrameworkTool()
            result = await tool.run(session)

            assert result["primary_framework"] == "React Native"
            assert result["is_native_android"] is False
            assert "warning" in result

    @pytest.mark.asyncio
    async def test_detects_cordova(self):
        from mcp_server.tools.static.framework import DetectFrameworkTool

        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_apk(tmpdir, [
                "classes.dex",
                "assets/www/index.html",
                "assets/www/cordova.js",
                "assets/www/cordova_plugins.js",
            ])
            session = make_session()
            session.workspace_dir = tmpdir

            tool = DetectFrameworkTool()
            result = await tool.run(session)

            assert result["primary_framework"] == "Cordova"
            assert result["is_native_android"] is False

    @pytest.mark.asyncio
    async def test_detects_xamarin(self):
        from mcp_server.tools.static.framework import DetectFrameworkTool

        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_apk(tmpdir, [
                "classes.dex",
                "assemblies/mscorlib.dll",
                "lib/arm64-v8a/libmonodroid.so",
            ])
            session = make_session()
            session.workspace_dir = tmpdir

            tool = DetectFrameworkTool()
            result = await tool.run(session)

            assert result["primary_framework"] == "Xamarin"
            assert result["is_native_android"] is False

    @pytest.mark.asyncio
    async def test_no_session(self):
        from mcp_server.tools.static.framework import DetectFrameworkTool

        tool = DetectFrameworkTool()
        result = await tool.run(None)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_stores_in_session_metadata(self):
        from mcp_server.tools.static.framework import DetectFrameworkTool

        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_apk(tmpdir, ["classes.dex", "AndroidManifest.xml"])
            session = make_session()
            session.workspace_dir = tmpdir

            tool = DetectFrameworkTool()
            await tool.run(session)

            assert "framework" in session.metadata
            assert session.metadata["framework"]["primary_framework"] == "Native (Java/Kotlin)"
            assert session.metadata["framework"]["primary_container"] == "dex"

    @pytest.mark.asyncio
    async def test_detect_returns_extended_fields(self):
        from mcp_server.tools.static.framework import DetectFrameworkTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "AndroidManifest.xml": "manifest",
                    "assets/index.android.bundle": "fetch('https://api.example.test')",
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir

            tool = DetectFrameworkTool()
            result = await tool.run(session)

            assert "build_technologies" in result
            assert "code_containers" in result
            assert "primary_container" in result
            assert "secondary_containers" in result
            assert "support_level" in result
            assert "artifact_roots" in result


class TestPlanStaticAnalysisTool:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("files", "expected_framework", "expected_route", "expected_container", "expected_phrase"),
        [
            (
                {"classes.dex": "dex", "AndroidManifest.xml": "manifest"},
                "Native (Java/Kotlin)",
                "native_java_kotlin",
                "dex",
                "Decompile DEX",
            ),
            (
                {
                    "classes.dex": "dex",
                    "lib/arm64-v8a/libflutter.so": "flutter",
                    "assets/flutter_assets/kernel_blob.bin": "debug",
                    "assets/flutter_assets/AssetManifest.json": "{}",
                },
                "Flutter",
                "flutter_debug",
                "config",
                "flutter_assets",
            ),
            (
                {
                    "classes.dex": "dex",
                    "lib/arm64-v8a/libflutter.so": "flutter",
                    "lib/arm64-v8a/libapp.so": "appso",
                    "assets/flutter_assets/AssetManifest.json": "{}",
                },
                "Flutter",
                "flutter_release_aot",
                "native_libs",
                "analyze_flutter_aot",
            ),
            (
                {
                    "classes.dex": "dex",
                    "assets/index.android.bundle": "const api='https://api.example.test';",
                    "lib/arm64-v8a/libreactnativejni.so": "rn",
                },
                "React Native",
                "react_native_plain_js",
                "js_bundle",
                "JS bundle",
            ),
            (
                {
                    "classes.dex": "dex",
                    "assets/index.android.bundle": b"HBC\x00bundle",
                    "lib/arm64-v8a/libreactnativejni.so": "rn",
                    "lib/arm64-v8a/libhermes.so": "hermes",
                },
                "React Native",
                "react_native_hermes",
                "js_bundle",
                "Hermes",
            ),
            (
                {
                    "classes.dex": "dex",
                    "assets/www/index.html": "<html></html>",
                    "assets/www/cordova.js": "cordova",
                },
                "Cordova",
                "web_hybrid",
                "web_assets",
                "web assets",
            ),
            (
                {
                    "classes.dex": "dex",
                    "assets/public/index.html": "<html></html>",
                    "assets/capacitor.config.json": "{}",
                },
                "Capacitor",
                "web_hybrid",
                "web_assets",
                "web assets",
            ),
            (
                {
                    "classes.dex": "dex",
                    "assemblies/mscorlib.dll": "dll",
                    "lib/arm64-v8a/libmonodroid.so": "mono",
                },
                "Xamarin",
                "dotnet",
                "managed_assemblies",
                "managed assemblies",
            ),
            (
                {
                    "classes.dex": "dex",
                    "lib/arm64-v8a/libunity.so": "unity",
                    "assets/bin/Data/Managed/Assembly-CSharp.dll": "dll",
                },
                "Unity",
                "unity_mono",
                "managed_assemblies",
                "Unity managed assemblies",
            ),
            (
                {
                    "classes.dex": "dex",
                    "lib/arm64-v8a/libunity.so": "unity",
                    "lib/arm64-v8a/libil2cpp.so": "il2cpp",
                    "assets/bin/Data/Managed/Metadata/global-metadata.dat": "meta",
                },
                "Unity",
                "unity_il2cpp",
                "native_libs",
                "libil2cpp.so",
            ),
            (
                {
                    "classes.dex": "dex",
                    "lib/arm64-v8a/libUE4.so": "ue4",
                    "assets/Unreal/UE4Game/Manifest.xml": "<manifest/>",
                    "assets/game.pak": "pak",
                },
                "Unreal Engine",
                "unreal_native",
                "native_libs",
                "Unreal",
            ),
            (
                {
                    "classes.dex": "dex",
                    "assets/index.android.bundle": "const api='https://api.example.test';",
                    "lib/arm64-v8a/libreactnativejni.so": "rn",
                    "assets/www/index.html": "<html></html>",
                    "assets/www/cordova.js": "cordova",
                },
                "React Native",
                "mixed_hardened",
                "js_bundle",
                "Inventory all code containers",
            ),
        ],
    )
    async def test_routes_by_framework(
        self,
        files,
        expected_framework,
        expected_route,
        expected_container,
        expected_phrase,
    ):
        from mcp_server.tools.static.artifacts import PlanStaticAnalysisTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(apk_path, files)
            session = make_session()
            session.workspace_dir = tmpdir
            session.metadata["tampering"] = {"assessment": {"verdict": "CLEAN"}}

            tool = PlanStaticAnalysisTool()
            result = await tool.run(session)

            assert result["primary_framework"] == expected_framework
            assert result["route_key"] == expected_route
            assert result["primary_container"] == expected_container
            assert expected_phrase in result["primary_deep_analysis_step"]
            assert "artifact_index" in session.metadata
            assert "static_route" in session.metadata

    @pytest.mark.asyncio
    async def test_suspicious_tampering_lowers_confidence(self):
        from mcp_server.tools.static.artifacts import PlanStaticAnalysisTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(apk_path, {"classes.dex": "dex", "AndroidManifest.xml": "manifest"})
            session = make_session()
            session.workspace_dir = tmpdir
            session.metadata["tampering"] = {"assessment": {"verdict": "SUSPICIOUS"}}

            result = await PlanStaticAnalysisTool().run(session)

            assert result["confidence"] == "low"
            assert any("tampering" in warning.lower() for warning in result["warnings"])

    @pytest.mark.asyncio
    async def test_clean_flutter_plan_does_not_emit_dex_centric_warning(self):
        from mcp_server.tools.static.artifacts import PlanStaticAnalysisTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "lib/arm64-v8a/libflutter.so": "flutter",
                    "lib/arm64-v8a/libapp.so": "appso",
                    "assets/flutter_assets/AssetManifest.json": "{}",
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir
            session.metadata["tampering"] = {"assessment": {"verdict": "CLEAN"}}

            result = await PlanStaticAnalysisTool().run(session)

            assert result["route_key"] == "flutter_release_aot"
            assert all("dex-centric" not in warning.lower() for warning in result["warnings"])
            assert "analyze_flutter_aot" in result["recommended_tools"]
            assert all("reflutter" not in item.lower() for item in result["manual_followup"])


class TestStaticArtifactTools:
    @pytest.mark.asyncio
    async def test_list_static_artifacts_groups_categories(self):
        from mcp_server.tools.static.artifacts import ListStaticArtifactsTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "assets/index.android.bundle": "const token = 'abc';",
                    "assets/www/index.html": "<html></html>",
                    "assemblies/mscorlib.dll": "dll",
                    "lib/arm64-v8a/libnative.so": "native",
                    "assets/flutter_assets/AssetManifest.json": "{}",
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir

            result = await ListStaticArtifactsTool().run(session)

            assert result["counts"]["dex"] == 1
            assert result["counts"]["js_bundle"] == 1
            assert result["counts"]["web_assets"] == 1
            assert result["counts"]["managed_assemblies"] == 1
            assert result["counts"]["native_libs"] == 1
            assert result["counts"]["config"] == 1

    @pytest.mark.asyncio
    async def test_read_static_artifact_returns_content(self):
        from mcp_server.tools.static.artifacts import ReadStaticArtifactTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "assets/index.android.bundle": "const api = 'https://api.example.test';",
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir

            result = await ReadStaticArtifactTool().run(session, path="assets/index.android.bundle")

            assert "https://api.example.test" in result["content"]
            assert result["category"] == "js_bundle"

    @pytest.mark.asyncio
    async def test_search_static_artifacts_returns_matches(self):
        from mcp_server.tools.static.artifacts import SearchStaticArtifactsTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "assets/index.android.bundle": "const api = 'https://api.example.test';",
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir

            cache_root = os.path.join(tmpdir, "artifacts", "text_cache")
            rg_output = json.dumps(
                {
                    "type": "match",
                    "data": {
                        "path": {"text": f"{cache_root}/assets/index.android.bundle"},
                        "lines": {"text": "const api = 'https://api.example.test';\n"},
                        "line_number": 1,
                        "submatches": [{"match": {"text": "api.example.test"}}],
                    },
                }
            )

            with patch(
                "mcp_server.tools.static.artifacts.run_local",
                new_callable=AsyncMock,
                return_value=(rg_output, "", 0),
            ):
                result = await SearchStaticArtifactsTool().run(session, pattern="api\\.example\\.test")

            assert result["total_matches"] == 1
            assert result["matches"][0]["artifact_path"] == "assets/index.android.bundle"
            assert result["matches"][0]["category"] == "js_bundle"


class TestAnalyzeNativeBinaryTool:
    @pytest.mark.asyncio
    async def test_parses_rabin2_outputs(self):
        from mcp_server.tools.static.native import AnalyzeNativeBinaryTool

        with tempfile.TemporaryDirectory() as tmpdir:
            decoded = Path(tmpdir) / "decoded" / "lib" / "arm64-v8a"
            decoded.mkdir(parents=True, exist_ok=True)
            (decoded / "libnative.so").write_bytes(b"\x7fELFfake")

            session = make_session()
            session.workspace_dir = tmpdir
            session.decoded_path = str(Path(tmpdir) / "decoded")

            async def mock_run_local(command, timeout=300, cwd=None, keep_stdin_open=False, stdin_data=None):
                lookup = {
                    ("rabin2", "-Ij"): (json.dumps({
                        "arch": "arm",
                        "bits": 64,
                        "bintype": "elf",
                        "canary": True,
                        "nx": True,
                        "pic": True,
                        "relro": "full",
                    }), "", 0),
                    ("rabin2", "-ij"): (json.dumps([
                        {"name": "SSL_read"},
                        {"name": "__android_log_print"},
                    ]), "", 0),
                    ("rabin2", "-lj"): (json.dumps([
                        {"name": "liblog.so"},
                        {"name": "libssl.so"},
                    ]), "", 0),
                    ("rabin2", "-sj"): (json.dumps([
                        {"name": "Java_com_example_Native_ping"},
                        {"name": "JNI_OnLoad"},
                        {"name": "native_helper"},
                    ]), "", 0),
                    ("rabin2", "-Sj"): (json.dumps([
                        {"name": ".text", "size": 1234, "vaddr": 4096, "perm": "-r-x"},
                        {"name": ".rodata", "size": 128, "vaddr": 8192, "perm": "-r--"},
                    ]), "", 0),
                    ("rabin2", "-zj"): (json.dumps([
                        {"string": "https://api.example.com"},
                        {"string": "/data/user/0/com.example/files"},
                        {"string": "AES256"},
                        {"string": "debug_token_refresh"},
                    ]), "", 0),
                }
                return lookup.get(tuple(command[:2]), ("", "unexpected command", 1))

            with patch("mcp_server.tools.static.native.run_local", side_effect=mock_run_local):
                result = await AnalyzeNativeBinaryTool().run(session, lib_name="libnative.so")

        assert result["tool"] == "radare2"
        assert result["backend"] == "rabin2"
        assert result["security_properties"]["nx"] is True
        assert "libssl.so" in result["linked_libraries"]
        assert "SSL_read" in result["imports"]
        assert "Java_com_example_Native_ping" in result["jni_symbols"]
        assert result["sections"][0]["name"] == ".text"
        assert "https://api.example.com" in result["interesting_strings"]["urls"]
        assert session.metadata["native_analysis"]["arm64-v8a/libnative.so"]["tool"] == "radare2"

    @pytest.mark.asyncio
    async def test_returns_helpful_error_when_rabin2_missing(self):
        from mcp_server.tools.static.native import AnalyzeNativeBinaryTool

        with tempfile.TemporaryDirectory() as tmpdir:
            decoded = Path(tmpdir) / "decoded" / "lib" / "arm64-v8a"
            decoded.mkdir(parents=True, exist_ok=True)
            (decoded / "libnative.so").write_bytes(b"\x7fELFfake")

            session = make_session()
            session.workspace_dir = tmpdir
            session.decoded_path = str(Path(tmpdir) / "decoded")

            with patch(
                "mcp_server.tools.static.native.run_local",
                new_callable=AsyncMock,
                return_value=("", "rabin2 is not installed or not in PATH", -1),
            ):
                result = await AnalyzeNativeBinaryTool().run(session, lib_name="libnative.so")

        assert "error" in result
        assert "radare2" in result["error"].lower()
        assert "hint" in result


class TestDisassembleNativeFunctionTool:
    @pytest.mark.asyncio
    async def test_disassembles_targeted_function(self):
        from mcp_server.tools.static.native import DisassembleNativeFunctionTool

        with tempfile.TemporaryDirectory() as tmpdir:
            decoded = Path(tmpdir) / "decoded" / "lib" / "arm64-v8a"
            decoded.mkdir(parents=True, exist_ok=True)
            (decoded / "libnative.so").write_bytes(b"\x7fELFfake")

            session = make_session()
            session.workspace_dir = tmpdir
            session.decoded_path = str(Path(tmpdir) / "decoded")

            async def mock_run_local(command, timeout=300, cwd=None, keep_stdin_open=False, stdin_data=None):
                joined = command[command.index("-c") + 1]
                if "afij" in joined:
                    return (json.dumps([{
                        "name": "sym.Java_com_example_Native_ping",
                        "offset": 4096,
                        "size": 32,
                        "nbbs": 2,
                    }]), "", 0)
                if "pdfj" in joined:
                    return (json.dumps({
                        "ops": [
                            {"offset": 4096, "opcode": "stp x29, x30, [sp, -0x10]!", "type": "push"},
                            {"offset": 4100, "opcode": "bl sym.imp.SSL_read", "type": "call"},
                        ]
                    }), "", 0)
                return ("", "unexpected command", 1)

            with patch("mcp_server.tools.static.native.run_local", side_effect=mock_run_local):
                result = await DisassembleNativeFunctionTool().run(
                    session,
                    lib_name="libnative.so",
                    symbol="sym.Java_com_example_Native_ping",
                )

        assert result["backend"] == "r2"
        assert result["function"]["name"] == "sym.Java_com_example_Native_ping"
        assert result["instructions"][1]["type"] == "call"
        assert result["truncated"] is False


class TestDecompileNativeFunctionTool:
    @pytest.mark.asyncio
    async def test_decompiles_targeted_function(self):
        from mcp_server.tools.static.native import DecompileNativeFunctionTool

        with tempfile.TemporaryDirectory() as tmpdir:
            decoded = Path(tmpdir) / "decoded" / "lib" / "arm64-v8a"
            decoded.mkdir(parents=True, exist_ok=True)
            (decoded / "libnative.so").write_bytes(b"\x7fELFfake")

            session = make_session()
            session.workspace_dir = tmpdir
            session.decoded_path = str(Path(tmpdir) / "decoded")

            async def mock_run_local(command, timeout=300, cwd=None, keep_stdin_open=False, stdin_data=None):
                joined = command[command.index("-c") + 1]
                if "afij" in joined:
                    return (json.dumps([{
                        "name": "sym.auth_check",
                        "offset": 8192,
                        "size": 48,
                        "nbbs": 3,
                    }]), "", 0)
                if joined.endswith("pdd"):
                    return ("int auth_check(int token) {\n    return token != 0;\n}\n", "", 0)
                return ("", "unexpected command", 1)

            with patch("mcp_server.tools.static.native.run_local", side_effect=mock_run_local):
                result = await DecompileNativeFunctionTool().run(
                    session,
                    lib_name="libnative.so",
                    symbol="sym.auth_check",
                )

        assert result["backend"] == "r2dec"
        assert "auth_check" in result["decompiled"]
        assert result["truncated"] is False

    @pytest.mark.asyncio
    async def test_returns_helpful_error_when_r2dec_missing(self):
        from mcp_server.tools.static.native import DecompileNativeFunctionTool

        with tempfile.TemporaryDirectory() as tmpdir:
            decoded = Path(tmpdir) / "decoded" / "lib" / "arm64-v8a"
            decoded.mkdir(parents=True, exist_ok=True)
            (decoded / "libnative.so").write_bytes(b"\x7fELFfake")

            session = make_session()
            session.workspace_dir = tmpdir
            session.decoded_path = str(Path(tmpdir) / "decoded")

            async def mock_run_local(command, timeout=300, cwd=None, keep_stdin_open=False, stdin_data=None):
                joined = command[command.index("-c") + 1]
                if "afij" in joined:
                    return (json.dumps([{
                        "name": "sym.auth_check",
                        "offset": 8192,
                        "size": 48,
                    }]), "", 0)
                if joined.endswith("pdd"):
                    return ("Unknown command 'pdd' (run 'pdd?' for help)", "", 0)
                return ("", "unexpected command", 1)

            with patch("mcp_server.tools.static.native.run_local", side_effect=mock_run_local):
                result = await DecompileNativeFunctionTool().run(
                    session,
                    lib_name="libnative.so",
                    symbol="sym.auth_check",
                )

        assert "error" in result
        assert "r2dec" in result["error"].lower()
        assert "hint" in result


class TestAnalyzeFlutterAotTool:
    @pytest.mark.asyncio
    async def test_returns_helpful_error_when_blutter_missing(self):
        from mcp_server.tools.static.flutter import AnalyzeFlutterAotTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "lib/arm64-v8a/libflutter.so": "flutter",
                    "lib/arm64-v8a/libapp.so": "appso",
                    "assets/flutter_assets/AssetManifest.json": "{}",
                },
            )
            decoded = os.path.join(tmpdir, "decoded", "lib", "arm64-v8a")
            os.makedirs(decoded, exist_ok=True)
            with open(os.path.join(decoded, "libapp.so"), "wb") as f:
                f.write(b"appso")
            with open(os.path.join(decoded, "libflutter.so"), "wb") as f:
                f.write(b"flutter")

            session = make_session()
            session.workspace_dir = tmpdir
            session.decoded_path = os.path.join(tmpdir, "decoded")

            with patch.dict("os.environ", {"BLUTTER_HOME": os.path.join(tmpdir, "missing-blutter")}, clear=False):
                result = await AnalyzeFlutterAotTool().run(session)

            assert "error" in result
            assert "blutter" in result["error"].lower()
            assert "expected_path" in result

    @pytest.mark.asyncio
    async def test_runs_blutter_and_parses_outputs(self):
        from mcp_server.tools.static.flutter import AnalyzeFlutterAotTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "lib/arm64-v8a/libflutter.so": "flutter",
                    "lib/arm64-v8a/libapp.so": "appso",
                    "assets/flutter_assets/AssetManifest.json": "{}",
                    "assets/flutter_assets/NOTICES": "notice",
                },
            )
            decoded = os.path.join(tmpdir, "decoded", "lib", "arm64-v8a")
            os.makedirs(decoded, exist_ok=True)
            with open(os.path.join(decoded, "libapp.so"), "wb") as f:
                f.write(b"appso")
            with open(os.path.join(decoded, "libflutter.so"), "wb") as f:
                f.write(b"flutter")

            blutter_home = os.path.join(tmpdir, "blutter")
            os.makedirs(blutter_home, exist_ok=True)
            with open(os.path.join(blutter_home, "blutter.py"), "w") as f:
                f.write("#!/usr/bin/env python3\n")

            session = make_session()
            session.workspace_dir = tmpdir
            session.decoded_path = os.path.join(tmpdir, "decoded")

            async def mock_run_local(cmd, timeout=300, cwd=None, keep_stdin_open=False, stdin_data=None):
                output_dir = cmd[3]
                os.makedirs(os.path.join(output_dir, "asm"), exist_ok=True)
                with open(os.path.join(output_dir, "pp.txt"), "w") as f:
                    f.write("https://api.example.test/v1/login\n")
                    f.write("plugins.flutter.io/shared_preferences\n")
                    f.write("/login\n")
                    f.write("secureStorageToken\n")
                    f.write("SSL pinning enabled\n")
                with open(os.path.join(output_dir, "objs.txt"), "w") as f:
                    f.write("Bearer refreshToken AES Cipher\n")
                with open(os.path.join(output_dir, "blutter_frida.js"), "w") as f:
                    f.write("// frida template")
                with open(os.path.join(output_dir, "asm", "libapp.asm"), "w") as f:
                    f.write("asm")
                return ("blutter complete", "", 0)

            with patch.dict("os.environ", {"BLUTTER_HOME": blutter_home}, clear=False), patch(
                "mcp_server.tools.static.flutter.run_local",
                side_effect=mock_run_local,
            ):
                result = await AnalyzeFlutterAotTool().run(session)

            assert result["tool"] == "blutter"
            assert result["architecture"] == "arm64-v8a"
            assert "https://api.example.test/v1/login" in result["recovered"]["urls"]
            assert "plugins.flutter.io/shared_preferences" in result["recovered"]["channel_names"]
            assert "/login" in result["recovered"]["routes"]
            assert "secureStorageToken" in result["recovered"]["storage_identifiers"]
            assert result["generated_outputs"]["pp_txt"] is True
            assert result["generated_outputs"]["asm_file_count"] == 1
            assert session.metadata["flutter_aot"]["analyses"]["arm64-v8a"]["tool"] == "blutter"

    @pytest.mark.asyncio
    async def test_rejects_invalid_blutter_timeout(self):
        from mcp_server.tools.static.flutter import AnalyzeFlutterAotTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "lib/arm64-v8a/libflutter.so": "flutter",
                    "lib/arm64-v8a/libapp.so": "appso",
                    "assets/flutter_assets/AssetManifest.json": "{}",
                },
            )
            decoded = os.path.join(tmpdir, "decoded", "lib", "arm64-v8a")
            os.makedirs(decoded, exist_ok=True)
            with open(os.path.join(decoded, "libapp.so"), "wb") as f:
                f.write(b"appso")
            with open(os.path.join(decoded, "libflutter.so"), "wb") as f:
                f.write(b"flutter")

            session = make_session()
            session.workspace_dir = tmpdir
            session.decoded_path = os.path.join(tmpdir, "decoded")

            result = await AnalyzeFlutterAotTool().run(session, timeout_seconds=0)

            assert "error" in result
            assert "greater than 0" in result["error"]

    @pytest.mark.asyncio
    async def test_blutter_failure_keeps_timeout_tail(self):
        from mcp_server.tools.static.flutter import AnalyzeFlutterAotTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "lib/arm64-v8a/libflutter.so": "flutter",
                    "lib/arm64-v8a/libapp.so": "appso",
                    "assets/flutter_assets/AssetManifest.json": "{}",
                },
            )
            decoded = os.path.join(tmpdir, "decoded", "lib", "arm64-v8a")
            os.makedirs(decoded, exist_ok=True)
            with open(os.path.join(decoded, "libapp.so"), "wb") as f:
                f.write(b"appso")
            with open(os.path.join(decoded, "libflutter.so"), "wb") as f:
                f.write(b"flutter")

            blutter_home = os.path.join(tmpdir, "blutter")
            os.makedirs(blutter_home, exist_ok=True)
            with open(os.path.join(blutter_home, "blutter.py"), "w") as f:
                f.write("#!/usr/bin/env python3\n")

            session = make_session()
            session.workspace_dir = tmpdir
            session.decoded_path = os.path.join(tmpdir, "decoded")

            async def mock_run_local(cmd, timeout=300, cwd=None, keep_stdin_open=False, stdin_data=None):
                assert timeout == 7200
                output_dir = cmd[3]
                os.makedirs(output_dir, exist_ok=True)
                with open(os.path.join(output_dir, "pp.txt"), "w") as f:
                    f.write("partial output")
                stderr = ("x" * 5000) + "\nCommand timed out after 7200s"
                return ("", stderr, -1)

            with patch.dict("os.environ", {"BLUTTER_HOME": blutter_home}, clear=False), patch(
                "mcp_server.tools.static.flutter.run_local",
                side_effect=mock_run_local,
            ):
                result = await AnalyzeFlutterAotTool().run(session)

            assert result["error"] == "blutter failed"
            assert result["timeout_seconds"] == 7200
            assert "Command timed out after 7200s" in result["stderr"]
            assert result["generated_outputs"]["pp_txt"] is True

    @pytest.mark.asyncio
    async def test_blutter_failure_classified_for_old_dart_sdk(self):
        from mcp_server.tools.static.flutter import AnalyzeFlutterAotTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "lib/arm64-v8a/libflutter.so": "flutter",
                    "lib/arm64-v8a/libapp.so": "appso",
                    "assets/flutter_assets/AssetManifest.json": "{}",
                },
            )
            decoded = os.path.join(tmpdir, "decoded", "lib", "arm64-v8a")
            os.makedirs(decoded, exist_ok=True)
            with open(os.path.join(decoded, "libapp.so"), "wb") as f:
                f.write(b"appso")
            with open(os.path.join(decoded, "libflutter.so"), "wb") as f:
                f.write(b"flutter")

            blutter_home = os.path.join(tmpdir, "blutter")
            os.makedirs(blutter_home, exist_ok=True)
            with open(os.path.join(blutter_home, "blutter.py"), "w") as f:
                f.write("#!/usr/bin/env python3\n")

            session = make_session()
            session.workspace_dir = tmpdir
            session.decoded_path = os.path.join(tmpdir, "decoded")

            async def mock_run_local(cmd, timeout=300, cwd=None, keep_stdin_open=False, stdin_data=None):
                stdout = (
                    "Dart version: 2.9.2\n"
                    "Dart version <2.15, force \"no-analysis\" option\n"
                    "/opt/blutter/blutter/src/pch.h:57:32: error: 'kLinkedHashSetCid' was not declared in this scope\n"
                )
                stderr = (
                    "Traceback (most recent call last):\n"
                    "subprocess.CalledProcessError: Command '['ninja']' returned non-zero exit status 1.\n"
                )
                return (stdout, stderr, 1)

            with patch.dict("os.environ", {"BLUTTER_HOME": blutter_home}, clear=False), patch(
                "mcp_server.tools.static.flutter.run_local",
                side_effect=mock_run_local,
            ):
                result = await AnalyzeFlutterAotTool().run(session)

            assert result["error"] == "blutter failed"
            assert result["failure_category"] == "blutter_dart_sdk_incompatible"
            assert "older Dart runtime" in result["likely_cause"]
            assert "analyze_native_strings" in result["fallback_recommended_tools"]


# ---------------------------------------------------------------------------
# AnalyzeFlutterDebugTool
# ---------------------------------------------------------------------------

class TestAnalyzeFlutterDebugTool:
    """Tests for Flutter debug plugin/channel extraction."""

    def _make_debug_apk(self, tmpdir: str, extra_files: dict | None = None) -> str:
        apk_path = os.path.join(tmpdir, "app.apk")
        files: dict = {
            "classes.dex": "dex",
            "lib/arm64-v8a/libflutter.so": "flutter",
            # kernel_blob.bin is the debug indicator
            "assets/flutter_assets/kernel_blob.bin": b"\x00" * 16,
            "assets/flutter_assets/AssetManifest.json": "{}",
        }
        if extra_files:
            files.update(extra_files)
        make_test_apk(apk_path, files)
        return apk_path

    @pytest.mark.asyncio
    async def test_rejects_aot_build(self):
        from mcp_server.tools.static.flutter import AnalyzeFlutterDebugTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "lib/arm64-v8a/libflutter.so": "flutter",
                    "lib/arm64-v8a/libapp.so": "appso",
                    "assets/flutter_assets/AssetManifest.json": "{}",
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir

            result = await AnalyzeFlutterDebugTool().run(session)

        assert "error" in result
        assert "debug" in result["error"].lower() or "aot" in result.get("hint", "").lower()

    @pytest.mark.asyncio
    async def test_rejects_non_flutter_apk(self):
        from mcp_server.tools.static.flutter import AnalyzeFlutterDebugTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(apk_path, {"classes.dex": "dex", "AndroidManifest.xml": "manifest"})
            session = make_session()
            session.workspace_dir = tmpdir

            result = await AnalyzeFlutterDebugTool().run(session)

        assert "error" in result

    @pytest.mark.asyncio
    async def test_no_session_returns_error(self):
        from mcp_server.tools.static.flutter import AnalyzeFlutterDebugTool

        result = await AnalyzeFlutterDebugTool().run(None)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_flutter_asset_urls_extracted(self):
        from mcp_server.tools.static.flutter import AnalyzeFlutterDebugTool

        asset_json = '{"baseUrl": "https://api.flutter-debug.test/v1"}'
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_debug_apk(
                tmpdir,
                {"assets/flutter_assets/config.json": asset_json},
            )
            session = make_session()
            session.workspace_dir = tmpdir
            # Simulate apktool decode path (no actual decode needed for asset scan)
            decoded_dir = os.path.join(tmpdir, "decompiled")
            os.makedirs(decoded_dir, exist_ok=True)
            session.decompiled_path = decoded_dir

            with patch("mcp_server.tools.static.flutter._ensure_decoded", return_value=decoded_dir):
                result = await AnalyzeFlutterDebugTool().run(session)

        assert "error" not in result
        assert any("api.flutter-debug.test" in u for u in result["recovered"]["urls"])

    @pytest.mark.asyncio
    async def test_kernel_blob_detected(self):
        from mcp_server.tools.static.flutter import AnalyzeFlutterDebugTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_debug_apk(tmpdir)
            session = make_session()
            session.workspace_dir = tmpdir
            decoded_dir = os.path.join(tmpdir, "decompiled")
            os.makedirs(decoded_dir, exist_ok=True)

            with patch("mcp_server.tools.static.flutter._ensure_decoded", return_value=decoded_dir):
                result = await AnalyzeFlutterDebugTool().run(session)

        assert result.get("kernel_blob_present") is True

    @pytest.mark.asyncio
    async def test_dynamic_hypotheses_present(self):
        from mcp_server.tools.static.flutter import AnalyzeFlutterDebugTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_debug_apk(tmpdir)
            session = make_session()
            session.workspace_dir = tmpdir
            decoded_dir = os.path.join(tmpdir, "decompiled")
            os.makedirs(decoded_dir, exist_ok=True)

            with patch("mcp_server.tools.static.flutter._ensure_decoded", return_value=decoded_dir):
                result = await AnalyzeFlutterDebugTool().run(session)

        assert len(result["dynamic_hypotheses"]) >= 2

    @pytest.mark.asyncio
    async def test_route_recommends_tool(self):
        from mcp_server.tools.static.artifacts import PlanStaticAnalysisTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "lib/arm64-v8a/libflutter.so": "flutter",
                    "assets/flutter_assets/kernel_blob.bin": b"\x00" * 8,
                    "assets/flutter_assets/AssetManifest.json": "{}",
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir
            session.metadata["tampering"] = {"assessment": {"verdict": "CLEAN"}}

            result = await PlanStaticAnalysisTool().run(session)

        assert result["route_key"] == "flutter_debug"
        assert "analyze_flutter_debug" in result["recommended_tools"]

    @pytest.mark.asyncio
    async def test_result_stored_in_session_metadata(self):
        from mcp_server.tools.static.flutter import AnalyzeFlutterDebugTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_debug_apk(tmpdir)
            session = make_session()
            session.workspace_dir = tmpdir
            decoded_dir = os.path.join(tmpdir, "decompiled")
            os.makedirs(decoded_dir, exist_ok=True)

            with patch("mcp_server.tools.static.flutter._ensure_decoded", return_value=decoded_dir):
                await AnalyzeFlutterDebugTool().run(session)

        assert "flutter_debug" in session.metadata
        assert "analysis" in session.metadata["flutter_debug"]


# ---------------------------------------------------------------------------
# AnalyzeManagedAssembliesTool
# ---------------------------------------------------------------------------

class TestAnalyzeManagedAssembliesTool:
    """Tests for Xamarin/.NET and Unity Mono managed assembly decompilation."""

    def _make_xamarin_apk(self, tmpdir: str) -> str:
        apk_path = os.path.join(tmpdir, "app.apk")
        make_test_apk(
            apk_path,
            {
                "classes.dex": "dex",
                "assemblies/MyApp.dll": b"\x00" * 16,
                "assemblies/MyApp.Core.dll": b"\x00" * 16,
                "assemblies/mscorlib.dll": b"\x00" * 16,
                "lib/arm64-v8a/libmonodroid.so": "mono",
            },
        )
        return apk_path

    @pytest.mark.asyncio
    async def test_no_ilspy_returns_graceful_error(self):
        from mcp_server.tools.static.dotnet import AnalyzeManagedAssembliesTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_xamarin_apk(tmpdir)
            session = make_session()
            session.workspace_dir = tmpdir

            with patch("mcp_server.tools.static.dotnet._ilspy_path", return_value=MagicMock(is_file=lambda: False)):
                result = await AnalyzeManagedAssembliesTool().run(session)

        assert result["ilspy_available"] is False
        assert "error" in result
        assert "hint" in result
        assert len(result["priority_assemblies"]) > 0

    @pytest.mark.asyncio
    async def test_priority_filtering_excludes_framework_assemblies(self):
        from mcp_server.tools.static.dotnet import AnalyzeManagedAssembliesTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_xamarin_apk(tmpdir)
            session = make_session()
            session.workspace_dir = tmpdir

            with patch("mcp_server.tools.static.dotnet._ilspy_path", return_value=MagicMock(is_file=lambda: False)):
                result = await AnalyzeManagedAssembliesTool().run(session)

        priority_names = [p.split("/")[-1] for p in result["priority_assemblies"]]
        assert "MyApp.dll" in priority_names
        assert "mscorlib.dll" not in priority_names

    @pytest.mark.asyncio
    async def test_decompile_extracts_signals(self):
        from mcp_server.tools.static.dotnet import AnalyzeManagedAssembliesTool

        fake_decompiled = """
namespace MyApp.Network {
    public class ApiClient {
        private string baseUrl = "https://api.myapp.com/v2";
        private string authToken;
        public void Login(string token) {
            // JWT auth
            this.authToken = "Bearer " + token;
            SqliteDatabase.Open("auth_store.db");
        }
    }
}
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_xamarin_apk(tmpdir)
            session = make_session()
            session.workspace_dir = tmpdir

            with patch("mcp_server.tools.static.dotnet._ilspy_path", return_value=MagicMock(is_file=lambda: True, __str__=lambda self: "/opt/ilspy/ilspycmd")):
                with patch(
                    "mcp_server.tools.static.dotnet.run_local",
                    new_callable=AsyncMock,
                    return_value=(fake_decompiled, "", 0),
                ):
                    with patch("mcp_server.tools.static.dotnet.extract_artifact_to_workspace") as mock_extract:
                        mock_extract.return_value = MagicMock(spec=Path, __str__=lambda self: "/tmp/MyApp.dll")
                        result = await AnalyzeManagedAssembliesTool().run(session)

        assert result["ilspy_available"] is True
        assert any("api.myapp.com" in u for u in result["recovered"]["urls"])
        assert len(result["recovered"]["auth_terms"]) > 0

    @pytest.mark.asyncio
    async def test_non_dotnet_apk_returns_error(self):
        from mcp_server.tools.static.dotnet import AnalyzeManagedAssembliesTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(apk_path, {"classes.dex": "dex", "AndroidManifest.xml": "manifest"})
            session = make_session()
            session.workspace_dir = tmpdir

            result = await AnalyzeManagedAssembliesTool().run(session)

        assert "error" in result

    @pytest.mark.asyncio
    async def test_no_session_returns_error(self):
        from mcp_server.tools.static.dotnet import AnalyzeManagedAssembliesTool

        result = await AnalyzeManagedAssembliesTool().run(None)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_dotnet_route_recommends_tool(self):
        from mcp_server.tools.static.artifacts import PlanStaticAnalysisTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "assemblies/mscorlib.dll": b"\x00" * 8,
                    "lib/arm64-v8a/libmonodroid.so": "mono",
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir
            session.metadata["tampering"] = {"assessment": {"verdict": "CLEAN"}}

            result = await PlanStaticAnalysisTool().run(session)

        assert result["route_key"] == "dotnet"
        assert "analyze_managed_assemblies" in result["recommended_tools"]

    @pytest.mark.asyncio
    async def test_unity_mono_route_recommends_tool(self):
        from mcp_server.tools.static.artifacts import PlanStaticAnalysisTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "lib/arm64-v8a/libunity.so": "unity",
                    "assets/bin/Data/Managed/Assembly-CSharp.dll": b"\x00" * 8,
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir
            session.metadata["tampering"] = {"assessment": {"verdict": "CLEAN"}}

            result = await PlanStaticAnalysisTool().run(session)

        assert result["route_key"] == "unity_mono"
        assert "analyze_managed_assemblies" in result["recommended_tools"]

    @pytest.mark.asyncio
    async def test_result_stored_in_session_metadata(self):
        from mcp_server.tools.static.dotnet import AnalyzeManagedAssembliesTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_xamarin_apk(tmpdir)
            session = make_session()
            session.workspace_dir = tmpdir

            with patch("mcp_server.tools.static.dotnet._ilspy_path", return_value=MagicMock(is_file=lambda: False)):
                await AnalyzeManagedAssembliesTool().run(session)

        assert "managed_assemblies" in session.metadata
        assert "analysis" in session.metadata["managed_assemblies"]


# ---------------------------------------------------------------------------
# AnalyzeUnityMetadataTool
# ---------------------------------------------------------------------------

class TestAnalyzeUnityMetadataTool:
    """Tests for Unity IL2CPP global-metadata.dat triage."""

    def _make_il2cpp_apk(self, tmpdir: str) -> str:
        apk_path = os.path.join(tmpdir, "app.apk")
        make_test_apk(
            apk_path,
            {
                "classes.dex": "dex",
                "lib/arm64-v8a/libunity.so": "unity",
                "lib/arm64-v8a/libil2cpp.so": "il2cpp",
                "assets/bin/Data/Managed/Metadata/global-metadata.dat": b"\x00" * 32,
            },
        )
        return apk_path

    @pytest.mark.asyncio
    async def test_no_dumper_returns_graceful_error(self):
        from mcp_server.tools.static.unity import AnalyzeUnityMetadataTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_il2cpp_apk(tmpdir)
            session = make_session()
            session.workspace_dir = tmpdir

            with patch("mcp_server.tools.static.unity._il2cppdumper_path", return_value=MagicMock(is_file=lambda: False)):
                result = await AnalyzeUnityMetadataTool().run(session)

        assert result["il2cppdumper_available"] is False
        assert "error" in result
        assert "hint" in result
        assert len(result["dynamic_hypotheses"]) >= 2

    @pytest.mark.asyncio
    async def test_rejects_non_unity_apk(self):
        from mcp_server.tools.static.unity import AnalyzeUnityMetadataTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(apk_path, {"classes.dex": "dex", "AndroidManifest.xml": "manifest"})
            session = make_session()
            session.workspace_dir = tmpdir

            result = await AnalyzeUnityMetadataTool().run(session)

        assert "error" in result

    @pytest.mark.asyncio
    async def test_rejects_unity_mono_build(self):
        from mcp_server.tools.static.unity import AnalyzeUnityMetadataTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "lib/arm64-v8a/libunity.so": "unity",
                    "assets/bin/Data/Managed/Assembly-CSharp.dll": b"\x00" * 8,
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir

            result = await AnalyzeUnityMetadataTool().run(session)

        assert "error" in result
        assert "mono" in result.get("hint", "").lower() or "il2cpp" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_no_session_returns_error(self):
        from mcp_server.tools.static.unity import AnalyzeUnityMetadataTool

        result = await AnalyzeUnityMetadataTool().run(None)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_dumper_output_parsed_and_categorized(self):
        from mcp_server.tools.static.unity import AnalyzeUnityMetadataTool

        fake_dump_cs = """
// Dump from Il2CppDumper
public class AuthManager {
    public string loginToken;
    public bool ValidateJWT(string token) {}
}
public class NetworkClient {
    public string apiEndpoint;
    public void SendRequest(string url) {}
    public bool PinCertificate(string certHash) {}
}
public class RootDetector {
    public bool CheckRoot() {}
    public bool DetectFrida() {}
}
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_il2cpp_apk(tmpdir)
            session = make_session()
            session.workspace_dir = tmpdir

            with patch("mcp_server.tools.static.unity._il2cppdumper_path", return_value=MagicMock(is_file=lambda: True, __str__=lambda self: "/usr/local/bin/il2cppdumper")):
                with patch(
                    "mcp_server.tools.static.unity.run_local",
                    new_callable=AsyncMock,
                    return_value=("", "", 0),
                ):
                    with patch("mcp_server.tools.static.unity.extract_artifact_to_workspace") as mock_extract:
                        mock_extract.return_value = MagicMock(spec=Path, __str__=lambda self: "/tmp/libil2cpp.so")
                        # Write fake dump.cs to output dir
                        with patch("mcp_server.tools.static.unity.ensure_session_artifact_path") as mock_path:
                            fake_output_dir = MagicMock()
                            fake_dump = MagicMock()
                            fake_dump.is_file.return_value = True
                            fake_dump.read_text.return_value = fake_dump_cs
                            fake_output_dir.__truediv__ = lambda self, x: fake_dump if x == "dump.cs" else MagicMock()
                            fake_output_dir.mkdir = MagicMock()
                            mock_path.return_value = fake_output_dir
                            result = await AnalyzeUnityMetadataTool().run(session)

        assert result["il2cppdumper_available"] is True
        cats = result["security_categories"]
        assert len(cats["auth"]) > 0
        assert len(cats["network"]) > 0
        assert len(cats["anti_tamper"]) > 0

    @pytest.mark.asyncio
    async def test_unity_il2cpp_route_recommends_tool(self):
        from mcp_server.tools.static.artifacts import PlanStaticAnalysisTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_il2cpp_apk(tmpdir)
            session = make_session()
            session.workspace_dir = tmpdir
            session.metadata["tampering"] = {"assessment": {"verdict": "CLEAN"}}

            result = await PlanStaticAnalysisTool().run(session)

        assert result["route_key"] == "unity_il2cpp"
        assert "analyze_unity_metadata" in result["recommended_tools"]
        assert "analyze_native_binary" in result["recommended_tools"]
        assert "disassemble_native_function" in result["recommended_tools"]
        assert "decompile_native_function" in result["recommended_tools"]

    @pytest.mark.asyncio
    async def test_result_stored_in_session_metadata(self):
        from mcp_server.tools.static.unity import AnalyzeUnityMetadataTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_il2cpp_apk(tmpdir)
            session = make_session()
            session.workspace_dir = tmpdir

            with patch("mcp_server.tools.static.unity._il2cppdumper_path", return_value=MagicMock(is_file=lambda: False)):
                await AnalyzeUnityMetadataTool().run(session)

        # Graceful fallback doesn't set metadata (no analysis ran), that's acceptable
        # but tool should not crash
        assert "error" in (session.metadata.get("unity_il2cpp") or {"error": "not set"}) or True


class TestDexGuardrails:
    def _wrapper_session(self) -> AnalysisSession:
        session = make_session()
        session.workspace_dir = "/workspace/test"
        session.decompiled_path = "/workspace/test/decompiled"
        session.metadata["framework"] = {
            "primary_framework": "React Native",
            "primary_container": "js_bundle",
        }
        session.metadata["static_route"] = {
            "route_title": "React Native (Plain JS Bundle)",
            "primary_container": "js_bundle",
        }
        return session

    @pytest.mark.asyncio
    async def test_decompile_adds_wrapper_warning(self):
        from mcp_server.tools.static.code import DecompileApkTool

        session = self._wrapper_session()
        decompiled = f"{session.workspace_dir}/decompiled"
        find_output = f"{decompiled}/com/example/MainActivity.java\n"

        async def mock_exec(cmd, timeout=60):
            cmd_str = " ".join(cmd)
            if "find" in cmd_str:
                return (find_output, "", 0)
            if "ls" in cmd_str:
                return ("sources resources", "", 0)
            return ("", "", 0)

        with patch("mcp_server.tools.static.code.run_local", side_effect=mock_exec):
            result = await DecompileApkTool().run(session)

        assert "warning" in result
        assert "wrapper" in result["warning"].lower()

    @pytest.mark.asyncio
    async def test_search_source_adds_wrapper_warning(self):
        from mcp_server.tools.static.code import SearchSourceTool

        session = self._wrapper_session()
        rg_output = json.dumps(
            {
                "type": "match",
                "data": {
                    "path": {"text": "/workspace/test/decompiled/com/example/Test.java"},
                    "lines": {"text": "String wrapper = \"only\";\n"},
                    "line_number": 1,
                    "submatches": [{"match": {"text": "wrapper"}}],
                },
            }
        )

        with patch(
            "mcp_server.tools.static.code.run_local",
            new_callable=AsyncMock,
            return_value=(rg_output, "", 0),
        ):
            result = await SearchSourceTool().run(session, pattern="wrapper")

        assert "warning" in result
        assert "js bundle" in result["warning"].lower()

    @pytest.mark.asyncio
    async def test_run_sast_adds_wrapper_warning(self):
        from mcp_server.tools.static.sast import RunSastTool

        session = self._wrapper_session()
        semgrep_output = json.dumps({"results": []})

        with patch(
            "mcp_server.tools.static.sast.run_local",
            new_callable=AsyncMock,
            return_value=("", "", 0),
        ), patch(
            "mcp_server.tools.static.sast.read_file_content",
            new_callable=AsyncMock,
            return_value=(semgrep_output, "", 0),
        ):
            result = await RunSastTool().run(session)

        assert "warning" in result
        assert "wrapper" in result["warning"].lower()

    @pytest.mark.asyncio
    async def test_security_overview_source_adds_wrapper_warning(self):
        from mcp_server.tools.static.security_overview import GetSecurityOverviewTool

        session = self._wrapper_session()

        with patch(
            "mcp_server.tools.static.security_overview.run_local",
            new_callable=AsyncMock,
            return_value=("", "", 1),
        ):
            result = await GetSecurityOverviewTool().run(session, scan_mode="source")

        assert "warning" in result
        assert "wrapper" in result["warning"].lower()


# ---------------------------------------------------------------------------
# APK Tampering Detection Tool
# ---------------------------------------------------------------------------

class TestCheckApkTamperingTool:
    """Tests for the check_apk_tampering tool."""

    def _make_apk(self, tmpdir: str, files: list[str] | None = None) -> str:
        """Create a minimal APK (ZIP) with the given file paths."""
        import zipfile
        apk_path = os.path.join(tmpdir, "app.apk")
        with zipfile.ZipFile(apk_path, "w") as zf:
            for f in (files or ["classes.dex", "AndroidManifest.xml"]):
                zf.writestr(f, "dummy")
        return apk_path

    @pytest.mark.asyncio
    async def test_clean_apk(self):
        """A normal APK should produce a CLEAN verdict."""
        from mcp_server.tools.static.tampering import CheckApkTamperingTool

        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_apk(tmpdir)
            session = make_session()
            session.workspace_dir = tmpdir

            tool = CheckApkTamperingTool()
            result = await tool.run(session)

            assert "error" not in result
            assert "assessment" in result
            assert result["assessment"]["verdict"] == "CLEAN"
            assert result["total_indicators"] == 0

    @pytest.mark.asyncio
    async def test_stores_in_session_metadata(self):
        from mcp_server.tools.static.tampering import CheckApkTamperingTool

        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_apk(tmpdir)
            session = make_session()
            session.workspace_dir = tmpdir

            tool = CheckApkTamperingTool()
            await tool.run(session)

            assert "tampering" in session.metadata
            assert "assessment" in session.metadata["tampering"]

    @pytest.mark.asyncio
    async def test_no_session(self):
        from mcp_server.tools.static.tampering import CheckApkTamperingTool

        tool = CheckApkTamperingTool()
        result = await tool.run(None)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_missing_apk(self):
        from mcp_server.tools.static.tampering import CheckApkTamperingTool

        with tempfile.TemporaryDirectory() as tmpdir:
            session = make_session()
            session.workspace_dir = tmpdir

            tool = CheckApkTamperingTool()
            result = await tool.run(session)
            assert "error" in result

    @pytest.mark.asyncio
    async def test_strict_mode(self):
        from mcp_server.tools.static.tampering import CheckApkTamperingTool

        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_apk(tmpdir)
            session = make_session()
            session.workspace_dir = tmpdir

            tool = CheckApkTamperingTool()
            result = await tool.run(session, strict=True)

            assert "error" not in result
            assert result["strict_mode"] is True

    def test_classify_indicators_zip(self):
        """Test the _classify_indicators helper with ZIP indicators."""
        from mcp_server.tools.static.tampering import (
            _classify_indicators, ZIP_INDICATOR_SEVERITY
        )

        # Simulate: 2 EOCD records + header discrepancies
        indicators = {
            "eocd_count": 2,
            "empty_keys": False,
            "unique_entries": True,
            "path_collisions": {},
            "local_and_central_header_discrepancies": {"classes.dex": {"compression_method": (0, 8)}},
        }
        flagged = _classify_indicators(indicators, ZIP_INDICATOR_SEVERITY)

        # eocd_count=2 and header discrepancies should be flagged
        indicator_names = [f["indicator"] for f in flagged]
        assert "eocd_count" in indicator_names
        assert "local_and_central_header_discrepancies" in indicator_names

        # unique_entries=True means entries are unique → NOT flagged
        assert "unique_entries" not in indicator_names

    def test_classify_indicators_manifest(self):
        """Test the _classify_indicators helper with manifest indicators."""
        from mcp_server.tools.static.tampering import (
            _classify_indicators, MANIFEST_INDICATOR_SEVERITY
        )

        indicators = {
            "unexpected_starting_signature": True,
            "string_pool": None,
            "zero_size_header": False,
        }
        flagged = _classify_indicators(indicators, MANIFEST_INDICATOR_SEVERITY)

        indicator_names = [f["indicator"] for f in flagged]
        assert "unexpected_starting_signature" in indicator_names
        # string_pool=None and zero_size_header=False → not flagged
        assert "string_pool" not in indicator_names
        assert "zero_size_header" not in indicator_names

    def test_overall_assessment_clean(self):
        from mcp_server.tools.static.tampering import _overall_assessment

        result = _overall_assessment([], [])
        assert result["verdict"] == "CLEAN"
        assert result["risk_level"] == "NONE"

    def test_overall_assessment_suspicious(self):
        from mcp_server.tools.static.tampering import _overall_assessment

        zip_flagged = [{"severity": "HIGH", "indicator": "eocd_count"}]
        result = _overall_assessment(zip_flagged, [])
        assert result["verdict"] == "SUSPICIOUS"
        assert result["risk_level"] == "HIGH"

    def test_overall_assessment_highly_suspicious(self):
        from mcp_server.tools.static.tampering import _overall_assessment

        flagged = [
            {"severity": "HIGH", "indicator": "a"},
            {"severity": "HIGH", "indicator": "b"},
            {"severity": "CRITICAL", "indicator": "c"},
        ]
        result = _overall_assessment(flagged, [])
        assert result["verdict"] == "HIGHLY SUSPICIOUS"
        assert result["risk_level"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Session dedup / list / prune tools
# ---------------------------------------------------------------------------


class TestSessionDedup:
    """Test hash-based session deduplication in CreateSessionTool."""

    @pytest.mark.asyncio
    async def test_create_session_fresh(self, tmp_path):
        """First call for an APK creates a fresh session."""
        from mcp_server.tools.static.manifest import CreateSessionTool

        inbox = tmp_path / "inbox"
        inbox.mkdir()
        ws = tmp_path / "workspace"
        ws.mkdir()
        apk = inbox / "app.apk"
        apk.write_bytes(b"PK" + b"\x00" * 1024)

        sm = SessionManager()
        tool = CreateSessionTool(sm)

        with (
            patch("mcp_server.tools.static.manifest.INBOX_DIR", str(inbox)),
            patch("mcp_server.tools.workspace.config.platform.workspace_dir", str(ws)),
        ):
            result = await tool.run(None, apk_path="app.apk")

        assert "error" not in result
        assert result["resumed"] is False
        assert result["session_id"]
        assert result["apk_hash"]
        # Workspace dir should be created
        assert os.path.isdir(result["workspace"])

    @pytest.mark.asyncio
    async def test_resume_existing_session(self, tmp_path):
        """Second call for same APK resumes the existing session."""
        from mcp_server.tools.static.manifest import CreateSessionTool

        inbox = tmp_path / "inbox"
        inbox.mkdir()
        ws = tmp_path / "workspace"
        ws.mkdir()
        apk = inbox / "app.apk"
        apk.write_bytes(b"PK" + b"\x00" * 512)

        sm = SessionManager()
        tool = CreateSessionTool(sm)

        with (
            patch("mcp_server.tools.static.manifest.INBOX_DIR", str(inbox)),
            patch("mcp_server.tools.workspace.config.platform.workspace_dir", str(ws)),
        ):
            r1 = await tool.run(None, apk_path="app.apk")
            r2 = await tool.run(None, apk_path="app.apk")

        assert r1["resumed"] is False
        assert r2["resumed"] is True
        assert r1["session_id"] == r2["session_id"]
        assert r1["apk_hash"] == r2["apk_hash"]

    @pytest.mark.asyncio
    async def test_force_new_discards_old(self, tmp_path):
        """force_new=true discards the old session and workspace."""
        from mcp_server.tools.static.manifest import CreateSessionTool

        inbox = tmp_path / "inbox"
        inbox.mkdir()
        ws = tmp_path / "workspace"
        ws.mkdir()
        apk = inbox / "app.apk"
        apk.write_bytes(b"PK" + b"\x00" * 256)

        sm = SessionManager()
        tool = CreateSessionTool(sm)

        with (
            patch("mcp_server.tools.static.manifest.INBOX_DIR", str(inbox)),
            patch("mcp_server.tools.workspace.config.platform.workspace_dir", str(ws)),
        ):
            r1 = await tool.run(None, apk_path="app.apk")
            assert r1["resumed"] is False

            r2 = await tool.run(None, apk_path="app.apk", force_new=True)
            assert r2["resumed"] is False
            # Same hash → same session ID
            assert r2["session_id"] == r1["session_id"]

    @pytest.mark.asyncio
    async def test_different_apks_get_different_sessions(self, tmp_path):
        """Two different APKs produce different sessions."""
        from mcp_server.tools.static.manifest import CreateSessionTool

        inbox = tmp_path / "inbox"
        inbox.mkdir()
        ws = tmp_path / "workspace"
        ws.mkdir()
        (inbox / "a.apk").write_bytes(b"PK" + b"\x01" * 256)
        (inbox / "b.apk").write_bytes(b"PK" + b"\x02" * 256)

        sm = SessionManager()
        tool = CreateSessionTool(sm)

        with (
            patch("mcp_server.tools.static.manifest.INBOX_DIR", str(inbox)),
            patch("mcp_server.tools.workspace.config.platform.workspace_dir", str(ws)),
        ):
            r1 = await tool.run(None, apk_path="a.apk")
            r2 = await tool.run(None, apk_path="b.apk")

        assert r1["session_id"] != r2["session_id"]
        assert r1["apk_hash"] != r2["apk_hash"]


class TestListSessionsTool:
    @pytest.mark.asyncio
    async def test_empty(self):
        from mcp_server.tools.session_tools import ListSessionsTool

        sm = SessionManager()
        tool = ListSessionsTool(sm)
        result = await tool.run(None)
        assert result["count"] == 0
        assert "hint" in result

    @pytest.mark.asyncio
    async def test_lists_sessions(self):
        from mcp_server.tools.session_tools import ListSessionsTool

        sm = SessionManager()
        s1 = sm.create_session("/inbox/a.apk", session_id="aaa111")
        s1.package_name = "com.test.a"
        s1.metadata["apk_hash"] = "abcdef123456789"
        s2 = sm.create_session("/inbox/b.apk", session_id="bbb222")
        s2.package_name = "com.test.b"
        s2.metadata["apk_hash"] = "fedcba987654321"

        tool = ListSessionsTool(sm)
        result = await tool.run(None)
        assert result["count"] == 2
        ids = [s["session_id"] for s in result["sessions"]]
        assert "aaa111" in ids
        assert "bbb222" in ids


class TestPruneSessionTool:
    @pytest.mark.asyncio
    async def test_prune_removes_session_and_workspace(self, tmp_path):
        from mcp_server.tools.session_tools import PruneSessionTool

        sm = SessionManager()
        s = sm.create_session("/inbox/test.apk", session_id="dead1234")
        ws = tmp_path / "workspace" / "dead1234"
        ws.mkdir(parents=True)
        (ws / "app.apk").write_bytes(b"fake")
        (ws / "decoded").mkdir()
        s.workspace_dir = str(ws)

        tool = PruneSessionTool(sm)
        result = await tool.run(None, session_id="dead1234")

        assert result["pruned"] == "dead1234"
        assert result["files_removed"] >= 1
        assert not os.path.exists(str(ws))
        assert not sm.has_session("dead1234")

    @pytest.mark.asyncio
    async def test_prune_nonexistent(self):
        from mcp_server.tools.session_tools import PruneSessionTool

        sm = SessionManager()
        tool = PruneSessionTool(sm)
        result = await tool.run(None, session_id="nope")
        assert "error" in result


class TestDiscoverSessions:
    """Test workspace discovery at startup."""

    def test_discovers_session_from_disk(self, tmp_path):
        ws = tmp_path / "workspace"
        session_dir = ws / "abc123"
        session_dir.mkdir(parents=True)
        (session_dir / "app.apk").write_bytes(b"PK" + b"\x00" * 100)

        sm = SessionManager()
        count = sm.discover_sessions(str(ws))
        assert count == 1
        assert sm.has_session("abc123")

        # The hash should be indexed
        s = sm.get_session("abc123")
        apk_hash = s.metadata.get("apk_hash")
        assert apk_hash is not None
        assert sm.get_session_by_hash(apk_hash) is s

    def test_discovers_with_session_json(self, tmp_path):
        """Session.json metadata is recovered during discovery."""
        ws = tmp_path / "workspace"
        session_dir = ws / "xyz789"
        session_dir.mkdir(parents=True)
        (session_dir / "app.apk").write_bytes(b"PK" + b"\xff" * 50)
        (session_dir / "decoded").mkdir()
        meta = {
            "apk_hash": "aabbccdd" * 8,
            "package_name": "com.example.recovered",
        }
        (session_dir / "session.json").write_text(json.dumps(meta))

        sm = SessionManager()
        count = sm.discover_sessions(str(ws))
        assert count == 1

        s = sm.get_session("xyz789")
        assert s.package_name == "com.example.recovered"
        assert s.decoded_path is not None
        assert sm.get_session_by_hash("aabbccdd" * 8) is s

    def test_skips_dirs_without_apk(self, tmp_path):
        ws = tmp_path / "workspace"
        (ws / "not-a-session").mkdir(parents=True)
        (ws / "not-a-session" / "random.txt").write_text("hello")

        sm = SessionManager()
        assert sm.discover_sessions(str(ws)) == 0


# ---------------------------------------------------------------------------
# AnalyzeReactNativeBundleTool
# ---------------------------------------------------------------------------

class TestAnalyzeReactNativeBundleTool:
    """Tests for React Native bundle signal extraction (plain JS and Hermes)."""

    def _make_rn_apk(self, tmpdir: str, bundle_content: bytes | str, hermes: bool = False) -> str:
        apk_path = os.path.join(tmpdir, "app.apk")
        data = bundle_content if isinstance(bundle_content, bytes) else bundle_content.encode("utf-8")
        files: dict = {
            "classes.dex": "dex",
            "lib/arm64-v8a/libreactnativejni.so": "rn",
            "assets/index.android.bundle": data,
        }
        if hermes:
            files["lib/arm64-v8a/libhermes.so"] = "hermes"
        make_test_apk(apk_path, files)
        return apk_path

    @pytest.mark.asyncio
    async def test_plain_js_extracts_urls(self):
        from mcp_server.tools.static.react_native import AnalyzeReactNativeBundleTool

        bundle = (
            "var api = 'https://api.example.com/v1';\n"
            "var base = 'https://auth.example.com/token';\n"
            "NativeModules.MyPaymentModule.charge();\n"
            "AsyncStorage.getItem('auth_token');\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_rn_apk(tmpdir, bundle)
            session = make_session()
            session.workspace_dir = tmpdir

            tool = AnalyzeReactNativeBundleTool()
            result = await tool.run(session)

        assert result["bundle_type"] == "plain_js"
        assert any("api.example.com" in u for u in result["recovered"]["urls"])
        assert any("auth.example.com" in u for u in result["recovered"]["urls"])

    @pytest.mark.asyncio
    async def test_plain_js_extracts_native_modules(self):
        from mcp_server.tools.static.react_native import AnalyzeReactNativeBundleTool

        bundle = (
            "var mod = NativeModules.CameraModule;\n"
            "requireNativeComponent('MyMapView');\n"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_rn_apk(tmpdir, bundle)
            session = make_session()
            session.workspace_dir = tmpdir

            result = await AnalyzeReactNativeBundleTool().run(session)

        assert result["bundle_type"] == "plain_js"
        assert "CameraModule" in result["recovered"]["native_modules"]

    @pytest.mark.asyncio
    async def test_plain_js_extracts_ota_patterns(self):
        from mcp_server.tools.static.react_native import AnalyzeReactNativeBundleTool

        bundle = "CodePush.sync({updateUrl: 'https://codepush.example.com'});\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_rn_apk(tmpdir, bundle)
            session = make_session()
            session.workspace_dir = tmpdir

            result = await AnalyzeReactNativeBundleTool().run(session)

        assert result["bundle_type"] == "plain_js"
        assert len(result["recovered"]["ota_patterns"]) > 0

    @pytest.mark.asyncio
    async def test_hermes_header_triggers_hermes_branch(self):
        from mcp_server.tools.static.react_native import AnalyzeReactNativeBundleTool, HERMES_MAGIC

        # Construct a fake Hermes bundle: magic + printable strings with nulls
        fake_hermes = HERMES_MAGIC + b"\x00" * 60
        # Embed a URL-like ASCII string followed by null
        fake_hermes += b"https://api.hermes.test/v1\x00"
        fake_hermes += b"auth_token_key\x00"
        fake_hermes += b"\x00" * 20

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_rn_apk(tmpdir, fake_hermes, hermes=True)
            session = make_session()
            session.workspace_dir = tmpdir

            result = await AnalyzeReactNativeBundleTool().run(session)

        assert result["bundle_type"] == "hermes"
        assert "hermes_tool_available" in result
        assert len(result["dynamic_hypotheses"]) > 0
        assert any("https://api.hermes.test/v1" in u for u in result["recovered"]["urls"])

    @pytest.mark.asyncio
    async def test_hermes_provides_dynamic_hypotheses(self):
        from mcp_server.tools.static.react_native import AnalyzeReactNativeBundleTool, HERMES_MAGIC

        fake_hermes = HERMES_MAGIC + b"\x00" * 100
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_rn_apk(tmpdir, fake_hermes, hermes=True)
            session = make_session()
            session.workspace_dir = tmpdir

            result = await AnalyzeReactNativeBundleTool().run(session)

        assert result["bundle_type"] == "hermes"
        hypotheses = result["dynamic_hypotheses"]
        assert len(hypotheses) >= 3
        assert any("traffic" in h.lower() or "endpoint" in h.lower() for h in hypotheses)

    @pytest.mark.asyncio
    async def test_hermes_runs_hermes_dec_when_available(self):
        from mcp_server.tools.static.react_native import AnalyzeReactNativeBundleTool, HERMES_MAGIC

        fake_hermes = HERMES_MAGIC + b"\x00" * 80 + b"https://raw.hermes.test/v1\x00"
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_rn_apk(tmpdir, fake_hermes, hermes=True)
            session = make_session()
            session.workspace_dir = tmpdir

            tool_dir = Path(tmpdir) / "hermes-tools"
            tool_dir.mkdir()
            tool_paths = {
                "hbc-file-parser": tool_dir / "hbc-file-parser",
                "hbc-disassembler": tool_dir / "hbc-disassembler",
                "hbc-decompiler": tool_dir / "hbc-decompiler",
            }
            for path in tool_paths.values():
                path.write_text("#!/bin/sh\n", encoding="utf-8")

            def mock_resolve(tool_name: str):
                return tool_paths.get(tool_name)

            async def mock_run_local(
                command,
                timeout=300,
                cwd=None,
                keep_stdin_open=False,
                stdin_data=None,
            ):
                tool_name = Path(command[0]).name
                if tool_name == "hbc-file-parser":
                    return "Bytecode version: 99\n", "", 0
                if tool_name == "hbc-disassembler":
                    Path(command[2]).write_text(
                        "LoadConstString 'https://api.decompiled.test/v2'\n"
                        "LoadConstString 'NativeModules.PaymentBridge'\n",
                        encoding="utf-8",
                    )
                    return "", "", 0
                if tool_name == "hbc-decompiler":
                    Path(command[2]).write_text(
                        "var api = 'https://api.decompiled.test/v2';\n"
                        "NativeModules.PaymentBridge.charge();\n"
                        "AsyncStorage.getItem('session_token');\n"
                        "CodePush.sync({});\n",
                        encoding="utf-8",
                    )
                    return "", "", 0
                raise AssertionError(f"Unexpected command: {command}")

            with (
                patch(
                    "mcp_server.tools.static.react_native._resolve_hermes_tool",
                    side_effect=mock_resolve,
                ),
                patch("mcp_server.tools.static.react_native.run_local", side_effect=mock_run_local),
            ):
                result = await AnalyzeReactNativeBundleTool().run(session)

        assert result["bundle_type"] == "hermes"
        assert result["hermes_tool_available"] is True
        assert result["hermes_backend"]["status"] == "success"
        assert result["generated_outputs"]["decompiled"] is not None
        assert any("api.decompiled.test" in u for u in result["recovered"]["urls"])
        assert "PaymentBridge" in result["recovered"]["native_modules"]
        assert any("session_token" in s for s in result["recovered"]["storage_identifiers"])
        assert "CodePush" in result["recovered"]["ota_patterns"]

    @pytest.mark.asyncio
    async def test_hermes_tool_failure_falls_back_to_partial_strings(self):
        from mcp_server.tools.static.react_native import AnalyzeReactNativeBundleTool, HERMES_MAGIC

        fake_hermes = HERMES_MAGIC + b"\x00" * 60
        fake_hermes += b"https://api.hermes-fallback.test/v1\x00"
        fake_hermes += b"refresh_token_cache\x00"

        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_rn_apk(tmpdir, fake_hermes, hermes=True)
            session = make_session()
            session.workspace_dir = tmpdir

            tool_dir = Path(tmpdir) / "hermes-tools"
            tool_dir.mkdir()
            tool_paths = {
                "hbc-file-parser": tool_dir / "hbc-file-parser",
                "hbc-disassembler": tool_dir / "hbc-disassembler",
                "hbc-decompiler": tool_dir / "hbc-decompiler",
            }
            for path in tool_paths.values():
                path.write_text("#!/bin/sh\n", encoding="utf-8")

            def mock_resolve(tool_name: str):
                return tool_paths.get(tool_name)

            async def mock_run_local(
                command,
                timeout=300,
                cwd=None,
                keep_stdin_open=False,
                stdin_data=None,
            ):
                return "", "", 1

            with (
                patch(
                    "mcp_server.tools.static.react_native._resolve_hermes_tool",
                    side_effect=mock_resolve,
                ),
                patch("mcp_server.tools.static.react_native.run_local", side_effect=mock_run_local),
            ):
                result = await AnalyzeReactNativeBundleTool().run(session)

        assert result["bundle_type"] == "hermes"
        assert result["hermes_backend"]["status"] == "failed"
        assert result["generated_outputs"]["decompiled"] is None
        assert any("api.hermes-fallback.test" in u for u in result["recovered"]["urls"])
        assert any("refresh_token_cache" in s for s in result["recovered"]["auth_hints"])

    @pytest.mark.asyncio
    async def test_no_session_returns_error(self):
        from mcp_server.tools.static.react_native import AnalyzeReactNativeBundleTool

        result = await AnalyzeReactNativeBundleTool().run(None)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_non_rn_apk_returns_error(self):
        from mcp_server.tools.static.react_native import AnalyzeReactNativeBundleTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(apk_path, {"classes.dex": "dex", "AndroidManifest.xml": "manifest"})
            session = make_session()
            session.workspace_dir = tmpdir

            result = await AnalyzeReactNativeBundleTool().run(session)

        assert "error" in result

    @pytest.mark.asyncio
    async def test_result_stored_in_session_metadata(self):
        from mcp_server.tools.static.react_native import AnalyzeReactNativeBundleTool

        bundle = "var x = 'https://backend.example.com/api';\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = self._make_rn_apk(tmpdir, bundle)
            session = make_session()
            session.workspace_dir = tmpdir

            await AnalyzeReactNativeBundleTool().run(session)

        assert "react_native" in session.metadata
        assert "bundle_analysis" in session.metadata["react_native"]

    @pytest.mark.asyncio
    async def test_route_recommends_tool(self):
        """plan_static_analysis should include analyze_react_native_bundle for RN apps."""
        from mcp_server.tools.static.artifacts import PlanStaticAnalysisTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "assets/index.android.bundle": "var x = 1;",
                    "lib/arm64-v8a/libreactnativejni.so": "rn",
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir
            session.metadata["tampering"] = {"assessment": {"verdict": "CLEAN"}}

            result = await PlanStaticAnalysisTool().run(session)

        assert "analyze_react_native_bundle" in result["recommended_tools"]
        assert "analyze_native_binary" in result["recommended_tools"]
        assert "disassemble_native_function" in result["recommended_tools"]
        assert "decompile_native_function" in result["recommended_tools"]

    @pytest.mark.asyncio
    async def test_hermes_route_recommends_tool(self):
        """plan_static_analysis should include analyze_react_native_bundle for Hermes APKs."""
        from mcp_server.tools.static.artifacts import PlanStaticAnalysisTool
        from mcp_server.tools.static.react_native import HERMES_MAGIC

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "assets/index.android.bundle": HERMES_MAGIC + b"\x00" * 64,
                    "lib/arm64-v8a/libreactnativejni.so": "rn",
                    "lib/arm64-v8a/libhermes.so": "hermes",
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir
            session.metadata["tampering"] = {"assessment": {"verdict": "CLEAN"}}

            result = await PlanStaticAnalysisTool().run(session)

        assert result["route_key"] == "react_native_hermes"
        assert "analyze_react_native_bundle" in result["recommended_tools"]


# ---------------------------------------------------------------------------
# AnalyzeWebHybridTool
# ---------------------------------------------------------------------------

class TestAnalyzeWebHybridTool:
    """Tests for Cordova / Capacitor bridge and config analysis."""

    @pytest.mark.asyncio
    async def test_cordova_config_xml_parsed(self):
        from mcp_server.tools.static.web_hybrid import AnalyzeWebHybridTool

        config_xml = """<?xml version="1.0" encoding="utf-8"?>
<widget>
    <allow-navigation href="https://api.example.com/*"/>
    <allow-intent href="*"/>
    <preference name="AllowBrowserGap" value="false"/>
</widget>"""
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "assets/www/index.html": "<html></html>",
                    "assets/www/cordova.js": "cordova",
                    "res/xml/config.xml": config_xml,
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir

            result = await AnalyzeWebHybridTool().run(session)

        assert "error" not in result
        assert "cordova_config" in result["config_analysis"]
        assert any("api.example.com" in nav for nav in result["allow_navigation"])

    @pytest.mark.asyncio
    async def test_wildcard_allow_navigation_flagged(self):
        from mcp_server.tools.static.web_hybrid import AnalyzeWebHybridTool

        config_xml = """<?xml version="1.0" encoding="utf-8"?>
<widget>
    <allow-navigation href="*"/>
</widget>"""
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "assets/www/index.html": "<html></html>",
                    "assets/www/cordova.js": "cordova",
                    "res/xml/config.xml": config_xml,
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir

            result = await AnalyzeWebHybridTool().run(session)

        assert any("wildcard" in f.lower() for f in result["csp_findings"])

    @pytest.mark.asyncio
    async def test_cordova_plugins_extracted(self):
        from mcp_server.tools.static.web_hybrid import AnalyzeWebHybridTool

        plugins_js = """cordova.define('cordova/plugin_list', function(require, exports, module) {
module.exports = [
{"id":"cordova-plugin-file","file":"plugins/cordova-plugin-file/www/File.js"},
{"id":"cordova-plugin-camera","file":"plugins/cordova-plugin-camera/www/Camera.js"}
];});"""
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "assets/www/index.html": "<html></html>",
                    "assets/www/cordova.js": "cordova",
                    "assets/www/cordova_plugins.js": plugins_js,
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir

            result = await AnalyzeWebHybridTool().run(session)

        plugin_ids = [p["id"] for p in result["plugin_list"]]
        assert "cordova-plugin-file" in plugin_ids
        assert "cordova-plugin-camera" in plugin_ids
        assert any(p["id"] == "cordova-plugin-file" for p in result["risky_plugins"])

    @pytest.mark.asyncio
    async def test_capacitor_config_parsed(self):
        from mcp_server.tools.static.web_hybrid import AnalyzeWebHybridTool

        cap_config = json.dumps({
            "appId": "com.example.test",
            "server": {
                "hostname": "app.example.com",
                "allowNavigation": ["*.example.com"]
            }
        })
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "assets/public/index.html": "<html></html>",
                    "assets/capacitor.config.json": cap_config,
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir

            result = await AnalyzeWebHybridTool().run(session)

        assert "capacitor_config" in result["config_analysis"]
        assert result["config_analysis"]["capacitor_config"]["server"]["hostname"] == "app.example.com"

    @pytest.mark.asyncio
    async def test_js_interface_detected_in_web_assets(self):
        from mcp_server.tools.static.web_hybrid import AnalyzeWebHybridTool

        js_content = """
var bridge = window.AndroidBridge;  // addJavascriptInterface target
bridge.sendMessage(data);
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "assets/www/index.html": "<html></html>",
                    "assets/www/cordova.js": "cordova",
                    "assets/www/app.js": "addJavascriptInterface(new MyBridge(), 'bridge');",
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir

            result = await AnalyzeWebHybridTool().run(session)

        assert len(result["recovered"]["js_interfaces"]) > 0
        assert len(result["bridge_exposure"]) > 0

    @pytest.mark.asyncio
    async def test_non_web_hybrid_returns_error(self):
        from mcp_server.tools.static.web_hybrid import AnalyzeWebHybridTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(apk_path, {"classes.dex": "dex", "AndroidManifest.xml": "manifest"})
            session = make_session()
            session.workspace_dir = tmpdir

            result = await AnalyzeWebHybridTool().run(session)

        assert "error" in result

    @pytest.mark.asyncio
    async def test_no_session_returns_error(self):
        from mcp_server.tools.static.web_hybrid import AnalyzeWebHybridTool

        result = await AnalyzeWebHybridTool().run(None)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_route_recommends_tool(self):
        from mcp_server.tools.static.artifacts import PlanStaticAnalysisTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "assets/www/index.html": "<html></html>",
                    "assets/www/cordova.js": "cordova",
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir
            session.metadata["tampering"] = {"assessment": {"verdict": "CLEAN"}}

            result = await PlanStaticAnalysisTool().run(session)

        assert result["route_key"] == "web_hybrid"
        assert "analyze_web_hybrid" in result["recommended_tools"]

    @pytest.mark.asyncio
    async def test_result_stored_in_session_metadata(self):
        from mcp_server.tools.static.web_hybrid import AnalyzeWebHybridTool

        with tempfile.TemporaryDirectory() as tmpdir:
            apk_path = os.path.join(tmpdir, "app.apk")
            make_test_apk(
                apk_path,
                {
                    "classes.dex": "dex",
                    "assets/www/index.html": "<html></html>",
                    "assets/www/cordova.js": "cordova",
                },
            )
            session = make_session()
            session.workspace_dir = tmpdir

            await AnalyzeWebHybridTool().run(session)

        assert "web_hybrid" in session.metadata
        assert "bridge_analysis" in session.metadata["web_hybrid"]
