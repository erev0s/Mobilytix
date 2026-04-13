"""Tests for ADB-backed UI interaction tools."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from mcp_server.session_manager import SessionManager


def make_session(tmp_path: Path):
    mgr = SessionManager()
    session = mgr.create_session("/tmp/test.apk")
    session.package_name = "com.example.test"
    session.device_id = "android:5555"
    workspace = tmp_path / session.id
    workspace.mkdir(parents=True, exist_ok=True)
    session.workspace_dir = str(workspace)
    return session


def _write_file(path_str: str, content: str | bytes) -> None:
    path = Path(path_str)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content)


class TestInspectUiTool:
    @pytest.mark.asyncio
    async def test_parses_ui_dump_and_persists_state(self, tmp_path):
        from mcp_server.tools.dynamic.ui import InspectUiTool

        session = make_session(tmp_path)
        tool = InspectUiTool()
        xml_dump = """<?xml version="1.0" encoding="UTF-8"?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.example.test" content-desc="" clickable="false" long-clickable="false" checkable="false" checked="false" enabled="true" focusable="false" focused="false" scrollable="false" selected="false" visible-to-user="true" bounds="[0,0][1080,1920]">
    <node index="0" text="Username" resource-id="com.example.test:id/username" class="android.widget.EditText" package="com.example.test" content-desc="" clickable="true" long-clickable="true" checkable="false" checked="false" enabled="true" focusable="true" focused="false" scrollable="false" selected="false" visible-to-user="true" bounds="[100,200][980,320]" />
    <node index="1" text="Sign in" resource-id="com.example.test:id/login" class="android.widget.Button" package="com.example.test" content-desc="Sign in button" clickable="true" long-clickable="false" checkable="false" checked="false" enabled="true" focusable="true" focused="false" scrollable="false" selected="false" visible-to-user="true" bounds="[100,400][980,520]" />
  </node>
</hierarchy>
"""

        async def run_local_side_effect(command, timeout=300, cwd=None, keep_stdin_open=False, stdin_data=None):
            if command[:5] == ["adb", "-s", "android:5555", "shell", "uiautomator"]:
                return (f"UI hierchary dumped to: {command[-1]}", "", 0)
            if command[:4] == ["adb", "-s", "android:5555", "pull"] and command[4] == "/sdcard/window_dump.xml":
                _write_file(command[5], xml_dump)
                return ("1 file pulled", "", 0)
            raise AssertionError(f"Unexpected command: {command}")

        with patch("mcp_server.tools.dynamic.ui.run_local", AsyncMock(side_effect=run_local_side_effect)):
            result = await tool.run(session, include_screenshot=False)

        assert result["total_nodes"] == 3
        assert result["interactive_nodes"] == 2
        assert result["returned_elements"] == 3
        assert result["elements"][1]["resource_id"] == "com.example.test:id/username"
        assert result["elements"][2]["bounds_rect"]["center_y"] == 460
        assert session.metadata["ui_state"]["dump_path"] == result["dump_path"]


class TestUiActionTool:
    @pytest.mark.asyncio
    async def test_tap_uses_element_id_from_last_ui_state(self, tmp_path):
        from mcp_server.tools.dynamic.ui import UiActionTool

        session = make_session(tmp_path)
        session.metadata["ui_state"] = {
            "elements": [
                {
                    "element_id": "node_0002",
                    "resource_id": "com.example.test:id/login",
                    "text": "Sign in",
                    "bounds_rect": {
                        "center_x": 540,
                        "center_y": 460,
                    },
                }
            ]
        }
        tool = UiActionTool()

        run_local_mock = AsyncMock(return_value=("", "", 0))

        with patch("mcp_server.tools.dynamic.ui.run_local", run_local_mock):
            result = await tool.run(
                session,
                action="tap",
                element_id="node_0002",
                capture_ui_after=False,
                include_screenshot=False,
                post_action_wait_ms=0,
            )

        assert result["executed"] is True
        assert result["target"]["x"] == 540
        assert run_local_mock.await_args_list[0].args[0] == [
            "adb",
            "-s",
            "android:5555",
            "shell",
            "input",
            "tap",
            "540",
            "460",
        ]


class TestWaitForUiTool:
    @pytest.mark.asyncio
    async def test_waits_until_selector_is_present(self, tmp_path):
        from mcp_server.tools.dynamic.ui import WaitForUiTool

        session = make_session(tmp_path)
        tool = WaitForUiTool()
        xml_dumps = [
            """<?xml version="1.0" encoding="UTF-8"?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.example.test" content-desc="" clickable="false" long-clickable="false" checkable="false" checked="false" enabled="true" focusable="false" focused="false" scrollable="false" selected="false" visible-to-user="true" bounds="[0,0][1080,1920]" />
</hierarchy>
""",
            """<?xml version="1.0" encoding="UTF-8"?>
<hierarchy rotation="0">
  <node index="0" text="Welcome back" resource-id="com.example.test:id/title" class="android.widget.TextView" package="com.example.test" content-desc="" clickable="false" long-clickable="false" checkable="false" checked="false" enabled="true" focusable="false" focused="false" scrollable="false" selected="false" visible-to-user="true" bounds="[0,0][1080,200]" />
</hierarchy>
""",
        ]
        pull_count = {"value": 0}

        async def run_local_side_effect(command, timeout=300, cwd=None, keep_stdin_open=False, stdin_data=None):
            if command[:5] == ["adb", "-s", "android:5555", "shell", "uiautomator"]:
                return (f"UI hierchary dumped to: {command[-1]}", "", 0)
            if command[:4] == ["adb", "-s", "android:5555", "pull"] and command[4] == "/sdcard/window_dump.xml":
                xml_dump = xml_dumps[min(pull_count["value"], len(xml_dumps) - 1)]
                pull_count["value"] += 1
                _write_file(command[5], xml_dump)
                return ("1 file pulled", "", 0)
            raise AssertionError(f"Unexpected command: {command}")

        with patch("mcp_server.tools.dynamic.ui.run_local", AsyncMock(side_effect=run_local_side_effect)):
            result = await tool.run(
                session,
                text="welcome",
                timeout_seconds=2,
                poll_interval_ms=0,
                include_screenshot=False,
            )

        assert result["matched"] is True
        assert result["attempts"] == 2
        assert result["matched_elements"][0]["text"] == "Welcome back"
