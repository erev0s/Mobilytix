"""Tests for the remaining Frida class enumeration tool."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from mcp_server.session_manager import SessionManager


def make_session(tmp_path: Path, device_id: str | None = "android:5555"):
    mgr = SessionManager()
    session = mgr.create_session("/tmp/test.apk")
    session.package_name = "com.example.test"
    workspace = tmp_path / session.id
    workspace.mkdir(parents=True, exist_ok=True)
    session.workspace_dir = str(workspace)
    if device_id:
        session.device_id = device_id
    return session


class TestListLoadedClassesTool:
    @pytest.mark.asyncio
    async def test_uses_script_asset_and_attach_mode(self, tmp_path):
        from mcp_server.tools.dynamic.frida_tools import ListLoadedClassesTool

        session = make_session(tmp_path)
        tool = ListLoadedClassesTool()

        run_local_mock = AsyncMock(
            return_value=(
                '{"type":"classes","classes":["com.example.A","com.example.B"]}\n',
                "",
                0,
            )
        )

        with patch("mcp_server.tools.dynamic.frida_tools.run_local", run_local_mock):
            result = await tool.run(session)

        assert result["total_classes"] == 2
        assert result["returned_classes"] == 2
        assert result["classes"] == ["com.example.A", "com.example.B"]
        assert result["class_records"] == [
            {"name": "com.example.A", "package": "com.example"},
            {"name": "com.example.B", "package": "com.example"},
        ]
        assert result["attempts"] == [{"mode": "attach_identifier", "target": session.package_name}]

        cmd = run_local_mock.await_args_list[0].args[0]
        assert "-N" in cmd
        assert "-f" not in cmd
        assert session.package_name in cmd
        assert (Path(session.workspace_dir) / "list_loaded_classes.js").exists()

    @pytest.mark.asyncio
    async def test_parses_loaded_classes_records_and_timeout_window(self, tmp_path):
        from mcp_server.tools.dynamic.frida_tools import ListLoadedClassesTool

        session = make_session(tmp_path)
        tool = ListLoadedClassesTool()

        run_local_mock = AsyncMock(
            return_value=(
                '{"type":"loaded_classes","total":2,"classes":['
                '{"name":"com.example.A","package":"com.example"},'
                '{"name":"com.example.B","package":"com.example"}'
                ']}\n',
                "Command timed out after 10s",
                -1,
            )
        )

        with patch("mcp_server.tools.dynamic.frida_tools.run_local", run_local_mock):
            result = await tool.run(session, timeout_seconds=10)

        assert result["total_classes"] == 2
        assert result["returned_classes"] == 2
        assert result["classes"] == ["com.example.A", "com.example.B"]
        assert result["class_records"] == [
            {"name": "com.example.A", "package": "com.example"},
            {"name": "com.example.B", "package": "com.example"},
        ]
        assert result["capture_window_seconds"] == 10
        assert result["timed_out"] is True

    @pytest.mark.asyncio
    async def test_can_attach_to_custom_process_name(self, tmp_path):
        from mcp_server.tools.dynamic.frida_tools import ListLoadedClassesTool

        session = make_session(tmp_path)
        tool = ListLoadedClassesTool()

        run_local_mock = AsyncMock(
            return_value=(
                '{"type":"classes","classes":["com.example.A","com.example.B"]}\n',
                "",
                0,
            )
        )

        with patch("mcp_server.tools.dynamic.frida_tools.run_local", run_local_mock):
            result = await tool.run(session, process_name="com.example.test:remote")

        assert result["total_classes"] == 2
        assert result["classes"] == ["com.example.A", "com.example.B"]

        cmd = run_local_mock.await_args_list[0].args[0]
        assert "-n" in cmd
        assert "com.example.test:remote" in cmd

    @pytest.mark.asyncio
    async def test_spawn_uses_real_frida_spawn_when_package_not_running(self, tmp_path):
        from mcp_server.tools.dynamic.frida_tools import ListLoadedClassesTool

        session = make_session(tmp_path)
        tool = ListLoadedClassesTool()

        run_local_mock = AsyncMock(
            side_effect=[
                (
                    "",
                    "Failed to attach: unable to find process with identifier 'com.example.test'",
                    1,
                ),
                ('{"type":"classes","classes":["com.example.A","com.example.B"]}\n', "", 0),
            ]
        )

        with patch("mcp_server.tools.dynamic.frida_tools.run_local", run_local_mock):
            result = await tool.run(session, spawn=True)

        assert result["total_classes"] == 2
        assert result["classes"] == ["com.example.A", "com.example.B"]
        assert run_local_mock.await_count == 2
        assert result["attempts"] == [
            {"mode": "attach_identifier", "target": session.package_name},
            {"mode": "spawn", "target": session.package_name},
        ]

        first_cmd = run_local_mock.await_args_list[0].args[0]
        second_cmd = run_local_mock.await_args_list[1].args[0]

        assert "-N" in first_cmd
        assert "-f" in second_cmd

    @pytest.mark.asyncio
    async def test_falls_back_to_pid_attach_when_process_exists(self, tmp_path):
        from mcp_server.tools.dynamic.frida_tools import ListLoadedClassesTool

        session = make_session(tmp_path)
        tool = ListLoadedClassesTool()

        run_local_mock = AsyncMock(
            side_effect=[
                (
                    "",
                    "Failed to attach: unable to find process with identifier 'com.example.test'",
                    1,
                ),
                ("7308\n", "", 0),
                ('{"type":"classes","classes":["com.example.A","com.example.B"]}\n', "", 0),
            ]
        )

        with patch("mcp_server.tools.dynamic.frida_tools.run_local", run_local_mock):
            result = await tool.run(session, spawn=True)

        assert result["total_classes"] == 2
        assert result["classes"] == ["com.example.A", "com.example.B"]
        assert result["attempts"] == [
            {"mode": "attach_identifier", "target": session.package_name},
            {"mode": "attach_pid", "target": "7308"},
        ]

        first_cmd = run_local_mock.await_args_list[0].args[0]
        pidof_cmd = run_local_mock.await_args_list[1].args[0]
        second_cmd = run_local_mock.await_args_list[2].args[0]

        assert "-N" in first_cmd
        assert "pidof" in pidof_cmd
        assert "-p" in second_cmd

    @pytest.mark.asyncio
    async def test_reports_helpful_hint_when_process_is_missing(self, tmp_path):
        from mcp_server.tools.dynamic.frida_tools import ListLoadedClassesTool

        session = make_session(tmp_path)
        tool = ListLoadedClassesTool()

        run_local_mock = AsyncMock(
            return_value=(
                "",
                "Failed to attach: unable to find process with name 'com.example.test'",
                1,
            )
        )

        with patch("mcp_server.tools.dynamic.frida_tools.run_local", run_local_mock):
            result = await tool.run(session)

        assert "error" in result
        assert result["attempts"] == [{"mode": "attach_identifier", "target": session.package_name}]
        assert "hint" in result
        assert "spawn=true" in result["hint"]

    @pytest.mark.asyncio
    async def test_parses_classes_from_stderr_too(self, tmp_path):
        from mcp_server.tools.dynamic.frida_tools import ListLoadedClassesTool

        session = make_session(tmp_path)
        tool = ListLoadedClassesTool()

        run_local_mock = AsyncMock(
            return_value=(
                "",
                '{"type":"loaded_classes","total":2,"classes":['
                '{"name":"com.example.A","package":"com.example"},'
                '{"name":"com.example.B","package":"com.example"}'
                ']}\n',
                0,
            )
        )

        with patch("mcp_server.tools.dynamic.frida_tools.run_local", run_local_mock):
            result = await tool.run(session)

        assert result["total_classes"] == 2
        assert result["classes"] == ["com.example.A", "com.example.B"]

    @pytest.mark.asyncio
    async def test_can_limit_returned_results(self, tmp_path):
        from mcp_server.tools.dynamic.frida_tools import ListLoadedClassesTool

        session = make_session(tmp_path)
        tool = ListLoadedClassesTool()

        run_local_mock = AsyncMock(
            return_value=(
                '{"type":"loaded_classes","total":3,"classes":['
                '{"name":"com.example.A","package":"com.example"},'
                '{"name":"com.example.B","package":"com.example"},'
                '{"name":"com.example.C","package":"com.example"}'
                ']}\n',
                "",
                0,
            )
        )

        with patch("mcp_server.tools.dynamic.frida_tools.run_local", run_local_mock):
            result = await tool.run(session, max_results=2)

        assert result["total_classes"] == 3
        assert result["returned_classes"] == 2
        assert result["classes"] == ["com.example.A", "com.example.B"]
        assert result["truncated"] is True

    @pytest.mark.asyncio
    async def test_rejects_invalid_timeout(self, tmp_path):
        from mcp_server.tools.dynamic.frida_tools import ListLoadedClassesTool

        session = make_session(tmp_path)
        tool = ListLoadedClassesTool()

        result = await tool.run(session, timeout_seconds=0)

        assert "error" in result
        assert "greater than 0" in result["error"]

    @pytest.mark.asyncio
    async def test_rejects_invalid_max_results(self, tmp_path):
        from mcp_server.tools.dynamic.frida_tools import ListLoadedClassesTool

        session = make_session(tmp_path)
        tool = ListLoadedClassesTool()

        result = await tool.run(session, max_results=-1)

        assert "error" in result
        assert "0 or greater" in result["error"]
