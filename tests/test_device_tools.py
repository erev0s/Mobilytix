"""Tests for Android device lifecycle tools."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from mcp_server.session_manager import SessionManager


def make_session(tmp_path: Path):
    mgr = SessionManager()
    session = mgr.create_session("/tmp/test.apk")
    session.package_name = "com.example.test"
    workspace = tmp_path / session.id
    workspace.mkdir(parents=True, exist_ok=True)
    session.workspace_dir = str(workspace)
    return session


class TestStartDynamicSessionTool:
    @pytest.mark.asyncio
    async def test_configures_frida_bridge(self, tmp_path):
        from mcp_server.tools.dynamic.device import StartDynamicSessionTool

        session = make_session(tmp_path)
        tool = StartDynamicSessionTool()

        run_local_mock = AsyncMock(
            side_effect=[
                ("connected to android:5555", "", 0),
                ("connected to android:5555", "", 0),
                ("1", "", 0),
                ("13", "", 0),
                ("", "", 0),
                ("", "", 0),
                ("", "", 0),
            ]
        )

        with (
            patch("mcp_server.tools.dynamic.device.run_local", run_local_mock),
            patch(
                "mcp_server.tools.dynamic.device.ensure_frida_server_running",
                AsyncMock(return_value={"running": True, "already_running": True, "remote_path": "/data/local/tmp/frida-server"}),
            ),
        ):
            result = await tool.run(session)

        assert result["ready"] is True
        assert result["proxy_configured"] is False
        assert result["https_interception_ready"] is False
        assert result["frida_server_running"] is True
        assert result["frida_bridge_configured"] is True
        assert result["frida_endpoint"] == "127.0.0.1:27042"
        assert result["drozer_bridge_configured"] is True
        assert result["drozer_endpoint"] == "127.0.0.1:31415"
        assert session.device_id == "android:5555"
        assert session.current_phase.value == "dynamic_setup"

        forward_cmd = run_local_mock.await_args_list[5].args[0]
        assert forward_cmd[:4] == ["adb", "-s", "android:5555", "forward"]
        assert "tcp:27042" in forward_cmd

        drozer_forward_cmd = run_local_mock.await_args_list[6].args[0]
        assert drozer_forward_cmd[:4] == ["adb", "-s", "android:5555", "forward"]
        assert "tcp:31415" in drozer_forward_cmd


class TestEnsureFridaServerTool:
    @pytest.mark.asyncio
    async def test_starts_remote_frida_server_when_binary_exists(self, tmp_path):
        from mcp_server.tools.dynamic.device import EnsureFridaServerTool

        session = make_session(tmp_path)
        session.device_id = "android:5555"
        tool = EnsureFridaServerTool()

        run_local_mock = AsyncMock(
            side_effect=[
                ("/data/local/tmp/frida-server\n", "", 0),
                ("", "", 0),
            ]
        )

        with (
            patch("mcp_server.tools.dynamic.device.run_local", run_local_mock),
            patch(
                "mcp_server.tools.dynamic.device._probe_frida_server_status",
                AsyncMock(
                    side_effect=[
                        {"process_running": False, "port_listening": False, "port": 27042},
                        {"process_running": True, "port_listening": True, "port": 27042, "pid_hint": "1234"},
                        {"process_running": True, "port_listening": True, "port": 27042, "pid_hint": "1234"},
                        {"process_running": True, "port_listening": True, "port": 27042, "pid_hint": "1234"},
                    ]
                ),
            ),
            patch(
                "mcp_server.tools.dynamic.device._is_frida_bridge_reachable",
                AsyncMock(return_value=(True, None)),
            ),
        ):
            result = await tool.run(session)

        assert result["running"] is True
        assert result["already_running"] is False
        assert result["start_method"] == "direct"
        assert result["process_running"] is True
        assert result["port_listening"] is True
        assert result["bridge_reachable"] is True
        assert session.metadata["frida_server"]["running"] is True

    @pytest.mark.asyncio
    async def test_accepts_bridge_when_port_probe_is_false_negative(self, tmp_path):
        from mcp_server.tools.dynamic.device import EnsureFridaServerTool

        session = make_session(tmp_path)
        session.device_id = "android:5555"
        tool = EnsureFridaServerTool()

        run_local_mock = AsyncMock(
            side_effect=[
                ("/data/local/tmp/frida-server\n", "", 0),
                ("", "", 0),
            ]
        )

        with (
            patch("mcp_server.tools.dynamic.device.run_local", run_local_mock),
            patch(
                "mcp_server.tools.dynamic.device._probe_frida_server_status",
                AsyncMock(
                    side_effect=[
                        {"process_running": False, "port_listening": False, "port": 27042},
                        {"process_running": True, "port_listening": False, "port": 27042, "pid_hint": "3147"},
                        {"process_running": True, "port_listening": False, "port": 27042, "pid_hint": "3147"},
                        {"process_running": True, "port_listening": False, "port": 27042, "pid_hint": "3147"},
                    ]
                ),
            ),
            patch(
                "mcp_server.tools.dynamic.device._is_frida_bridge_reachable",
                AsyncMock(
                    side_effect=[
                        (True, None),
                        (True, None),
                    ]
                ),
            ),
        ):
            result = await tool.run(session)

        assert result["running"] is True
        assert result["already_running"] is False
        assert result["start_method"] == "direct"
        assert result["process_running"] is True
        assert result["port_listening"] is False
        assert result["bridge_reachable"] is True
        assert result["pid_hint"] == "3147"


class TestLaunchAppTool:
    @pytest.mark.asyncio
    async def test_sets_runtime_phase_on_success(self, tmp_path):
        from mcp_server.tools.dynamic.device import LaunchAppTool

        session = make_session(tmp_path)
        session.device_id = "android:5555"
        tool = LaunchAppTool()

        run_local_mock = AsyncMock(return_value=("Starting: Intent { ... }", "", 0))

        with patch("mcp_server.tools.dynamic.device.run_local", run_local_mock):
            result = await tool.run(session)

        assert result["launched"] is True
        assert session.current_phase.value == "runtime"


class TestPullAppDataTool:
    @pytest.mark.asyncio
    async def test_fails_when_app_data_cannot_be_pulled(self, tmp_path):
        from mcp_server.tools.dynamic.storage import PullAppDataTool

        session = make_session(tmp_path)
        session.device_id = "android:5555"
        tool = PullAppDataTool()

        run_local_mock = AsyncMock(
            side_effect=[
                ("", "", 0),
                ("", "run-as package not debuggable", 1),
                ("", "adb: error: failed to stat remote object", 1),
            ]
        )

        with patch("mcp_server.tools.dynamic.storage.run_local", run_local_mock):
            result = await tool.run(session)

        assert "error" in result
        assert "Could not pull app data" in result["error"]
        assert session.current_phase.value != "storage"
        assert "app_data_path" not in session.metadata
