"""Tests for SessionManager."""

import json

import pytest

from mcp_server.models.enums import AnalysisPhase, FindingCategory, Severity
from mcp_server.models.finding import Finding
from mcp_server.session_manager import SessionManager


@pytest.fixture
def manager():
    return SessionManager()


def test_create_session(manager):
    session = manager.create_session("/tmp/test.apk")
    assert session.apk_path == "/tmp/test.apk"
    assert session.id is not None
    assert len(session.id) > 0


def test_get_session(manager):
    session = manager.create_session("/tmp/test.apk")
    retrieved = manager.get_session(session.id)
    assert retrieved.id == session.id


def test_get_nonexistent_session(manager):
    with pytest.raises(KeyError):
        manager.get_session("does-not-exist")


def test_list_sessions_empty(manager):
    assert manager.list_sessions() == []


def test_list_sessions(manager):
    s1 = manager.create_session("/tmp/a.apk")
    s2 = manager.create_session("/tmp/b.apk")
    sessions = manager.list_sessions()
    assert len(sessions) == 2
    ids = {s.id for s in sessions}
    assert s1.id in ids
    assert s2.id in ids


def test_delete_session(manager):
    session = manager.create_session("/tmp/test.apk")
    assert manager.has_session(session.id)
    manager.delete_session(session.id)
    assert not manager.has_session(session.id)


def test_delete_nonexistent_session(manager):
    with pytest.raises(KeyError):
        manager.delete_session("does-not-exist")


def test_has_session(manager):
    session = manager.create_session("/tmp/test.apk")
    assert manager.has_session(session.id)
    assert not manager.has_session("nope")


def test_session_metadata(manager):
    session = manager.create_session("/tmp/test.apk")
    assert session.metadata == {}
    session.metadata["key"] = "value"
    retrieved = manager.get_session(session.id)
    assert retrieved.metadata["key"] == "value"


def test_session_findings(manager):
    from mcp_server.models.finding import Finding
    from mcp_server.models.enums import Severity, FindingCategory

    session = manager.create_session("/tmp/test.apk")
    finding = Finding(
        title="Test Finding",
        severity=Severity.HIGH,
        category=FindingCategory.CONFIGURATION_ISSUE,
        description="A test finding",
        evidence="test evidence",
        location="AndroidManifest.xml",
    )
    session.add_finding(finding)
    assert len(session.findings) == 1
    assert session.findings[0].title == "Test Finding"


def test_session_tool_calls(manager):
    session = manager.create_session("/tmp/test.apk")
    session.record_tool_call("get_manifest")
    session.record_tool_call("decompile_apk")
    assert "get_manifest" in session.tools_called
    assert "decompile_apk" in session.tools_called
    assert len(session.tools_called) == 2


def test_session_summary(manager):
    session = manager.create_session("/tmp/test.apk")
    session.package_name = "com.example.test"
    session.app_name = "Test App"
    summary = session.to_summary_dict()
    assert summary["package_name"] == "com.example.test"
    assert summary["app_name"] == "Test App"


def test_save_and_rehydrate_static_route_metadata(tmp_path):
    session_dir = tmp_path / "session1"
    session_dir.mkdir()
    (session_dir / "app.apk").write_bytes(b"fake apk")

    manager = SessionManager()
    session = manager.create_session(str(session_dir / "app.apk"), session_id="session1")
    session.workspace_dir = str(session_dir)
    session.metadata["apk_hash"] = "abc123"
    session.metadata["artifact_index"] = {"counts": {"js_bundle": 1}}
    session.metadata["static_route"] = {"route_key": "react_native_plain_js"}

    manager.save_session_meta(session)

    meta_path = session_dir / "session.json"
    with open(meta_path) as f:
        saved = json.load(f)

    assert saved["artifact_index"]["counts"]["js_bundle"] == 1
    assert saved["static_route"]["route_key"] == "react_native_plain_js"

    rehydrated = SessionManager._rehydrate_session(
        "session1",
        str(session_dir),
        str(session_dir / "app.apk"),
    )

    assert rehydrated is not None
    assert rehydrated.metadata["artifact_index"]["counts"]["js_bundle"] == 1
    assert rehydrated.metadata["static_route"]["route_key"] == "react_native_plain_js"


def test_save_and_rehydrate_findings_and_tool_history(tmp_path):
    session_dir = tmp_path / "session2"
    session_dir.mkdir()
    (session_dir / "app.apk").write_bytes(b"fake apk")

    manager = SessionManager()
    session = manager.create_session(str(session_dir / "app.apk"), session_id="session2")
    session.workspace_dir = str(session_dir)
    session.metadata["apk_hash"] = "def456"
    session.current_phase = AnalysisPhase.STATIC
    session.record_tool_call("get_manifest")
    session.record_tool_call("check_manifest_security")
    session.add_finding(
        Finding(
            title="Exported component",
            severity=Severity.HIGH,
            category=FindingCategory.EXPORTED_COMPONENT,
            description="Component is exported without permission",
            evidence="android:exported=\"true\"",
            location="AndroidManifest.xml (.MainActivity)",
            tool="check_manifest_security",
        )
    )

    manager.save_session_meta(session)

    rehydrated = SessionManager._rehydrate_session(
        "session2",
        str(session_dir),
        str(session_dir / "app.apk"),
    )

    assert rehydrated is not None
    assert rehydrated.current_phase.value == "static"
    assert rehydrated.tools_called == ["get_manifest", "check_manifest_security"]
    assert len(rehydrated.findings) == 1
    assert rehydrated.findings[0].title == "Exported component"
    assert rehydrated.findings[0].tool == "check_manifest_security"
