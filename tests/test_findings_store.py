"""Tests for findings_store module."""

import pytest

from mcp_server.findings_store import FindingsStore
from mcp_server.models.finding import Finding
from mcp_server.models.enums import Severity, FindingCategory
from mcp_server.models.session import AnalysisSession
from mcp_server.session_manager import SessionManager


@pytest.fixture
def session():
    mgr = SessionManager()
    s = mgr.create_session("/tmp/test.apk")
    s.package_name = "com.example.test"
    s.app_name = "Test App"
    return s


@pytest.fixture
def store():
    return FindingsStore()


def _make_finding(title="Test", severity=Severity.HIGH, category=FindingCategory.CONFIGURATION_ISSUE):
    return Finding(
        title=title,
        severity=severity,
        category=category,
        description=f"Description for {title}",
        evidence="Some evidence",
        location="AndroidManifest.xml",
        tool="test_tool",
    )


def test_add_finding(store, session):
    finding = _make_finding()
    store.add_finding(session, finding)
    assert len(session.findings) == 1


def test_get_findings_all(store, session):
    store.add_finding(session, _make_finding("A", Severity.HIGH))
    store.add_finding(session, _make_finding("B", Severity.LOW))
    findings = store.get_findings(session)
    assert len(findings) == 2


def test_get_findings_by_severity(store, session):
    store.add_finding(session, _make_finding("high", Severity.HIGH))
    store.add_finding(session, _make_finding("low", Severity.LOW))
    findings = store.get_findings(session, severity=Severity.HIGH)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_get_findings_by_category(store, session):
    store.add_finding(session, _make_finding("config", Severity.HIGH, FindingCategory.CONFIGURATION_ISSUE))
    store.add_finding(session, _make_finding("crypto", Severity.MEDIUM, FindingCategory.WEAK_CRYPTOGRAPHY))
    findings = store.get_findings(session, category=FindingCategory.WEAK_CRYPTOGRAPHY)
    assert len(findings) == 1


def test_get_summary(store, session):
    store.add_finding(session, _make_finding("A", Severity.CRITICAL))
    store.add_finding(session, _make_finding("B", Severity.HIGH))
    store.add_finding(session, _make_finding("C", Severity.HIGH))
    store.add_finding(session, _make_finding("D", Severity.LOW))

    summary = store.get_summary(session)
    assert summary["total_findings"] == 4
    assert summary["by_severity"]["critical"] == 1
    assert summary["by_severity"]["high"] == 2
    assert summary["by_severity"]["low"] == 1


def test_generate_report(store, session):
    store.add_finding(session, _make_finding("SQL Injection", Severity.CRITICAL, FindingCategory.CODE_INJECTION))
    store.add_finding(session, _make_finding("Debug Mode", Severity.HIGH, FindingCategory.CONFIGURATION_ISSUE))

    report = store.generate_markdown_report(session)
    assert "# Mobilytix Security Assessment Report" in report
    assert "SQL Injection" in report
    assert "Debug Mode" in report
    assert "com.example.test" in report
