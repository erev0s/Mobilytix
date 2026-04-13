"""Curated Frida script assets used by dynamic analysis tools."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

from mcp_server.models.session import AnalysisSession
from mcp_server.tools.workspace import (
    ensure_session_workspace as _ensure_session_workspace,
)
from mcp_server.tools.workspace import (
    session_workspace as _session_workspace,
)


def load_asset(filename: str) -> str:
    """Load a bundled Frida script asset from this package."""
    return resources.files(__name__).joinpath(filename).read_text(encoding="utf-8")


def session_workspace(session: AnalysisSession) -> Path:
    """Return the workspace directory for a session."""
    return _session_workspace(session)


def session_script_path(session: AnalysisSession, filename: str) -> Path:
    """Return a writable script path inside the session workspace."""
    return _ensure_session_workspace(session) / filename


def write_session_script(session: AnalysisSession, filename: str, contents: str) -> Path:
    """Write a script into the session workspace and return the path."""
    path = session_script_path(session, filename)
    path.write_text(contents, encoding="utf-8")
    return path
