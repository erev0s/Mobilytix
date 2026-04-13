"""Shared workspace helpers for session-scoped analysis artifacts."""

from __future__ import annotations

from pathlib import Path

from mcp_server.config import config, ensure_workspace_dir
from mcp_server.models.session import AnalysisSession


def workspace_root() -> Path:
    """Return the configured workspace root for the current runtime."""
    root = ensure_workspace_dir(config.platform.workspace_dir)
    config.platform.workspace_dir = str(root)
    return root


def workspace_for_session_id(session_id: str) -> Path:
    """Return the workspace path for a session ID."""
    return workspace_root() / session_id


def session_workspace(session: AnalysisSession) -> Path:
    """Return the workspace path for a session, preferring the saved path."""
    if session.workspace_dir:
        return Path(session.workspace_dir)
    return workspace_for_session_id(session.id)


def ensure_session_workspace(session: AnalysisSession) -> Path:
    """Ensure the session workspace exists and return it."""
    path = session_workspace(session)
    path.mkdir(parents=True, exist_ok=True)
    return path


def session_artifact_path(session: AnalysisSession, *parts: str) -> Path:
    """Return a path under the session workspace."""
    return session_workspace(session).joinpath(*parts)


def ensure_session_artifact_path(session: AnalysisSession, *parts: str) -> Path:
    """Ensure the session workspace exists and return a path under it."""
    path = session_artifact_path(session, *parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path
