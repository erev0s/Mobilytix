"""Session management tools — list and prune analysis sessions.

These are session-free tools (they don't require an active session to run).
"""

from __future__ import annotations

import os
import shutil
from typing import Any, Optional

from loguru import logger

from mcp_server.models.session import AnalysisSession
from mcp_server.session_manager import SessionManager
from mcp_server.tools.base import BaseTool


class ListSessionsTool(BaseTool):
    """List all known analysis sessions.

    Returns a summary of every session the server is aware of (both
    in-memory and discovered from disk).
    """

    name = "list_sessions"
    description = (
        "List all analysis sessions. Shows session ID, APK hash, package "
        "name, decoded/decompiled status, and findings count for each."
    )

    def __init__(self, session_manager: SessionManager) -> None:
        self._sm = session_manager

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {}}

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        sessions = self._sm.list_sessions()
        if not sessions:
            return {
                "sessions": [],
                "count": 0,
                "hint": "No sessions found. Use create_session to start analysis.",
            }

        summaries = []
        for s in sessions:
            summaries.append(
                {
                    "session_id": s.id,
                    "apk_path": s.apk_path,
                    "apk_hash": s.metadata.get("apk_hash", "?")[:12],
                    "package_name": s.package_name or "?",
                    "app_name": s.app_name or "?",
                    "decoded": s.decoded_path is not None,
                    "decompiled": s.decompiled_path is not None,
                    "findings": len(s.findings),
                    "tools_called": len(set(s.tools_called)),
                    "workspace": s.workspace_dir,
                    "created_at": s.created_at.isoformat() if s.created_at else None,
                }
            )

        return {"sessions": summaries, "count": len(summaries)}


class PruneSessionTool(BaseTool):
    """Delete a session and all its workspace artifacts from disk.

    Use this when the user wants to start a clean analysis or free disk
    space for a previously-analyzed APK.
    """

    name = "prune_session"
    description = (
        "Delete a session and its entire workspace directory (decoded, "
        "decompiled, findings, etc.). Use list_sessions to see available "
        "session IDs. This action is irreversible."
    )

    def __init__(self, session_manager: SessionManager) -> None:
        self._sm = session_manager

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The ID of the session to prune.",
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        sid = kwargs["session_id"]

        try:
            target = self._sm.get_session(sid)
        except KeyError:
            return {"error": f"Session not found: {sid}"}

        # Delete workspace from disk
        ws = target.workspace_dir
        deleted_files = 0
        if ws and os.path.isdir(ws):
            for _root, _dirs, files in os.walk(ws):
                deleted_files += len(files)
            shutil.rmtree(ws, ignore_errors=True)

        # Remove from session manager
        self._sm.delete_session(sid)

        return {
            "pruned": sid,
            "workspace_deleted": ws or "(none)",
            "files_removed": deleted_files,
            "hint": "Session and workspace permanently deleted.",
        }
