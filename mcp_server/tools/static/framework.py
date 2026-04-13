"""Framework detection tool for framework-aware static analysis routing."""

from __future__ import annotations

import os
import zipfile
from typing import Any, Optional

from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool
from mcp_server.tools.static.routing import detect_framework
from mcp_server.tools.workspace import session_workspace


class DetectFrameworkTool(BaseTool):
    """Detect the development framework and dominant code container for an APK."""

    name = "detect_framework"
    description = (
        "Detect which framework was used to build the APK and where the meaningful logic most likely lives. "
        "Returns framework metadata, dominant code containers, format hints, support level, and artifact roots. "
        "Call this immediately after create_session."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session. Call create_session first."}

        apk_path = f"{session_workspace(session)}/app.apk"
        if not os.path.isfile(apk_path):
            return {"error": f"APK not found at {apk_path}"}

        try:
            detected = detect_framework(apk_path)
        except (zipfile.BadZipFile, ValueError) as exc:
            return {"error": f"File is not a valid APK/ZIP: {exc}"}

        session.metadata["framework"] = detected
        return detected

