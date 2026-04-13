"""Base tool abstract class for all Mobilytix tools.

Every tool in the system inherits from BaseTool. This provides a consistent
interface for tool registration, schema generation, and execution.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from loguru import logger

from mcp_server.models.session import AnalysisSession
from mcp_server.session_manager import SessionManager


class BaseTool(ABC):
    """Abstract base class for all Mobilytix tools.

    Subclasses must define:
      - name: str — unique tool identifier
      - description: str — human-readable description (also used as MCP description)
      - run() — async method that executes the tool
      - input_schema() — JSON Schema for the tool's inputs
    """

    name: str = ""
    description: str = ""

    @abstractmethod
    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        """Execute the tool and return structured results.

        Args:
            session: The active analysis session (None for session-creation tools).
            **kwargs: Tool-specific arguments matching input_schema().

        Returns:
            A dict with structured results. On error, returns
            {"error": "...", "details": "..."} instead of raising.
        """

    def input_schema(self) -> dict:
        """Return JSON Schema for this tool's inputs.

        Override in subclasses to define tool-specific parameters.
        The base schema requires only session_id.
        """
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                }
            },
            "required": ["session_id"],
        }

    def to_mcp_tool(self) -> dict:
        """Convert this tool to the MCP tool list format."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema(),
        }

    async def safe_run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        """Execute run() with error handling — never raises to MCP layer."""
        try:
            result = await self.run(session, **kwargs)
            # Record tool usage and persist session state to disk
            if session is not None:
                session.record_tool_call(self.name)
                SessionManager.save_session_meta(session)
            return result
        except Exception as e:
            logger.exception("Tool {} failed: {}", self.name, e)
            return {
                "error": f"Tool '{self.name}' failed",
                "details": str(e),
                "tool": self.name,
            }
