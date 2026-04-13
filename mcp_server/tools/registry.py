"""Tool registry — registration and routing of all Mobilytix tools.

Tools are registered at import time and routed by name from the MCP server.
"""

from __future__ import annotations

from typing import Optional

from loguru import logger

from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool


class ToolRegistry:
    """Central registry for all available tools."""

    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        """Register a tool instance."""
        if tool.name in self._tools:
            logger.warning("Tool '{}' already registered, overwriting", tool.name)
        self._tools[tool.name] = tool
        logger.debug("Registered tool: {}", tool.name)

    def get(self, name: str) -> Optional[BaseTool]:
        """Get a tool by name."""
        return self._tools.get(name)

    def list_tools(self) -> list[dict]:
        """Return all tools in MCP format."""
        return [tool.to_mcp_tool() for tool in self._tools.values()]

    def list_tool_names(self) -> list[str]:
        """Return all registered tool names."""
        return list(self._tools.keys())

    async def call_tool(
        self,
        name: str,
        session: Optional[AnalysisSession],
        **kwargs,
    ) -> dict:
        """Route a tool call to the correct handler.

        Args:
            name: Tool name.
            session: Active session (None for create_session).
            **kwargs: Tool-specific arguments.

        Returns:
            Tool result dict, or error dict if tool not found.
        """
        tool = self.get(name)
        if tool is None:
            return {
                "error": f"Unknown tool: {name}",
                "available_tools": self.list_tool_names(),
            }
        return await tool.safe_run(session, **kwargs)


# Global registry instance
registry = ToolRegistry()


def get_registry() -> ToolRegistry:
    """Return the global tool registry."""
    return registry
