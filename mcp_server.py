#!/usr/bin/env python3
"""
Mobilytix MCP Server — Direct entry point for Cursor and other MCP clients.

This is a wrapper script that Cursor/MCP clients can execute directly.
It starts the Mobilytix MCP server on stdio.
"""

import sys
from mcp_server.server import main

if __name__ == "__main__":
    main()
