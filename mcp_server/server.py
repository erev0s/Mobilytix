"""Mobilytix MCP Server — entrypoint.

Exposes all Mobilytix tools over the Model Context Protocol. Supports
stdio and Streamable HTTP transports. Start with:

    python -m mcp_server          # stdio (pipe, for Claude Desktop)
    python -m mcp_server --http   # Streamable HTTP (default inside Docker)
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

from loguru import logger
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp import types

from mcp_server.config import config
from mcp_server.session_manager import SessionManager
from mcp_server.findings_store import FindingsStore
from mcp_server.tools.registry import get_registry
from mcp_server.tools.workspace import workspace_root

# ---------------------------------------------------------------------------
# Configure logging
# ---------------------------------------------------------------------------
logger.remove()  # Remove default handler
logger.add(
    sys.stderr,
    level=config.platform.log_level,
    format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
)

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
session_manager = SessionManager()
findings_store = FindingsStore()

# ---------------------------------------------------------------------------
# Create MCP Server
# ---------------------------------------------------------------------------
server = Server("Mobilytix", version="0.1.0")


def _get_session(session_id: str | None):
    """Helper to retrieve session, returning None if not provided."""
    if not session_id:
        return None
    try:
        return session_manager.get_session(session_id)
    except KeyError:
        return None


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """Return all registered tools in MCP format."""
    registry = get_registry()
    tools = []
    for tool_dict in registry.list_tools():
        tools.append(
            types.Tool(
                name=tool_dict["name"],
                description=tool_dict["description"],
                inputSchema=tool_dict["inputSchema"],
            )
        )
    logger.debug("list_tools: returning {} tools", len(tools))
    return tools


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict[str, Any] | None) -> list[types.TextContent]:
    """Route a tool call to the correct handler."""
    arguments = arguments or {}
    logger.info("call_tool: {} with args {}", name, list(arguments.keys()))

    registry = get_registry()

    # Extract session_id from arguments
    session_id = arguments.pop("session_id", None)

    # Tools that don't need a session
    if name in ("create_session", "list_inbox", "list_sessions", "prune_session"):
        session = None
    else:
        if session_id:
            try:
                session = session_manager.get_session(session_id)
            except KeyError:
                return [
                    types.TextContent(
                        type="text",
                        text=json.dumps({
                            "error": f"Session not found: {session_id}",
                            "hint": "Create a session first with create_session tool",
                        }),
                    )
                ]
        else:
            # Try to use the most recent session
            sessions = session_manager.list_sessions()
            if sessions:
                session = sessions[-1]
                logger.debug("No session_id provided, using most recent: {}", session.id)
            else:
                return [
                    types.TextContent(
                        type="text",
                        text=json.dumps({
                            "error": "No active session. Create one first with create_session.",
                        }),
                    )
                ]

    # Call the tool
    result = await registry.call_tool(name, session, **arguments)

    # Serialize result to JSON
    result_text = json.dumps(result, indent=2, default=str)

    return [types.TextContent(type="text", text=result_text)]


# ---------------------------------------------------------------------------
# MCP Prompts — give AI clients automatic instructions
# ---------------------------------------------------------------------------

_PROMPT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "prompts",
    "pentest_system_prompt.txt",
)
# Also check container path for Docker deployments
if not os.path.exists(_PROMPT_PATH):
    _PROMPT_PATH = "/app/prompts/pentest_system_prompt.txt"


@server.list_prompts()
async def handle_list_prompts() -> list[types.Prompt]:
    return [
        types.Prompt(
            name="mobilytix-guide",
            description=(
                "Android penetration testing guide. Provides step-by-step "
                "methodology and explains how to use all Mobilytix tools."
            ),
        ),
    ]


@server.get_prompt()
async def handle_get_prompt(name: str, arguments: dict | None) -> types.GetPromptResult:
    if name != "mobilytix-guide":
        raise ValueError(f"Unknown prompt: {name}")

    # Load the system prompt
    prompt_text = (
        "You are connected to Mobilytix, an Android penetration testing platform.\n"
        "All tools run INSIDE a Docker container. File paths are container-internal.\n\n"
        "HOW TO START:\n"
        "1. Call list_inbox to see which APKs are available\n"
        "2. Call create_session with the filename (e.g. 'app.apk')\n"
        "3. Follow the analysis phases below\n\n"
        "IMPORTANT: APK files live in /inbox/ inside the container. "
        "The user mounts a host APK folder into /inbox/. "
        "Analysis artifacts are written to /workspace and persist across "
        "container restarts when that directory is mounted. "
        "NEVER try to access host filesystem paths like /home/... — "
        "always use list_inbox to discover files.\n\n"
    )
    if os.path.exists(_PROMPT_PATH):
        with open(_PROMPT_PATH) as f:
            prompt_text += f.read()

    return types.GetPromptResult(
        messages=[
            types.PromptMessage(
                role="user",
                content=types.TextContent(type="text", text=prompt_text),
            )
        ]
    )


# ---------------------------------------------------------------------------
# Register all tools at import time
# ---------------------------------------------------------------------------
def _register_all_tools() -> None:
    """Import and register all tool modules."""
    registry = get_registry()

    # Import tool modules — each module registers its tools
    try:
        from mcp_server.tools.static.manifest import (
            ListInboxTool,
            CreateSessionTool,
            GetApkMetadataTool,
            GetManifestTool,
            ListExportedComponentsTool,
            CheckManifestSecurityTool,
        )

        registry.register(ListInboxTool())
        registry.register(CreateSessionTool(session_manager))
        registry.register(GetApkMetadataTool())
        registry.register(GetManifestTool())
        registry.register(ListExportedComponentsTool())
        registry.register(CheckManifestSecurityTool())
        logger.info("Registered manifest/recon tools")
    except ImportError as e:
        logger.debug("Manifest tools not yet available: {}", e)

    try:
        from mcp_server.tools.session_tools import (
            ListSessionsTool,
            PruneSessionTool,
        )

        registry.register(ListSessionsTool(session_manager))
        registry.register(PruneSessionTool(session_manager))
        logger.info("Registered session management tools")
    except ImportError as e:
        logger.debug("Manifest tools not yet available: {}", e)

    try:
        from mcp_server.tools.static.framework import DetectFrameworkTool

        registry.register(DetectFrameworkTool())
        logger.info("Registered framework detection tool")
    except ImportError as e:
        logger.debug("Framework detection tool not yet available: {}", e)

    try:
        from mcp_server.tools.static.tampering import CheckApkTamperingTool

        registry.register(CheckApkTamperingTool())
        logger.info("Registered APK tampering detection tool")
    except ImportError as e:
        logger.debug("APK tampering detection tool not yet available: {}", e)

    try:
        from mcp_server.tools.static.artifacts import (
            PlanStaticAnalysisTool,
            ListStaticArtifactsTool,
            SearchStaticArtifactsTool,
            ReadStaticArtifactTool,
        )

        registry.register(PlanStaticAnalysisTool())
        registry.register(ListStaticArtifactsTool())
        registry.register(SearchStaticArtifactsTool())
        registry.register(ReadStaticArtifactTool())
        logger.info("Registered framework-aware static routing tools")
    except ImportError as e:
        logger.debug("Framework-aware static routing tools not yet available: {}", e)

    try:
        from mcp_server.tools.static.code import (
            DecompileApkTool,
            SearchSourceTool,
            ReadSourceFileTool,
            GetClassListTool,
            AnalyzeClassTool,
        )

        registry.register(DecompileApkTool())
        registry.register(SearchSourceTool())
        registry.register(ReadSourceFileTool())
        registry.register(GetClassListTool())
        registry.register(AnalyzeClassTool())
        logger.info("Registered code analysis tools")
    except ImportError as e:
        logger.debug("Code analysis tools not yet available: {}", e)

    try:
        from mcp_server.tools.static.security_overview import GetSecurityOverviewTool

        registry.register(GetSecurityOverviewTool())
        logger.info("Registered security overview tool")
    except ImportError as e:
        logger.debug("Security overview tool not yet available: {}", e)

    try:
        from mcp_server.tools.static.secrets import ScanSecretsTool

        registry.register(ScanSecretsTool())
        logger.info("Registered secrets tools")
    except ImportError as e:
        logger.debug("Secrets tools not yet available: {}", e)

    try:
        from mcp_server.tools.static.sast import RunSastTool

        registry.register(RunSastTool())
        logger.info("Registered SAST tools")
    except ImportError as e:
        logger.debug("SAST tools not yet available: {}", e)

    try:
        from mcp_server.tools.static.crypto import (
            AnalyzeCertificateTool,
            FindCryptoIssuesTool,
        )

        registry.register(AnalyzeCertificateTool())
        registry.register(FindCryptoIssuesTool())
        logger.info("Registered crypto tools")
    except ImportError as e:
        logger.debug("Crypto tools not yet available: {}", e)

    try:
        from mcp_server.tools.static.native import (
            ListNativeLibsTool,
            AnalyzeNativeStringsTool,
            AnalyzeNativeBinaryTool,
            DisassembleNativeFunctionTool,
            DecompileNativeFunctionTool,
        )

        registry.register(ListNativeLibsTool())
        registry.register(AnalyzeNativeStringsTool())
        registry.register(AnalyzeNativeBinaryTool())
        registry.register(DisassembleNativeFunctionTool())
        registry.register(DecompileNativeFunctionTool())
        logger.info("Registered native analysis tools")
    except ImportError as e:
        logger.debug("Native analysis tools not yet available: {}", e)

    try:
        from mcp_server.tools.static.flutter import AnalyzeFlutterAotTool, AnalyzeFlutterDebugTool

        registry.register(AnalyzeFlutterAotTool())
        registry.register(AnalyzeFlutterDebugTool())
        logger.info("Registered Flutter analysis tools (AOT + debug)")
    except ImportError as e:
        logger.debug("Flutter analysis tools not yet available: {}", e)

    try:
        from mcp_server.tools.static.react_native import AnalyzeReactNativeBundleTool

        registry.register(AnalyzeReactNativeBundleTool())
        logger.info("Registered React Native bundle analysis tool")
    except ImportError as e:
        logger.debug("React Native bundle analysis tool not yet available: {}", e)

    try:
        from mcp_server.tools.static.web_hybrid import AnalyzeWebHybridTool

        registry.register(AnalyzeWebHybridTool())
        logger.info("Registered web-hybrid bridge analysis tool")
    except ImportError as e:
        logger.debug("Web-hybrid bridge analysis tool not yet available: {}", e)

    try:
        from mcp_server.tools.static.dotnet import AnalyzeManagedAssembliesTool

        registry.register(AnalyzeManagedAssembliesTool())
        logger.info("Registered managed assembly analysis tool")
    except ImportError as e:
        logger.debug("Managed assembly analysis tool not yet available: {}", e)

    try:
        from mcp_server.tools.static.unity import AnalyzeUnityMetadataTool

        registry.register(AnalyzeUnityMetadataTool())
        logger.info("Registered Unity IL2CPP metadata analysis tool")
    except ImportError as e:
        logger.debug("Unity IL2CPP metadata analysis tool not yet available: {}", e)

    # ------------------------------------------------------------------
    # Dynamic analysis tools
    # ------------------------------------------------------------------
    try:
        from mcp_server.tools.dynamic.device import (
            StartDynamicSessionTool,
            EnsureFridaServerTool,
            InstallApkTool,
            LaunchAppTool,
            StopAppTool,
            GetLogcatTool,
            ListRunningProcessesTool,
            TakeScreenshotTool,
        )

        registry.register(StartDynamicSessionTool())
        registry.register(EnsureFridaServerTool())
        registry.register(InstallApkTool())
        registry.register(LaunchAppTool())
        registry.register(StopAppTool())
        registry.register(GetLogcatTool())
        registry.register(ListRunningProcessesTool())
        registry.register(TakeScreenshotTool())
        logger.info("Registered device/dynamic tools")
    except ImportError as e:
        logger.debug("Device tools not yet available: {}", e)

    try:
        from mcp_server.tools.dynamic.ui import (
            InspectUiTool,
            UiActionTool,
            WaitForUiTool,
        )

        registry.register(InspectUiTool())
        registry.register(UiActionTool())
        registry.register(WaitForUiTool())
        logger.info("Registered UI interaction tools")
    except ImportError as e:
        logger.debug("UI interaction tools not yet available: {}", e)

    try:
        from mcp_server.tools.dynamic.frida_tools import (
            ListLoadedClassesTool,
            RunFridaScriptTool,
            RunFridaCodeshareScriptTool,
        )

        registry.register(ListLoadedClassesTool())
        registry.register(RunFridaScriptTool())
        registry.register(RunFridaCodeshareScriptTool())
        logger.info("Registered Frida/instrumentation tools")
    except ImportError as e:
        logger.debug("Frida tools not yet available: {}", e)

    try:
        from mcp_server.tools.dynamic.traffic import (
            StartTrafficCaptureTool,
            StopTrafficCaptureTool,
            GetCapturedRequestsTool,
            GetCapturedFlowBodyTool,
            FindSensitiveTrafficTool,
        )

        registry.register(StartTrafficCaptureTool())
        registry.register(StopTrafficCaptureTool())
        registry.register(GetCapturedRequestsTool())
        registry.register(GetCapturedFlowBodyTool())
        registry.register(FindSensitiveTrafficTool())
        logger.info("Registered traffic analysis tools")
    except ImportError as e:
        logger.debug("Traffic tools not yet available: {}", e)

    try:
        from mcp_server.tools.dynamic.storage import (
            PullAppDataTool,
            ReadSharedPreferencesTool,
            QueryAppDatabaseTool,
            ListAppFilesTool,
        )

        registry.register(PullAppDataTool())
        registry.register(ReadSharedPreferencesTool())
        registry.register(QueryAppDatabaseTool())
        registry.register(ListAppFilesTool())
        logger.info("Registered storage analysis tools")
    except ImportError as e:
        logger.debug("Storage tools not yet available: {}", e)

    # ------------------------------------------------------------------
    # Findings management tools (always available)
    # ------------------------------------------------------------------
    try:
        from mcp_server.tools.findings_management import (
            AddFindingTool,
            ListFindingsTool,
            GetFindingsSummaryTool,
            GenerateReportTool,
            GetAnalysisStatusTool,
        )

        registry.register(AddFindingTool())
        registry.register(ListFindingsTool())
        registry.register(GetFindingsSummaryTool())
        registry.register(GenerateReportTool(findings_store))
        registry.register(GetAnalysisStatusTool())
        logger.info("Registered findings management tools")
    except ImportError as e:
        logger.debug("Findings management tools not yet available: {}", e)

    logger.info(
        "Tool registration complete: {} tools available",
        len(registry.list_tool_names()),
    )


# ---------------------------------------------------------------------------
# Server runner
# ---------------------------------------------------------------------------
async def run_stdio() -> None:
    """Run the MCP server over stdio transport."""
    _register_all_tools()

    # Discover existing sessions from workspace on disk
    workspace_dir = str(workspace_root())
    n = session_manager.discover_sessions(workspace_dir)
    if n:
        logger.info("Recovered {} prior sessions from {}", n, workspace_dir)

    logger.info("Starting Mobilytix MCP server (stdio transport)")

    async with stdio_server() as (read_stream, write_stream):
        init_options = server.create_initialization_options()
        await server.run(read_stream, write_stream, init_options)


async def run_http() -> None:
    """Run the MCP server over Streamable HTTP transport.

    Exposes:
      /mcp     — Streamable HTTP endpoint (POST/GET/DELETE)
      /health  — health check
    """
    try:
        from starlette.applications import Starlette
        from starlette.middleware.cors import CORSMiddleware
        from starlette.routing import Route, Mount
        from starlette.responses import JSONResponse
        import uvicorn
    except ImportError:
        logger.error(
            "HTTP transport requires 'starlette' and 'uvicorn'. "
            "Install with: pip install starlette uvicorn"
        )
        sys.exit(1)

    _register_all_tools()

    # Discover existing sessions from workspace on disk
    workspace_dir = str(workspace_root())
    n = session_manager.discover_sessions(workspace_dir)
    if n:
        logger.info("Recovered {} prior sessions from {}", n, workspace_dir)

    import contextlib

    stateless = os.environ.get("MOBILYTIX_STATELESS", "true").lower() == "true"
    session_mgr = StreamableHTTPSessionManager(
        app=server,
        stateless=stateless,
    )

    @contextlib.asynccontextmanager
    async def lifespan(app):
        async with session_mgr.run():
            yield

    async def health(request):
        return JSONResponse({"status": "ok", "tools": len(get_registry().list_tool_names())})

    app = Starlette(
        debug=False,
        lifespan=lifespan,
        routes=[
            Route("/health", health),
            Mount("/mcp", app=session_mgr.handle_request),
        ],
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )

    host = os.environ.get("MOBILYTIX_HOST", config.mcp.host)
    port = int(os.environ.get("MOBILYTIX_PORT", config.mcp.port))

    logger.info("Starting Mobilytix MCP server (HTTP) on http://{}:{}", host, port)
    logger.info("  MCP endpoint:  http://{}:{}/mcp", host, port)
    logger.info("  Health check:  http://{}:{}/health", host, port)

    uvicorn_config = uvicorn.Config(
        app, host=host, port=port, log_level="warning"
    )
    uv_server = uvicorn.Server(uvicorn_config)
    await uv_server.serve()


def main() -> None:
    """Main entry point.

    Uses HTTP by default when MOBILYTIX_TRANSPORT=http or config says so,
    or when --http flag is passed. Falls back to stdio otherwise.
    """
    use_http = (
        "--http" in sys.argv
        or os.environ.get("MOBILYTIX_TRANSPORT", "").lower() == "http"
        or config.mcp.transport == "http"
    )
    if use_http:
        asyncio.run(run_http())
    else:
        asyncio.run(run_stdio())


if __name__ == "__main__":
    main()
