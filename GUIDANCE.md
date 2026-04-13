# Mobilytix — Project Guidance

## What Is This

Mobilytix is an **AI-native Android penetration testing platform** implemented as an **MCP (Model Context Protocol) server**. It wraps professional mobile security tools (jadx, apktool, androguard, Frida, mitmproxy, drozer, etc.) behind 63 MCP tool definitions so an MCP-capable client can assist with authorized Android pentests by chaining structured tool calls.

**Core idea**: The LLM never talks to tools directly — it always goes through the MCP server, which manages sessions, routes tool calls, accumulates findings, and generates reports.

---

## Architecture Overview

```
LLM Client (Claude Desktop / Cursor / custom)
    │  MCP protocol (STDIO or Streamable HTTP)
    ▼
Mobilytix MCP Server (Python, async)
    ├── Session Manager     — per-APK session lifecycle, dedup by SHA256
    ├── Tool Registry       — 63 tools, routed via BaseTool ABC
    ├── Findings Store      — accumulate vulns, generate reports
    └── Device Backend      — abstraction over Docker/physical device
         │
    ┌────┴────────────────────────┐
    │                             │
    ▼                             ▼
Static Analysis Container    Android Container + mitmproxy
(jadx, apktool, semgrep,    (emulator w/ KVM, Frida,
 apkleaks, androguard,       adb, drozer)
 ripgrep)
```

All three Docker services communicate over a custom bridge network (`mobilytix`).

---

## Key Directories

| Path | Purpose |
|------|---------|
| `Mobilytix/mcp_server/server.py` | MCP server entrypoint, registers all 63 tools |
| `Mobilytix/mcp_server/tools/static/` | Static analysis tools: manifest, artifacts, routing, code, framework, tampering, secrets, sast, crypto, native, Flutter, React Native, web-hybrid, .NET, Unity, security overview |
| `Mobilytix/mcp_server/tools/dynamic/` | Dynamic analysis tools: device, UI, Frida, traffic, storage |
| `Mobilytix/mcp_server/tools/base.py` | `BaseTool` ABC — all tools inherit this |
| `Mobilytix/mcp_server/tools/registry.py` | `ToolRegistry` — registration + routing |
| `Mobilytix/mcp_server/models/` | `AnalysisSession`, `Finding`, enums (Severity, FindingCategory, AnalysisPhase) |
| `Mobilytix/mcp_server/session_manager.py` | Session CRUD, APK hash dedup, workspace discovery |
| `Mobilytix/mcp_server/findings_store.py` | Findings accumulation, querying, markdown report generation |
| `Mobilytix/mcp_server/backends/` | `DeviceBackend` ABC + local/docker/physical backends |
| `Mobilytix/mcp_server/config.py` | YAML config loader |
| `Mobilytix/config/config.yaml` | Runtime config (transport, Docker settings, workspace path) |
| `Mobilytix/prompts/pentest_system_prompt.txt` | 7-phase methodology guide provided to LLMs |
| `Mobilytix/docker/` | docker-compose.yml + Dockerfiles for static/android containers |
| `Mobilytix/mcp_server.py` | Thin wrapper for MCP clients (`from mcp_server.server import main`) |

---

## The 63 Tools (by category)

### Session Management (5)
`list_inbox`, `create_session`, `get_analysis_status`, `list_sessions`, `prune_session`

### Recon & Manifest (7)
`detect_framework`, `check_apk_tampering`, `plan_static_analysis`, `get_apk_metadata`, `get_manifest`, `list_exported_components`, `check_manifest_security`

### Framework Artifacts (9)
`list_static_artifacts`, `search_static_artifacts`, `read_static_artifact`, `analyze_flutter_aot`, `analyze_flutter_debug`, `analyze_react_native_bundle`, `analyze_web_hybrid`, `analyze_managed_assemblies`, `analyze_unity_metadata`

### Code Analysis (6)
`decompile_apk`, `search_source`, `read_source_file`, `get_class_list`, `analyze_class`, `get_security_overview`

### Security Intelligence (4)
`scan_secrets`, `run_sast`, `analyze_certificate`, `find_crypto_issues`

### Native Code (5)
`list_native_libs`, `analyze_native_strings`, `analyze_native_binary`, `disassemble_native_function`, `decompile_native_function`

### Dynamic — Device (8)
`start_dynamic_session`, `ensure_frida_server`, `install_apk`, `launch_app`, `stop_app`, `get_logcat`, `list_running_processes`, `take_screenshot`

### Dynamic — UI (3)
`inspect_ui`, `ui_action`, `wait_for_ui`

### Dynamic — Frida (3)
`list_loaded_classes`, `run_frida_script`, `run_frida_codeshare_script`

### Traffic (5)
`start_traffic_capture`, `stop_traffic_capture`, `get_captured_requests`, `get_captured_flow_body`, `find_sensitive_traffic`

### Storage (4)
`pull_app_data`, `read_shared_preferences`, `query_app_database`, `list_app_files`

### Findings & Reporting (4)
`add_finding`, `list_findings`, `get_findings_summary`, `generate_report`

---

## How Connection Works

### STDIO (default — for Claude Desktop, Cursor)
- Client launches `python -m mcp_server` as a subprocess
- Communication over stdin/stdout using MCP JSON-RPC
- Config in `~/.config/claude/claude_desktop_config.json`

### Streamable HTTP (for Docker deployment)
- Source default listens on `127.0.0.1:3000`
- Docker runtime listens on `0.0.0.0` inside the container but publishes to `127.0.0.1:3000` on the host
- `/mcp` — Streamable HTTP endpoint (POST/GET/DELETE), `GET /health` — healthcheck
- Activated via `--http` flag or `MOBILYTIX_TRANSPORT=http`

### MCP Handlers
- `@server.list_tools()` — returns all 63 tools with JSON schemas
- `@server.call_tool()` — routes to `registry.call_tool()` → `tool.safe_run()`
- `@server.list_prompts()` / `@server.get_prompt()` — provides the pentest methodology guide

---

## Tool Execution Flow

```
Client calls tool(name, {session_id, ...})
  → server.call_tool() extracts session_id, looks up session
  → registry.call_tool(name, session, **kwargs)
  → tool.safe_run(session, **kwargs)  # wraps run() with error handling
  → tool.run(session, **kwargs)       # actual implementation
  → returns dict result (never raises to MCP layer)
```

All tools inherit `BaseTool` and implement `run()` + `input_schema()`. The `safe_run()` wrapper catches exceptions, logs them, records tool usage on the session, and returns error dicts.

---

## Session & Workspace Model

Each APK analysis is an `AnalysisSession` with:
- Unique ID (short UUID), APK path, package name
- `workspace_dir` at `/workspace/<session_id>/`
- Deduplication by SHA256 hash (same APK resumes existing session)
- Findings list, metadata dict, tools_called list
- Current `AnalysisPhase` (RECON → STATIC → ... → REPORTING)

Workspace layout:
```
/workspace/<session_id>/
├── app.apk, decoded/, decompiled/
├── session.json (persisted metadata)
├── apkleaks_output.json, semgrep_output.json
├── traffic_*.flow, logcat_*.txt
```

---

## Pentest Methodology (7 phases)

The LLM is guided through these phases by `prompts/pentest_system_prompt.txt`:

1. **Phase 0 — Framework Detection**: `detect_framework` + `check_apk_tampering` (critical — changes entire strategy for Flutter/RN/etc.)
2. **Phase 1 — Recon**: manifest, metadata, exported components
3. **Phase 2 — Static**: decompile, secrets scan, SAST, crypto analysis
4. **Phase 3 — Manual**: read source files, trace data flows, follow up on findings
5. **Phase 4 — Dynamic**: emulator setup, Frida scripting, UI interaction
6. **Phase 5 — Data & Traffic**: storage inspection, traffic capture
7. **Phase 6 — Reporting**: `generate_report()` produces markdown pentest report

---

## Running the Project

```bash
# Local (STDIO for Claude Desktop)
cd Mobilytix && python -m mcp_server

# Docker (full stack with emulator)
docker compose -f docker/docker-compose.yml up -d

# HTTP mode
python -m mcp_server --http
# or: MOBILYTIX_TRANSPORT=http python -m mcp_server
```

---

## Tech Stack

- **Language**: Python 3.11+ (async throughout)
- **MCP SDK**: `mcp>=1.0.0`
- **Key deps**: androguard, apkInspector, pydantic, loguru, aiofiles, starlette, uvicorn
- **External tools** (in Docker): jadx, apktool, aapt2, apksigner, apkleaks, semgrep, ripgrep, Frida, drozer, mitmproxy, adb
- **License**: Apache-2.0

---

## Design Principles

- **Local-first**: everything in Docker, no cloud dependency
- **Model-agnostic**: any MCP client can drive it
- **Tool-agnostic**: add tools by implementing `BaseTool` + registering
- **Error-resilient**: tools never crash the server; errors become structured dicts
- **Session-oriented**: isolated workspace per APK with finding accumulation

---

## Contributor Notes

- Tool failures must return structured dicts — never raise from `run()`. Use `{"error": "..."}`.
- `start_dynamic_session` sets up the Frida bridge on `127.0.0.1:27042`; Frida tools fail fast if `session.device_id` is missing.
- Traffic interception still needs more engineering for repeatable HTTPS interception, proxy state handling, and apps with certificate pinning or custom trust logic.
- iOS analysis is future work; current runtime and benchmark coverage are Android-focused.
- Session state is fully persisted in `session.json` and rehydrated on server restart.
- Run `pytest` from the repo root to execute the test suite.
- Check `git status` before editing to avoid overwriting unrelated in-progress work.

---

## Adding New Tools

Every tool in Mobilytix is a Python class that:

1. Extends `BaseTool` from `mcp_server/tools/base.py`
2. Defines a `name`, `description`, and `input_schema()`
3. Implements an async `run()` method
4. Gets registered in `server.py`

The MCP server exposes these tools to any connected LLM.

### Step-by-step Example

Let's add a hypothetical tool that checks for insecure WebView configurations.

#### 1. Create the tool class

Create or edit a file in `mcp_server/tools/static/` (for static analysis) or
`mcp_server/tools/dynamic/` (for dynamic analysis).

```python
# mcp_server/tools/static/webview.py

from __future__ import annotations
from typing import Any, Optional

from mcp_server.backends.local_backend import run_local
from mcp_server.models.enums import AnalysisPhase, FindingCategory, Severity
from mcp_server.models.finding import Finding
from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool


class CheckWebViewTool(BaseTool):
    """Search decompiled source for insecure WebView configurations."""

    name = "check_webview"
    description = (
        "Scan decompiled source code for insecure WebView settings such as "
        "JavaScript enabled, file access, and addJavascriptInterface."
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
            return {"error": "No active session"}

        decompiled = session.metadata.get("decompiled_path")
        if not decompiled:
            return {"error": "App not decompiled yet. Run decompile_apk first."}

        stdout, stderr, rc = await run_local(
            ["rg", "--json", "setJavaScriptEnabled\\(true\\)", decompiled],
            timeout=30,
        )

        issues = []
        for line in stdout.splitlines():
            # Parse ripgrep JSON output
            issues.append({"pattern": "JavaScript enabled", "file": "..."})

        for issue in issues:
            finding = Finding(
                title=f"Insecure WebView: {issue['pattern']}",
                severity=Severity.MEDIUM,
                category=FindingCategory.CODE_VULNERABILITY,
                description="...",
                evidence="...",
                tool="check_webview",
                phase=AnalysisPhase.CODE_ANALYSIS.value,
                cwe_id="CWE-749",
            )
            session.add_finding(finding)

        return {
            "total_issues": len(issues),
            "issues": issues,
            "findings_created": len(issues),
        }
```

#### 2. Register the tool in server.py

Edit `mcp_server/server.py` and add an import block in `_register_all_tools()`:

```python
try:
    from mcp_server.tools.static.webview import CheckWebViewTool

    registry.register(CheckWebViewTool())
    logger.info("Registered WebView analysis tools")
except ImportError as e:
    logger.debug("WebView tools not yet available: {}", e)
```

#### 3. Write a test

Create `tests/test_webview.py`:

```python
import pytest
from unittest.mock import AsyncMock, patch

from mcp_server.tools.static.webview import CheckWebViewTool
from mcp_server.session_manager import SessionManager


@pytest.fixture
def session():
    mgr = SessionManager()
    s = mgr.create_session("/tmp/test.apk")
    s.metadata["decompiled_path"] = "/workspace/test/sources"
    return s


class TestCheckWebViewTool:
    @pytest.mark.asyncio
    async def test_finds_js_enabled(self, session):
        tool = CheckWebViewTool()
        # ... mock run_local and assert findings
```

#### 4. Update Docker image (if needed)

If your tool requires a new binary, add it to the appropriate Dockerfile:
- `docker/static/Dockerfile` — for static analysis tools
- `docker/android/Dockerfile` — for dynamic analysis tools

### Guidelines

- **Never raise exceptions** — catch everything in `run()` and return `{"error": "..."}`.
- **Always return structured data** — dicts with clear keys, not raw strings.
- **Create findings inline** — don't defer finding creation to later tools.
- **Include evidence** — every finding should have concrete evidence (code, config, output).
- **Respect timeouts** — external commands should have reasonable timeout values.
- **Use `safe_run()`** — the `BaseTool.safe_run()` wrapper catches all exceptions.

### Tool Naming Conventions

- Use snake_case: `check_webview`, `scan_secrets`
- Be descriptive: `list_loaded_classes` not just `classes`
- Group related tools in the same file
