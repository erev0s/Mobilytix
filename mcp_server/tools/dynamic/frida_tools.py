"""Frida runtime analysis tools.

Provides class enumeration plus generic Frida script execution helpers.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Optional

from loguru import logger

from mcp_server.backends.local_backend import run_local
from mcp_server.config import config
from mcp_server.models.enums import AnalysisPhase
from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool
from mcp_server.tools.dynamic.frida_scripts import load_asset, write_session_script

FRIDA_ENDPOINT = f"127.0.0.1:{config.docker.frida_port}"
MAX_RAW_OUTPUT_CHARS = 12000


def _frida_command(
    target: str,
    *,
    mode: str,
    script_path: str | None = None,
    extra_args: list[str] | None = None,
) -> list[str]:
    """Build a Frida CLI command."""
    if mode == "pid":
        attach_flag = "-p"
    elif mode == "identifier":
        attach_flag = "-N"
    elif mode == "name":
        attach_flag = "-n"
    elif mode == "spawn":
        attach_flag = "-f"
    else:
        raise ValueError(f"Unsupported Frida mode: {mode}")

    command = ["frida", "-H", FRIDA_ENDPOINT]
    if script_path:
        command.extend(["-l", script_path])
    command.append("-q")
    if extra_args:
        command.extend(extra_args)
    command.extend([attach_flag, target])
    return command


def _parse_frida_messages(output: str) -> list[Any]:
    """Parse Frida CLI output into structured messages when possible."""
    import ast

    messages: list[Any] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        candidates = [stripped]
        if stripped.startswith("message:"):
            payload = stripped[len("message:"):].strip()
            if " data:" in payload:
                payload = payload.split(" data:", 1)[0].strip()
            if payload:
                candidates.insert(0, payload)

        parsed = False
        for candidate in candidates:
            try:
                value = json.loads(candidate)
                messages.append(value.get("payload", value) if isinstance(value, dict) else value)
                parsed = True
                break
            except json.JSONDecodeError:
                pass

            try:
                value = ast.literal_eval(candidate)
                messages.append(value.get("payload", value) if isinstance(value, dict) else value)
                parsed = True
                break
            except (ValueError, SyntaxError):
                pass

        if not parsed:
            messages.append(stripped)

    return messages


def _combine_frida_output(stdout: str, stderr: str) -> str:
    """Combine stdout/stderr so structured Frida output is not lost."""
    return "\n".join(
        chunk.strip()
        for chunk in (stdout, stderr)
        if chunk and chunk.strip()
    )


def _frida_process_hint(
    output: str,
    *,
    spawn: bool,
    process_name: str | None = None,
) -> str | None:
    """Return a hint for common Frida process lookup failures."""
    lowered = output.lower()
    if "unable to find process" not in lowered and "failed to spawn" not in lowered:
        return None

    if spawn:
        return (
            "Frida could not attach after launching the app. Verify the package "
            "name is correct and the process stays alive."
        )

    if process_name:
        return (
            f"Frida could not attach to process '{process_name}'. Retry with "
            "spawn=true or confirm the process name matches the running app."
        )

    return (
        "Frida could not find the running process. Retry with spawn=true or "
        "provide process_name if the app uses a custom process name."
    )


def _frida_timed_out(rc: int, output: str) -> bool:
    """Return whether a Frida command hit the wrapper timeout."""
    return rc == -1 and "command timed out" in output.lower()


def _filter_timeout_messages(messages: list[Any]) -> list[Any]:
    """Remove wrapper timeout diagnostics from parsed Frida output."""
    filtered: list[Any] = []
    for message in messages:
        if isinstance(message, str) and "command timed out after" in message.lower():
            continue
        filtered.append(message)
    return filtered


def _require_frida_session(session: Optional[AnalysisSession]) -> dict | None:
    """Return an error if the Android/Frida bridge has not been initialized."""
    if session is None:
        return {"error": "No active session"}

    if not session.device_id:
        return {
            "error": (
                "No Android device is connected. Run start_dynamic_session "
                "first; if you are attaching to a live app, run launch_app too."
            )
        }

    return None


def _is_missing_process(output: str) -> bool:
    """Return whether Frida reported a missing process lookup."""
    lowered = output.lower()
    return (
        "unable to find process" in lowered
        or "failed to attach" in lowered
        or "failed to spawn" in lowered
    )


async def _adb_pidof(session: AnalysisSession, process_name: str) -> str:
    """Return the process PID if running on the device."""
    stdout, _, _ = await run_local(
        [
            "adb",
            "-s",
            session.device_id or "android:5555",
            "shell",
            "pidof",
            "-s",
            process_name,
        ],
        timeout=10,
    )
    return stdout.strip()


async def _frida_target_is_alive(session: AnalysisSession, package: str) -> bool:
    """Return whether the app process is running on the device."""
    pid = await _adb_pidof(session, package)
    return bool(pid)


async def _adb_launch_app(
    session: AnalysisSession,
    package: str,
    max_wait: int = 15,
) -> bool:
    """Launch the app via Android's launcher intent and wait for it to run."""
    device_id = session.device_id or "android:5555"
    await run_local(
        [
            "adb",
            "-s",
            device_id,
            "shell",
            "monkey",
            "-p",
            package,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        ],
        timeout=15,
    )

    for _ in range(max_wait * 2):
        await asyncio.sleep(0.5)
        if await _frida_target_is_alive(session, package):
            return True

    return False


async def _execute_frida_capture(
    session: AnalysisSession,
    *,
    package: str,
    process_name: str,
    spawn: bool,
    timeout: int,
    script_path: str | None = None,
    extra_args: list[str] | None = None,
    stdin_data: str | None = None,
) -> dict[str, Any]:
    """Run a Frida capture using the same attach/launch flow as class listing."""
    target = process_name or package
    attach_mode = "name" if process_name else "identifier"

    attempts: list[dict[str, Any]] = []
    outputs: list[str] = []

    def _append_attempt(mode_name: str, attempt_target: str) -> None:
        attempts.append({"mode": mode_name, "target": attempt_target})

    _append_attempt(f"attach_{attach_mode}", target)

    stdout, stderr, rc = await run_local(
        _frida_command(
            target,
            mode=attach_mode,
            script_path=script_path,
            extra_args=extra_args,
        ),
        timeout=timeout,
        keep_stdin_open=True,
        stdin_data=stdin_data,
    )
    output = _combine_frida_output(stdout, stderr)
    outputs.append(output)
    timed_out = _frida_timed_out(rc, output)

    if rc != 0 and _is_missing_process(output):
        pid = await _adb_pidof(session, target)
        if pid:
            _append_attempt("attach_pid", pid)
            stdout, stderr, rc = await run_local(
                _frida_command(
                    pid,
                    mode="pid",
                    script_path=script_path,
                    extra_args=extra_args,
                ),
                timeout=timeout,
                keep_stdin_open=True,
                stdin_data=stdin_data,
            )
            pid_output = _combine_frida_output(stdout, stderr)
            outputs.append(pid_output)
            timed_out = timed_out or _frida_timed_out(rc, pid_output)
            output = "\n".join(chunk for chunk in outputs if chunk.strip())

    if spawn and rc != 0 and _is_missing_process(output):
        if not process_name:
            _append_attempt("spawn", package)
            stdout, stderr, rc = await run_local(
                _frida_command(
                    package,
                    mode="spawn",
                    script_path=script_path,
                    extra_args=extra_args,
                ),
                timeout=timeout,
                keep_stdin_open=True,
                stdin_data=stdin_data,
            )
            spawn_output = _combine_frida_output(stdout, stderr)
            outputs.append(spawn_output)
            timed_out = timed_out or _frida_timed_out(rc, spawn_output)
            output = "\n".join(chunk for chunk in outputs if chunk.strip())
        else:
            logger.info("Process {} was not running; launching {} via adb", target, package)
            _append_attempt("launch_app", package)
            launched = await _adb_launch_app(session, package)
            if not launched:
                hint = _frida_process_hint(
                    output,
                    spawn=spawn,
                    process_name=process_name or None,
                )
                result = {
                    "error": (
                        f"Could not launch {package}. Verify it is installed and "
                        "the device is connected."
                    ),
                    "mode": "spawn",
                    "target": target,
                    "exit_code": rc,
                    "attempts": attempts,
                    "messages": [],
                    "raw_output": output[:MAX_RAW_OUTPUT_CHARS],
                    "combined_output": output,
                    "capture_window_seconds": timeout,
                }
                if hint:
                    result["hint"] = hint
                return result

            relaunch_pid = await _adb_pidof(session, target)
            relaunch_mode = "pid" if relaunch_pid else attach_mode
            relaunch_target = relaunch_pid or target
            _append_attempt(f"attach_{relaunch_mode}_after_launch", relaunch_target)

            stdout, stderr, rc = await run_local(
                _frida_command(
                    relaunch_target,
                    mode=relaunch_mode,
                    script_path=script_path,
                    extra_args=extra_args,
                ),
                timeout=timeout,
                keep_stdin_open=True,
                stdin_data=stdin_data,
            )
            attach_output = _combine_frida_output(stdout, stderr)
            outputs.append(attach_output)
            timed_out = timed_out or _frida_timed_out(rc, attach_output)
            output = "\n".join(chunk for chunk in outputs if chunk.strip())

    messages = _filter_timeout_messages(_parse_frida_messages(output))
    hint = _frida_process_hint(output, spawn=spawn, process_name=process_name or None)

    result: dict[str, Any] = {
        "mode": "spawn" if spawn else "attach",
        "target": target,
        "exit_code": rc,
        "attempts": attempts,
        "messages": messages,
        "raw_output": output[:MAX_RAW_OUTPUT_CHARS],
        "combined_output": output,
        "capture_window_seconds": timeout,
    }
    if timed_out:
        result["timed_out"] = True
    if hint:
        result["hint"] = hint
    if rc != 0 and not output.strip():
        result["error"] = (
            "Frida execution failed with no output. Verify the app is running "
            "and frida-server is reachable."
        )
    return result


def _build_generic_runner_result(
    execution: dict[str, Any],
    *,
    max_messages: int,
    extra_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a stable result shape for generic Frida script runners."""
    messages = execution.get("messages", [])
    returned_messages = messages if max_messages == 0 else messages[:max_messages]

    result: dict[str, Any] = {
        "message_count": len(messages),
        "returned_messages": len(returned_messages),
        "messages": returned_messages,
        "truncated": max_messages != 0 and len(messages) > max_messages,
        "mode": execution["mode"],
        "target": execution["target"],
        "exit_code": execution["exit_code"],
        "capture_window_seconds": execution["capture_window_seconds"],
        "attempts": execution["attempts"],
        "raw_output": execution["raw_output"],
    }
    if execution.get("timed_out"):
        result["timed_out"] = True
    if execution.get("hint"):
        result["hint"] = execution["hint"]
    if execution.get("error"):
        result["error"] = execution["error"]
    if extra_fields:
        result.update(extra_fields)
    return result


class ListLoadedClassesTool(BaseTool):
    """List classes loaded by the running app using Frida."""

    name = "list_loaded_classes"
    description = (
        "Enumerate all classes loaded in the app's runtime using Frida. "
        "Optionally filter by pattern. Use process_name when the app runs "
        "under a custom process name, or spawn=true if it is not already "
        "running. The caller can choose how long to monitor before returning."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "filter_pattern": {
                    "type": "string",
                    "description": "Filter classes by substring (e.g. 'com.example')",
                },
                "process_name": {
                    "type": "string",
                    "description": (
                        "Optional process name to attach to when the running "
                        "process does not match the package name"
                    ),
                },
                "spawn": {
                    "type": "boolean",
                    "description": (
                        "Launch the app first if it is not already running, "
                        "then attach and collect classes"
                    ),
                    "default": False,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": (
                        "Number of seconds to monitor Frida output before "
                        "returning the collected class list"
                    ),
                    "default": 10,
                },
                "max_results": {
                    "type": "integer",
                    "description": (
                        "Maximum number of classes to return. Use 0 to return "
                        "every parsed class."
                    ),
                    "default": 1000,
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        preflight = _require_frida_session(session)
        if preflight:
            return preflight

        package = session.package_name
        if not package:
            return {"error": "Package name unknown."}

        filter_pattern = kwargs.get("filter_pattern", "")
        process_name = kwargs.get("process_name")
        if process_name is not None and not isinstance(process_name, str):
            return {"error": "process_name must be a string."}
        process_name = process_name.strip() if isinstance(process_name, str) else ""

        spawn = bool(kwargs.get("spawn", False))
        timeout = int(kwargs.get("timeout_seconds", 10))
        if timeout <= 0:
            return {"error": "timeout_seconds must be greater than 0."}

        max_results = int(kwargs.get("max_results", 1000))
        if max_results < 0:
            return {"error": "max_results must be 0 or greater."}

        script_path = write_session_script(
            session,
            "list_loaded_classes.js",
            load_asset("list_loaded_classes.js"),
        )
        execution = await _execute_frida_capture(
            session,
            package=package,
            process_name=process_name,
            spawn=spawn,
            timeout=timeout,
            script_path=str(script_path),
        )

        def _package_from_name(name: str) -> str:
            return name.rsplit(".", 1)[0] if "." in name else ""

        def _extract_classes(output: str) -> list[dict[str, str]]:
            classes: list[dict[str, str]] = []
            seen: set[str] = set()

            for message in _filter_timeout_messages(_parse_frida_messages(output)):
                if not isinstance(message, dict):
                    continue

                if message.get("type") not in {"classes", "classes_chunk", "loaded_classes"}:
                    continue

                raw_classes = message.get("classes")
                if not isinstance(raw_classes, list):
                    continue

                for entry in raw_classes:
                    if isinstance(entry, str):
                        name = entry
                        package_name = _package_from_name(name)
                    elif isinstance(entry, dict):
                        raw_name = entry.get("name")
                        if not isinstance(raw_name, str) or not raw_name:
                            continue
                        name = raw_name
                        raw_package = entry.get("package")
                        package_name = (
                            raw_package
                            if isinstance(raw_package, str)
                            else _package_from_name(name)
                        )
                    else:
                        continue

                    if name in seen:
                        continue

                    seen.add(name)
                    classes.append({"name": name, "package": package_name})

            return classes

        class_records = _extract_classes(execution["combined_output"])
        if filter_pattern:
            class_records = [
                entry
                for entry in class_records
                if filter_pattern.lower() in entry["name"].lower()
            ]

        if not class_records:
            result = {
                "error": (
                    "Frida did not return a parsed class list. Verify the app "
                    "is running and Frida is attached."
                ),
                "raw_output": execution["raw_output"],
                "attempts": execution["attempts"],
            }
            if execution.get("hint"):
                result["hint"] = execution["hint"]
            return result

        limited_records = class_records if max_results == 0 else class_records[:max_results]
        session.current_phase = AnalysisPhase.RUNTIME

        result = {
            "total_classes": len(class_records),
            "returned_classes": len(limited_records),
            "classes": [entry["name"] for entry in limited_records],
            "class_records": limited_records,
            "truncated": max_results != 0 and len(class_records) > max_results,
            "filter": filter_pattern or None,
            "capture_window_seconds": timeout,
            "attempts": execution["attempts"],
        }
        if execution.get("timed_out"):
            result["timed_out"] = True
        return result


class RunFridaScriptTool(BaseTool):
    """Run a custom Frida JavaScript script against the target app."""

    name = "run_frida_script"
    description = (
        "Run a custom Frida JavaScript instrumentation script and return the "
        "messages it emits during the requested capture window. Uses the same "
        "attach/launch flow as list_loaded_classes."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "script": {
                    "type": "string",
                    "description": "Frida JavaScript code to inject",
                },
                "process_name": {
                    "type": "string",
                    "description": (
                        "Optional process name to attach to when the running "
                        "process does not match the package name"
                    ),
                },
                "spawn": {
                    "type": "boolean",
                    "description": (
                        "Launch the app first if it is not already running, "
                        "then attach and run the script"
                    ),
                    "default": False,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": (
                        "Number of seconds to monitor Frida output before "
                        "returning the collected messages"
                    ),
                    "default": 10,
                },
                "max_messages": {
                    "type": "integer",
                    "description": (
                        "Maximum number of messages to return. Use 0 to return "
                        "every parsed message."
                    ),
                    "default": 200,
                },
            },
            "required": ["session_id", "script"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        preflight = _require_frida_session(session)
        if preflight:
            return preflight

        package = session.package_name
        if not package:
            return {"error": "Package name unknown."}

        script = kwargs.get("script")
        if not isinstance(script, str) or not script.strip():
            return {"error": "script must be a non-empty string."}

        process_name = kwargs.get("process_name")
        if process_name is not None and not isinstance(process_name, str):
            return {"error": "process_name must be a string."}
        process_name = process_name.strip() if isinstance(process_name, str) else ""

        spawn = bool(kwargs.get("spawn", False))
        timeout = int(kwargs.get("timeout_seconds", 10))
        if timeout <= 0:
            return {"error": "timeout_seconds must be greater than 0."}

        max_messages = int(kwargs.get("max_messages", 200))
        if max_messages < 0:
            return {"error": "max_messages must be 0 or greater."}

        script_path = write_session_script(
            session,
            "custom_frida.js",
            script,
        )
        execution = await _execute_frida_capture(
            session,
            package=package,
            process_name=process_name,
            spawn=spawn,
            timeout=timeout,
            script_path=str(script_path),
        )

        if execution.get("messages") or execution.get("exit_code") == 0 or execution.get("timed_out"):
            session.current_phase = AnalysisPhase.RUNTIME

        return _build_generic_runner_result(
            execution,
            max_messages=max_messages,
            extra_fields={"script_name": "custom_frida.js"},
        )


class RunFridaCodeshareScriptTool(BaseTool):
    """Run a Frida CodeShare script against the target app."""

    name = "run_frida_codeshare_script"
    description = (
        "Run a Frida CodeShare script and return the messages it emits during "
        "the requested capture window. Uses the same attach/launch flow as "
        "list_loaded_classes."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "codeshare_slug": {
                    "type": "string",
                    "description": (
                        "Frida CodeShare slug, for example "
                        "'pcipolloni/universal-android-ssl-pinning-bypass-with-frida'"
                    ),
                },
                "process_name": {
                    "type": "string",
                    "description": (
                        "Optional process name to attach to when the running "
                        "process does not match the package name"
                    ),
                },
                "spawn": {
                    "type": "boolean",
                    "description": (
                        "Launch the app first if it is not already running, "
                        "then attach and run the CodeShare script"
                    ),
                    "default": False,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": (
                        "Number of seconds to monitor Frida output before "
                        "returning the collected messages"
                    ),
                    "default": 10,
                },
                "max_messages": {
                    "type": "integer",
                    "description": (
                        "Maximum number of messages to return. Use 0 to return "
                        "every parsed message."
                    ),
                    "default": 200,
                },
            },
            "required": ["session_id", "codeshare_slug"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        preflight = _require_frida_session(session)
        if preflight:
            return preflight

        package = session.package_name
        if not package:
            return {"error": "Package name unknown."}

        codeshare_slug = kwargs.get("codeshare_slug")
        if not isinstance(codeshare_slug, str) or not codeshare_slug.strip():
            return {"error": "codeshare_slug must be a non-empty string."}
        codeshare_slug = codeshare_slug.strip()
        if "/" not in codeshare_slug:
            return {"error": "codeshare_slug must look like 'user/project'."}

        process_name = kwargs.get("process_name")
        if process_name is not None and not isinstance(process_name, str):
            return {"error": "process_name must be a string."}
        process_name = process_name.strip() if isinstance(process_name, str) else ""

        spawn = bool(kwargs.get("spawn", False))
        timeout = int(kwargs.get("timeout_seconds", 10))
        if timeout <= 0:
            return {"error": "timeout_seconds must be greater than 0."}

        max_messages = int(kwargs.get("max_messages", 200))
        if max_messages < 0:
            return {"error": "max_messages must be 0 or greater."}

        execution = await _execute_frida_capture(
            session,
            package=package,
            process_name=process_name,
            spawn=spawn,
            timeout=timeout,
            extra_args=["--codeshare", codeshare_slug],
            stdin_data="y\n",
        )

        if execution.get("messages") or execution.get("exit_code") == 0 or execution.get("timed_out"):
            session.current_phase = AnalysisPhase.RUNTIME

        return _build_generic_runner_result(
            execution,
            max_messages=max_messages,
            extra_fields={"codeshare_slug": codeshare_slug},
        )
