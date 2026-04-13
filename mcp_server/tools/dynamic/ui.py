"""ADB-backed UI inspection and interaction tools."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Optional
import xml.etree.ElementTree as ET

from mcp_server.backends.local_backend import run_local
from mcp_server.models.enums import AnalysisPhase
from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool
from mcp_server.tools.workspace import ensure_session_artifact_path

REMOTE_UI_DUMP_PATH = "/sdcard/window_dump.xml"
REMOTE_SCREENSHOT_PATH = "/sdcard/mobilytix_ui.png"
UI_STATE_METADATA_KEY = "ui_state"
BOUNDS_RE = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")

ALLOWED_KEYEVENTS = {
    "APP_SWITCH": "187",
    "BACK": "4",
    "DEL": "67",
    "DPAD_CENTER": "23",
    "DPAD_DOWN": "20",
    "DPAD_LEFT": "21",
    "DPAD_RIGHT": "22",
    "DPAD_UP": "19",
    "ENTER": "66",
    "ESCAPE": "111",
    "HOME": "3",
    "MENU": "82",
    "SEARCH": "84",
    "SPACE": "62",
    "TAB": "61",
    "WAKEUP": "224",
}


def _session_device_id(session: Optional[AnalysisSession]) -> str | None:
    if session is None:
        return None
    return session.device_id


def _adb_prefix(device_id: str) -> list[str]:
    return ["adb", "-s", device_id]


def _artifact_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _parse_bool(value: str | None) -> bool:
    return str(value).strip().lower() == "true"


def _parse_bounds(value: str | None) -> dict[str, int] | None:
    if not value:
        return None
    match = BOUNDS_RE.fullmatch(value)
    if not match:
        return None
    left, top, right, bottom = (int(part) for part in match.groups())
    return {
        "left": left,
        "top": top,
        "right": right,
        "bottom": bottom,
        "width": max(right - left, 0),
        "height": max(bottom - top, 0),
        "center_x": left + max(right - left, 0) // 2,
        "center_y": top + max(bottom - top, 0) // 2,
    }


def _is_interactive(node: ET.Element) -> bool:
    return any(
        _parse_bool(node.attrib.get(attr))
        for attr in (
            "clickable",
            "long-clickable",
            "checkable",
            "focusable",
            "scrollable",
        )
    )


def _parse_ui_dump(
    dump_path: Path,
    *,
    interactive_only: bool = False,
    max_elements: int = 200,
) -> dict[str, Any]:
    tree = ET.parse(dump_path)
    root = tree.getroot()

    elements: list[dict[str, Any]] = []
    total_nodes = 0
    interactive_nodes = 0

    for index, node in enumerate(root.iter("node"), start=1):
        total_nodes += 1
        interactive = _is_interactive(node)
        if interactive:
            interactive_nodes += 1
        if interactive_only and not interactive:
            continue

        bounds = _parse_bounds(node.attrib.get("bounds"))
        if bounds is None:
            continue

        if len(elements) >= max_elements:
            continue

        elements.append(
            {
                "element_id": f"node_{index:04d}",
                "index": index,
                "text": node.attrib.get("text", ""),
                "content_desc": node.attrib.get("content-desc", ""),
                "resource_id": node.attrib.get("resource-id", ""),
                "class_name": node.attrib.get("class", ""),
                "package_name": node.attrib.get("package", ""),
                "clickable": _parse_bool(node.attrib.get("clickable")),
                "long_clickable": _parse_bool(node.attrib.get("long-clickable")),
                "checkable": _parse_bool(node.attrib.get("checkable")),
                "checked": _parse_bool(node.attrib.get("checked")),
                "enabled": _parse_bool(node.attrib.get("enabled")),
                "focusable": _parse_bool(node.attrib.get("focusable")),
                "focused": _parse_bool(node.attrib.get("focused")),
                "scrollable": _parse_bool(node.attrib.get("scrollable")),
                "selected": _parse_bool(node.attrib.get("selected")),
                "visible_to_user": _parse_bool(node.attrib.get("visible-to-user")),
                "interactive": interactive,
                "bounds": node.attrib.get("bounds", ""),
                "bounds_rect": bounds,
            }
        )

    return {
        "total_nodes": total_nodes,
        "interactive_nodes": interactive_nodes,
        "elements": elements,
        "elements_truncated": total_nodes > len(elements),
    }


def _normalize_text_match(value: str) -> str:
    return value.strip().lower()


def _matches_selector(element: dict[str, Any], selector: dict[str, str]) -> bool:
    text = selector.get("text")
    if text:
        combined = " ".join((element.get("text", ""), element.get("content_desc", ""))).lower()
        if _normalize_text_match(text) not in combined:
            return False

    resource_id = selector.get("resource_id")
    if resource_id and element.get("resource_id") != resource_id:
        return False

    content_desc = selector.get("content_desc")
    if content_desc and _normalize_text_match(content_desc) not in element.get("content_desc", "").lower():
        return False

    class_name = selector.get("class_name")
    if class_name and _normalize_text_match(class_name) not in element.get("class_name", "").lower():
        return False

    package_name = selector.get("package_name")
    if package_name and element.get("package_name") != package_name:
        return False

    return True


def _lookup_element(session: AnalysisSession, element_id: str) -> dict[str, Any] | None:
    ui_state = session.metadata.get(UI_STATE_METADATA_KEY, {})
    for element in ui_state.get("elements", []):
        if element.get("element_id") == element_id:
            return element
    return None


def _encode_input_text(text: str) -> str:
    if "\n" in text or "\r" in text:
        raise ValueError("Text input does not support newlines. Use keyevent ENTER instead.")

    encoded: list[str] = []
    safe_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#_+=:,./-")
    for char in text:
        if char == " ":
            encoded.append("%s")
        elif char in safe_chars:
            encoded.append(char)
        else:
            encoded.append(f"\\{char}")
    return "".join(encoded)


async def _capture_screenshot(session: AnalysisSession, device_id: str, label: str) -> dict[str, Any]:
    timestamp = _artifact_timestamp()
    local_path = ensure_session_artifact_path(session, "ui", f"{label}_{timestamp}.png")

    stdout, stderr, rc = await run_local(
        _adb_prefix(device_id) + ["shell", "screencap", "-p", REMOTE_SCREENSHOT_PATH],
        timeout=10,
    )
    if rc != 0:
        return {"error": f"Failed to capture screenshot: {stderr[:300] or stdout[:300]}"}

    stdout, stderr, rc = await run_local(
        _adb_prefix(device_id) + ["pull", REMOTE_SCREENSHOT_PATH, str(local_path)],
        timeout=15,
    )
    if rc != 0:
        return {"error": f"Failed to pull screenshot: {stderr[:300] or stdout[:300]}"}

    await run_local(_adb_prefix(device_id) + ["shell", "rm", "-f", REMOTE_SCREENSHOT_PATH], timeout=5)

    return {"screenshot_path": str(local_path)}


async def _capture_ui_state(
    session: AnalysisSession,
    *,
    include_screenshot: bool,
    interactive_only: bool,
    max_elements: int,
    label: str,
) -> dict[str, Any]:
    device_id = _session_device_id(session)
    if not device_id:
        return {"error": "No device connected. Run start_dynamic_session first."}

    timestamp = _artifact_timestamp()
    local_dump_path = ensure_session_artifact_path(session, "ui", f"{label}_{timestamp}.xml")

    stdout, stderr, rc = await run_local(
        _adb_prefix(device_id) + ["shell", "uiautomator", "dump", REMOTE_UI_DUMP_PATH],
        timeout=15,
    )
    if rc != 0:
        return {"error": f"UI dump failed: {stderr[:300] or stdout[:300]}"}

    stdout, stderr, rc = await run_local(
        _adb_prefix(device_id) + ["pull", REMOTE_UI_DUMP_PATH, str(local_dump_path)],
        timeout=15,
    )
    if rc != 0:
        return {"error": f"Failed to pull UI dump: {stderr[:300] or stdout[:300]}"}

    try:
        parsed = _parse_ui_dump(
            local_dump_path,
            interactive_only=interactive_only,
            max_elements=max_elements,
        )
    except ET.ParseError as exc:
        return {"error": f"Failed to parse UI dump XML: {exc}"}

    result: dict[str, Any] = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "dump_path": str(local_dump_path),
        "total_nodes": parsed["total_nodes"],
        "interactive_nodes": parsed["interactive_nodes"],
        "returned_elements": len(parsed["elements"]),
        "elements_truncated": parsed["elements_truncated"],
        "elements": parsed["elements"],
    }

    if include_screenshot:
        screenshot_result = await _capture_screenshot(session, device_id, label)
        if "error" in screenshot_result:
            result["screenshot_error"] = screenshot_result["error"]
        else:
            result["screenshot_path"] = screenshot_result["screenshot_path"]

    session.metadata[UI_STATE_METADATA_KEY] = result
    session.current_phase = AnalysisPhase.RUNTIME
    return result


class InspectUiTool(BaseTool):
    """Capture the current UI tree from the Android device."""

    name = "inspect_ui"
    description = (
        "Capture the current Android UI hierarchy with uiautomator and return "
        "structured elements. Optionally captures a screenshot alongside the dump."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "include_screenshot": {
                    "type": "boolean",
                    "description": "Capture a screenshot together with the UI dump.",
                    "default": True,
                },
                "interactive_only": {
                    "type": "boolean",
                    "description": "Only return interactive nodes such as buttons and fields.",
                    "default": False,
                },
                "max_elements": {
                    "type": "integer",
                    "description": "Maximum number of parsed elements to return.",
                    "default": 200,
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        return await _capture_ui_state(
            session,
            include_screenshot=kwargs.get("include_screenshot", True),
            interactive_only=kwargs.get("interactive_only", False),
            max_elements=max(1, int(kwargs.get("max_elements", 200))),
            label="inspect_ui",
        )


class UiActionTool(BaseTool):
    """Perform a constrained UI action through ADB input commands."""

    name = "ui_action"
    description = (
        "Perform a constrained UI action through adb input: tap, long_press, "
        "swipe, type_text, keyevent, back, or home. Targets can be element IDs "
        "from inspect_ui or raw coordinates."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "action": {
                    "type": "string",
                    "enum": ["tap", "long_press", "swipe", "type_text", "keyevent", "back", "home"],
                    "description": "Interaction type to perform.",
                },
                "element_id": {
                    "type": "string",
                    "description": "Element ID from the latest inspect_ui result.",
                },
                "x": {
                    "type": "integer",
                    "description": "Tap X coordinate.",
                },
                "y": {
                    "type": "integer",
                    "description": "Tap Y coordinate.",
                },
                "start_x": {
                    "type": "integer",
                    "description": "Swipe start X coordinate.",
                },
                "start_y": {
                    "type": "integer",
                    "description": "Swipe start Y coordinate.",
                },
                "end_x": {
                    "type": "integer",
                    "description": "Swipe end X coordinate.",
                },
                "end_y": {
                    "type": "integer",
                    "description": "Swipe end Y coordinate.",
                },
                "duration_ms": {
                    "type": "integer",
                    "description": "Duration for long_press or swipe in milliseconds.",
                    "default": 750,
                },
                "text": {
                    "type": "string",
                    "description": "Text to enter for type_text.",
                },
                "keycode": {
                    "type": "string",
                    "description": "Allowlisted Android keyevent name such as ENTER or TAB.",
                },
                "post_action_wait_ms": {
                    "type": "integer",
                    "description": "Milliseconds to wait before capturing the post-action UI state.",
                    "default": 1000,
                },
                "capture_ui_after": {
                    "type": "boolean",
                    "description": "Capture a fresh UI dump after the action.",
                    "default": True,
                },
                "include_screenshot": {
                    "type": "boolean",
                    "description": "Capture a screenshot in the post-action UI state.",
                    "default": True,
                },
            },
            "required": ["session_id", "action"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        device_id = _session_device_id(session)
        if not device_id:
            return {"error": "No device connected. Run start_dynamic_session first."}

        action = str(kwargs.get("action", "")).strip()
        duration_ms = max(1, int(kwargs.get("duration_ms", 750)))
        post_action_wait_ms = max(0, int(kwargs.get("post_action_wait_ms", 1000)))
        capture_ui_after = kwargs.get("capture_ui_after", True)
        include_screenshot = kwargs.get("include_screenshot", True)

        target: dict[str, Any] = {}
        command: list[str]

        if action in {"tap", "long_press"}:
            if kwargs.get("element_id"):
                element = _lookup_element(session, kwargs["element_id"])
                if not element:
                    return {
                        "error": f"Unknown element_id: {kwargs['element_id']}",
                        "hint": "Run inspect_ui first to refresh the UI tree.",
                    }
                bounds = element.get("bounds_rect", {})
                x = bounds.get("center_x")
                y = bounds.get("center_y")
                target = {
                    "element_id": element["element_id"],
                    "resource_id": element.get("resource_id"),
                    "text": element.get("text"),
                    "x": x,
                    "y": y,
                }
            else:
                x = kwargs.get("x")
                y = kwargs.get("y")
                if x is None or y is None:
                    return {"error": "tap and long_press require either element_id or both x and y."}
                target = {"x": int(x), "y": int(y)}
                x = int(x)
                y = int(y)

            if action == "tap":
                command = _adb_prefix(device_id) + ["shell", "input", "tap", str(x), str(y)]
            else:
                command = (
                    _adb_prefix(device_id)
                    + ["shell", "input", "swipe", str(x), str(y), str(x), str(y), str(duration_ms)]
                )

        elif action == "swipe":
            required = ("start_x", "start_y", "end_x", "end_y")
            if any(kwargs.get(name) is None for name in required):
                return {"error": "swipe requires start_x, start_y, end_x, and end_y."}
            target = {name: int(kwargs[name]) for name in required}
            command = (
                _adb_prefix(device_id)
                + [
                    "shell",
                    "input",
                    "swipe",
                    str(target["start_x"]),
                    str(target["start_y"]),
                    str(target["end_x"]),
                    str(target["end_y"]),
                    str(duration_ms),
                ]
            )

        elif action == "type_text":
            text = kwargs.get("text")
            if text is None:
                return {"error": "type_text requires text."}
            try:
                encoded_text = _encode_input_text(str(text))
            except ValueError as exc:
                return {"error": str(exc)}
            target = {"text": str(text), "encoded_text": encoded_text}
            command = _adb_prefix(device_id) + ["shell", "input", "text", encoded_text]

        elif action in {"keyevent", "back", "home"}:
            keycode = kwargs.get("keycode")
            if action == "back":
                keycode = "BACK"
            elif action == "home":
                keycode = "HOME"

            if not keycode:
                return {"error": "keyevent requires keycode."}

            keycode_name = str(keycode).strip().upper()
            keycode_value = ALLOWED_KEYEVENTS.get(keycode_name)
            if not keycode_value:
                return {
                    "error": f"Unsupported keycode: {keycode}",
                    "allowed_keycodes": sorted(ALLOWED_KEYEVENTS),
                }
            target = {"keycode": keycode_name, "keycode_value": keycode_value}
            command = _adb_prefix(device_id) + ["shell", "input", "keyevent", keycode_value]

        else:
            return {"error": f"Unsupported action: {action}"}

        stdout, stderr, rc = await run_local(command, timeout=20)
        if rc != 0:
            return {"error": f"UI action failed: {stderr[:300] or stdout[:300]}", "action": action}

        if post_action_wait_ms:
            await asyncio.sleep(post_action_wait_ms / 1000)

        result: dict[str, Any] = {
            "action": action,
            "executed": True,
            "target": target,
        }

        if capture_ui_after:
            post_action_ui = await _capture_ui_state(
                session,
                include_screenshot=include_screenshot,
                interactive_only=False,
                max_elements=200,
                label=f"after_{action}",
            )
            result["post_action_ui"] = post_action_ui
        elif include_screenshot:
            screenshot_result = await _capture_screenshot(session, device_id, f"after_{action}")
            result.update(screenshot_result)

        return result


class WaitForUiTool(BaseTool):
    """Poll the UI hierarchy until a selector appears or disappears."""

    name = "wait_for_ui"
    description = (
        "Poll the Android UI hierarchy until text, resource_id, content_desc, "
        "class_name, or package_name appears or disappears."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "text": {
                    "type": "string",
                    "description": "Case-insensitive substring match across text and content description.",
                },
                "resource_id": {
                    "type": "string",
                    "description": "Exact Android resource ID to match.",
                },
                "content_desc": {
                    "type": "string",
                    "description": "Case-insensitive substring match for content description.",
                },
                "class_name": {
                    "type": "string",
                    "description": "Case-insensitive substring match for widget class name.",
                },
                "package_name": {
                    "type": "string",
                    "description": "Exact package name to match.",
                },
                "state": {
                    "type": "string",
                    "enum": ["present", "absent"],
                    "description": "Whether the selector should appear or disappear.",
                    "default": "present",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Maximum number of seconds to poll before timing out.",
                    "default": 15,
                },
                "poll_interval_ms": {
                    "type": "integer",
                    "description": "Milliseconds between polls.",
                    "default": 1000,
                },
                "include_screenshot": {
                    "type": "boolean",
                    "description": "Capture a screenshot once polling ends.",
                    "default": True,
                },
                "interactive_only": {
                    "type": "boolean",
                    "description": "Only evaluate interactive nodes while polling.",
                    "default": False,
                },
                "max_elements": {
                    "type": "integer",
                    "description": "Maximum number of parsed elements to keep from each poll.",
                    "default": 200,
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        device_id = _session_device_id(session)
        if not device_id:
            return {"error": "No device connected. Run start_dynamic_session first."}

        selector = {
            key: str(kwargs[key])
            for key in ("text", "resource_id", "content_desc", "class_name", "package_name")
            if kwargs.get(key)
        }
        if not selector:
            return {"error": "wait_for_ui requires at least one selector field."}

        desired_state = kwargs.get("state", "present")
        timeout_seconds = max(1, int(kwargs.get("timeout_seconds", 15)))
        poll_interval_ms = max(0, int(kwargs.get("poll_interval_ms", 1000)))
        include_screenshot = kwargs.get("include_screenshot", True)
        interactive_only = kwargs.get("interactive_only", False)
        max_elements = max(1, int(kwargs.get("max_elements", 200)))

        deadline = asyncio.get_running_loop().time() + timeout_seconds
        attempts = 0
        last_state: dict[str, Any] | None = None
        last_matches: list[dict[str, Any]] = []

        while True:
            attempts += 1
            last_state = await _capture_ui_state(
                session,
                include_screenshot=False,
                interactive_only=interactive_only,
                max_elements=max_elements,
                label="wait_for_ui",
            )
            if "error" in last_state:
                return last_state

            last_matches = [
                element for element in last_state.get("elements", []) if _matches_selector(element, selector)
            ]
            present = bool(last_matches)
            success = present if desired_state == "present" else not present

            if success or asyncio.get_running_loop().time() >= deadline:
                break

            if poll_interval_ms:
                await asyncio.sleep(poll_interval_ms / 1000)

        if include_screenshot and last_state is not None:
            screenshot_result = await _capture_screenshot(session, device_id, "wait_for_ui")
            if "error" in screenshot_result:
                last_state["screenshot_error"] = screenshot_result["error"]
            else:
                last_state["screenshot_path"] = screenshot_result["screenshot_path"]
                session.metadata[UI_STATE_METADATA_KEY] = last_state

        return {
            "matched": bool(last_matches) if desired_state == "present" else not bool(last_matches),
            "state": desired_state,
            "selector": selector,
            "attempts": attempts,
            "matched_elements": last_matches[:20],
            "ui_state": last_state,
        }
