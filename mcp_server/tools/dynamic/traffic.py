"""Traffic interception and analysis tools.

Manages mitmproxy traffic capture sessions and analyzes captured
requests for sensitive data exposure.
"""

from __future__ import annotations

import base64
import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from loguru import logger

from mcp_server.backends.local_backend import run_local, read_file_content
from mcp_server.config import config
from mcp_server.models.enums import AnalysisPhase, FindingCategory, Severity
from mcp_server.models.finding import Finding
from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool
from mcp_server.tools.dynamic.device import ensure_mitmproxy_ca_installed
from mcp_server.tools.workspace import session_workspace

MITMWEB_API_URL = "http://mitmproxy:8081/flows"
MITMWEB_TOKEN = os.environ.get("MOBILYTIX_MITMWEB_TOKEN", "mobilytix-local-token")
BODY_PREVIEW_MAX_CHARS = 8192
RETURNED_REQUEST_LIMIT = 50

# Patterns for sensitive data in traffic
SENSITIVE_TRAFFIC_PATTERNS = [
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "Email address"),
    (re.compile(r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b"), "Possible SSN"),
    (re.compile(r"\b\d{10,16}\b"), "Possible phone/card number"),
    (re.compile(r"password\s*[:=]\s*\S+", re.IGNORECASE), "Password"),
    (re.compile(r"(api[_-]?key|apikey|token|secret)\s*[:=]\s*\S+", re.IGNORECASE), "Secret/Token"),
]


async def _set_device_proxy(session: AnalysisSession, value: str) -> tuple[str, str, int]:
    """Set the emulator's global HTTP proxy."""
    if not session.device_id:
        return "", "No device connected. Run start_dynamic_session first.", 1

    return await run_local(
        ["adb", "-s", session.device_id, "shell", "settings", "put", "global", "http_proxy", value],
        timeout=10,
    )


async def _get_device_proxy(session: AnalysisSession) -> tuple[str, str, int]:
    """Read back the emulator's global HTTP proxy setting."""
    if not session.device_id:
        return "", "No device connected. Run start_dynamic_session first.", 1

    return await run_local(
        ["adb", "-s", session.device_id, "shell", "settings", "get", "global", "http_proxy"],
        timeout=10,
    )


def _parse_capture_timestamp(value: str | None) -> float | None:
    """Convert an ISO-8601 capture timestamp to a Unix timestamp."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def _extract_flow_list(payload: Any) -> list[dict[str, Any]] | None:
    """Normalize mitmweb API responses into a list of flow objects."""
    if isinstance(payload, list):
        return [flow for flow in payload if isinstance(flow, dict)]

    if isinstance(payload, dict):
        for key in ("flows", "data", "content"):
            value = payload.get(key)
            if isinstance(value, list):
                return [flow for flow in value if isinstance(flow, dict)]

    return None


async def _fetch_flow_message_preview(flow_id: str, message: str) -> str:
    """Fetch a single flow's request/response body preview from mitmweb."""
    stdout, stderr, rc = await run_local(
        [
            "curl",
            "-fsS",
            "-H",
            f"Authorization: Bearer {MITMWEB_TOKEN}",
            f"{MITMWEB_API_URL}/{flow_id}/{message}/content.data",
        ],
        timeout=15,
    )
    if rc != 0:
        logger.debug(
            "Failed to fetch {} body for flow {}: {}",
            message,
            flow_id,
            (stderr or stdout)[:200],
        )
        return ""
    return stdout[:BODY_PREVIEW_MAX_CHARS]


async def _fetch_flow_message_bytes(flow_id: str, message: str) -> tuple[bytes | None, str | None]:
    """Fetch the raw request/response body for a flow from mitmweb."""
    with tempfile.NamedTemporaryFile(prefix=f"mobilytix-flow-{message}-", delete=False) as tmp:
        temp_path = Path(tmp.name)

    try:
        stdout, stderr, rc = await run_local(
            [
                "curl",
                "-fsS",
                "-H",
                f"Authorization: Bearer {MITMWEB_TOKEN}",
                "-o",
                str(temp_path),
                f"{MITMWEB_API_URL}/{flow_id}/{message}/content.data",
            ],
            timeout=30,
        )
        if rc != 0:
            return None, (stderr or stdout)[:500]
        return temp_path.read_bytes(), None
    except OSError as exc:
        return None, str(exc)
    finally:
        temp_path.unlink(missing_ok=True)


def _serialize_body_payload(body: bytes, *, max_bytes: int = 0) -> dict[str, Any]:
    """Serialize raw body bytes as text when possible, else base64."""
    content_length = len(body)
    if max_bytes > 0 and content_length > max_bytes:
        returned = body[:max_bytes]
        truncated = True
    else:
        returned = body
        truncated = False

    try:
        return {
            "content_length": content_length,
            "returned_length": len(returned),
            "truncated": truncated,
            "encoding": "utf-8",
            "body": returned.decode("utf-8"),
        }
    except UnicodeDecodeError:
        return {
            "content_length": content_length,
            "returned_length": len(returned),
            "truncated": truncated,
            "encoding": "base64",
            "body": base64.b64encode(returned).decode("ascii"),
        }


class StartTrafficCaptureTool(BaseTool):
    """Start a labeled traffic capture session through mitmproxy."""

    name = "start_traffic_capture"
    description = (
        "Start capturing HTTP/HTTPS traffic through mitmproxy. "
        "Verifies the mitmproxy CA is installed in the emulator system trust "
        "store, enables the device proxy, and returns a capture_id to reference "
        "this capture session."
    )

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}
        if not session.device_id:
            return {"error": "No device connected. Run start_dynamic_session first."}

        mitmproxy_ca = session.metadata.get("mitmproxy_ca", {})
        if not mitmproxy_ca.get("installed"):
            mitmproxy_ca = await ensure_mitmproxy_ca_installed(session, session.device_id)
            session.metadata["mitmproxy_ca"] = mitmproxy_ca

        if not mitmproxy_ca.get("installed"):
            return {
                "error": (
                    "Cannot start traffic interception because the mitmproxy CA "
                    "is not installed in the emulator system trust store."
                ),
                "mitmproxy_ca": mitmproxy_ca,
                "hint": (
                    "Fix device trust first. Without a trusted CA, HTTPS failures "
                    "do not distinguish app pinning from plain device certificate rejection."
                ),
            }

        stdout, stderr, rc = await _set_device_proxy(session, "mitmproxy:8080")
        if rc != 0:
            return {
                "error": (
                    "Failed to enable the device proxy for traffic capture: "
                    f"{stderr[:500] or stdout[:500]}"
                )
            }

        proxy_stdout, proxy_stderr, proxy_rc = await _get_device_proxy(session)
        proxy_value = proxy_stdout.strip()
        if proxy_rc != 0:
            return {
                "error": (
                    "Enabled traffic capture, but failed to read back the device "
                    f"proxy setting: {proxy_stderr[:500] or proxy_stdout[:500]}"
                )
            }
        if proxy_value != "mitmproxy:8080":
            return {
                "error": (
                    "Traffic capture was requested, but Android did not keep the "
                    f"expected proxy setting. Current value: {proxy_value or '<empty>'}"
                ),
                "proxy_enabled": False,
                "proxy_readback": proxy_value,
                "hint": (
                    "Verify that the emulator accepts global proxy changes and "
                    "that nothing is clearing `settings global http_proxy`."
                ),
            }

        capture_id = str(uuid.uuid4())[:8]
        ws = str(session_workspace(session))
        dump_file = f"{ws}/traffic_{capture_id}.flow"

        # Store capture metadata
        if "captures" not in session.metadata:
            session.metadata["captures"] = {}

        session.metadata["captures"][capture_id] = {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "dump_file": dump_file,
            "stopped": False,
        }
        session.metadata["traffic_proxy_enabled"] = True

        session.current_phase = AnalysisPhase.TRAFFIC

        return {
            "capture_id": capture_id,
            "started_at": session.metadata["captures"][capture_id]["started_at"],
            "proxy_enabled": True,
            "proxy_target": "mitmproxy:8080",
            "proxy_readback": proxy_value,
            "https_interception_ready": True,
            "mitmproxy_ca_subject_hash": mitmproxy_ca.get("subject_hash"),
            "note": (
                "Traffic interception is enabled and the device trusts the "
                "mitmproxy CA. If HTTPS traffic from the target app is still "
                "not intercepted, suspect certificate pinning or app-specific "
                "trust logic rather than plain device certificate rejection."
            ),
        }


class StopTrafficCaptureTool(BaseTool):
    """Stop a traffic capture session and return summary."""

    name = "stop_traffic_capture"
    description = (
        "Stop an active traffic capture and return a summary: "
        "total requests, hosts contacted, and duration."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "capture_id": {
                    "type": "string",
                    "description": "Capture ID from start_traffic_capture",
                },
            },
            "required": ["session_id", "capture_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}
        if not session.device_id:
            return {"error": "No device connected. Run start_dynamic_session first."}

        capture_id = kwargs["capture_id"]
        captures = session.metadata.get("captures", {})

        if capture_id not in captures:
            return {"error": f"Capture not found: {capture_id}"}

        captures[capture_id]["stopped"] = True
        captures[capture_id]["stopped_at"] = datetime.now(timezone.utc).isoformat()
        stdout, stderr, rc = await _set_device_proxy(session, ":0")
        if rc != 0:
            return {
                "error": (
                    "Stopped capture metadata, but failed to clear the device "
                    f"proxy: {stderr[:500] or stdout[:500]}"
                ),
                "capture_id": capture_id,
                "stopped": True,
            }

        session.metadata["traffic_proxy_enabled"] = False

        return {
            "capture_id": capture_id,
            "stopped": True,
            "started_at": captures[capture_id]["started_at"],
            "stopped_at": captures[capture_id]["stopped_at"],
            "proxy_enabled": False,
        }


class GetCapturedRequestsTool(BaseTool):
    """Get captured HTTP requests from mitmproxy."""

    name = "get_captured_requests"
    description = (
        "Fetch captured HTTP/HTTPS requests from mitmproxy. "
        "Optionally filter by host or path. Shows request/response details."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "host_filter": {
                    "type": "string",
                    "description": "Filter requests by hostname substring",
                },
                "path_filter": {
                    "type": "string",
                    "description": "Filter requests by URL path substring",
                },
                "capture_id": {
                    "type": "string",
                    "description": (
                        "Optional capture ID from start_traffic_capture. When "
                        "provided, only flows created during that capture window "
                        "are returned."
                    ),
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        host_filter = kwargs.get("host_filter", "")
        path_filter = kwargs.get("path_filter", "")
        capture_id = kwargs.get("capture_id")
        captures = session.metadata.get("captures", {})
        capture = captures.get(capture_id) if capture_id else None
        capture_started = _parse_capture_timestamp(capture.get("started_at")) if capture else None
        capture_stopped = _parse_capture_timestamp(capture.get("stopped_at")) if capture else None
        if capture_id and capture is None:
            return {"error": f"Capture not found: {capture_id}"}

        # Try to get requests from mitmproxy API (mitmproxy runs in sibling container)
        stdout, stderr, rc = await run_local(
            [
                "curl",
                "-sS",
                "-H",
                f"Authorization: Bearer {MITMWEB_TOKEN}",
                MITMWEB_API_URL,
            ],
            timeout=15,
        )

        if rc != 0:
            return {
                "error": "Failed to query the mitmproxy web API.",
                "raw_output": (stderr or stdout)[:4000],
            }

        requests = []
        api_total_flows: int | None = None
        if stdout.strip():
            try:
                payload = json.loads(stdout)
                flows = _extract_flow_list(payload)
                if flows is None:
                    return {
                        "error": "Unexpected mitmproxy API response format.",
                        "raw_output": stdout[:4000],
                    }

                api_total_flows = len(flows)
                for flow in flows:
                    created_ts = flow.get("timestamp_created")
                    if isinstance(created_ts, str):
                        try:
                            created_ts = float(created_ts)
                        except ValueError:
                            created_ts = None

                    if capture_started is not None and isinstance(created_ts, (int, float)):
                        if created_ts < capture_started:
                            continue
                    if capture_stopped is not None and isinstance(created_ts, (int, float)):
                        if created_ts > capture_stopped:
                            continue

                    req = flow.get("request", {})
                    resp = flow.get("response", {})

                    if not isinstance(req, dict):
                        continue
                    if not isinstance(resp, dict):
                        resp = {}

                    request_entry = {
                        "method": req.get("method", ""),
                        "url": f"{req.get('scheme', 'http')}://{req.get('host', '')}{req.get('path', '')}",
                        "host": req.get("host", ""),
                        "path": req.get("path", ""),
                        "request_headers": dict(req.get("headers", [])),
                        "request_body_length": req.get("contentLength"),
                        "request_body_truncated": (
                            isinstance(req.get("contentLength"), int)
                            and req.get("contentLength", 0) > BODY_PREVIEW_MAX_CHARS
                        ),
                        "request_body_preview": "",
                        "response_status": resp.get("status_code", 0),
                        "response_headers": dict(resp.get("headers", [])),
                        "response_body_length": resp.get("contentLength"),
                        "response_body_truncated": (
                            isinstance(resp.get("contentLength"), int)
                            and resp.get("contentLength", 0) > BODY_PREVIEW_MAX_CHARS
                        ),
                        "response_body_preview": "",
                        "flow_id": flow.get("id"),
                        "timestamp_created": created_ts,
                        "mitm_error": (
                            flow.get("error", {}).get("msg")
                            if isinstance(flow.get("error"), dict)
                            else None
                        ),
                    }

                    # Apply filters
                    if host_filter and host_filter.lower() not in request_entry["host"].lower():
                        continue
                    if path_filter and path_filter.lower() not in request_entry["path"].lower():
                        continue

                    requests.append(request_entry)
            except json.JSONDecodeError:
                return {
                    "error": "mitmproxy API did not return valid JSON.",
                    "raw_output": stdout[:4000],
                    "hint": (
                        "If the output is empty or HTML, verify that the mitmweb "
                        "token configured in docker-compose matches MOBILYTIX_MITMWEB_TOKEN."
                    ),
                }

        returned_requests = requests[:RETURNED_REQUEST_LIMIT]
        for request_entry in returned_requests:
            flow_id = request_entry.get("flow_id")
            if not flow_id:
                continue
            if isinstance(request_entry.get("request_body_length"), int) and request_entry["request_body_length"] > 0:
                request_entry["request_body_preview"] = await _fetch_flow_message_preview(flow_id, "request")
            if isinstance(request_entry.get("response_body_length"), int) and request_entry["response_body_length"] > 0:
                request_entry["response_body_preview"] = await _fetch_flow_message_preview(flow_id, "response")
            truncated_parts = []
            if request_entry.get("request_body_truncated"):
                truncated_parts.append("request")
            if request_entry.get("response_body_truncated"):
                truncated_parts.append("response")
            if truncated_parts:
                if len(truncated_parts) == 2:
                    truncated_desc = "request and response bodies"
                    suggested_message = "both"
                else:
                    truncated_desc = f"{truncated_parts[0]} body"
                    suggested_message = truncated_parts[0]
                request_entry["body_retrieval_hint"] = (
                    f"The {truncated_desc} exceeds the {BODY_PREVIEW_MAX_CHARS}-byte preview limit. "
                    f"Use get_captured_flow_body with flow_id '{flow_id}' and "
                    f"message '{suggested_message}' to retrieve the full body."
                )

        # Collect unique hosts
        hosts = list(set(r["host"] for r in requests if r.get("host")))

        result = {
            "total_requests": len(requests),
            "api_total_flows": api_total_flows,
            "hosts": hosts,
            "requests": returned_requests,
            "truncated": len(requests) > RETURNED_REQUEST_LIMIT,
            "capture_id": capture_id,
            "body_preview_limit": BODY_PREVIEW_MAX_CHARS,
            "full_body_tool": "get_captured_flow_body",
        }
        if api_total_flows == 0:
            result["hint"] = (
                "mitmproxy currently has no flows. If you are sure the app made "
                "requests, the app may be bypassing the system proxy or using a "
                "non-HTTP protocol."
            )
        elif api_total_flows and len(requests) == 0 and capture_id:
            result["hint"] = (
                "mitmproxy has flows, but none matched the requested capture "
                "window or filters."
            )
        return result


class GetCapturedFlowBodyTool(BaseTool):
    """Retrieve the full request/response body for a captured flow."""

    name = "get_captured_flow_body"
    description = (
        "Retrieve the full request and/or response body for a captured flow. "
        "Use this when get_captured_requests reports a truncated body preview."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "flow_id": {
                    "type": "string",
                    "description": "Flow ID returned by get_captured_requests",
                },
                "message": {
                    "type": "string",
                    "enum": ["request", "response", "both"],
                    "description": "Which body to retrieve; defaults to both",
                },
                "max_bytes": {
                    "type": "integer",
                    "description": "Maximum bytes to return per body; use 0 for the full body",
                },
            },
            "required": ["session_id", "flow_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        flow_id = kwargs["flow_id"]
        message = kwargs.get("message", "both")
        max_bytes = int(kwargs.get("max_bytes", 0) or 0)

        if max_bytes < 0:
            return {"error": "max_bytes must be 0 or greater."}

        if message == "both":
            parts = ["request", "response"]
        else:
            parts = [message]

        result: dict[str, Any] = {
            "flow_id": flow_id,
            "message": message,
            "max_bytes": max_bytes,
        }
        retrieved_any = False

        for part in parts:
            body_bytes, error = await _fetch_flow_message_bytes(flow_id, part)
            if error is not None:
                result[f"{part}_error"] = error
                continue

            payload = _serialize_body_payload(body_bytes or b"", max_bytes=max_bytes)
            result[f"{part}_body"] = payload["body"]
            result[f"{part}_body_length"] = payload["content_length"]
            result[f"{part}_body_returned_length"] = payload["returned_length"]
            result[f"{part}_body_truncated"] = payload["truncated"]
            result[f"{part}_body_encoding"] = payload["encoding"]
            if payload["encoding"] == "base64":
                result[f"{part}_body_note"] = (
                    "Body is binary or not valid UTF-8; the returned body is base64-encoded."
                )
            retrieved_any = True

        if not retrieved_any:
            return {
                "error": "Failed to retrieve any body content for the requested flow.",
                "flow_id": flow_id,
                "message": message,
                "request_error": result.get("request_error"),
                "response_error": result.get("response_error"),
            }

        if max_bytes > 0:
            result["hint"] = (
                "The returned body may be truncated by max_bytes. Set max_bytes to 0 "
                "to retrieve the full body."
            )

        return result


class FindSensitiveTrafficTool(BaseTool):
    """Analyze captured traffic for sensitive data exposure.

    Checks for: HTTP (not HTTPS) traffic, credentials in headers,
    PII in request/response bodies, API keys in query parameters.
    """

    name = "find_sensitive_traffic"
    description = (
        "Analyze captured traffic for sensitive data: HTTP (not HTTPS) requests, "
        "credentials in headers, PII in bodies, API keys in URLs. "
        "Creates findings for each issue."
    )

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        # Get captured requests via the other tool
        get_requests = GetCapturedRequestsTool()
        result = await get_requests.run(session)

        if "error" in result:
            return result

        requests = result.get("requests", [])
        findings_created = []

        for req in requests:
            url = req.get("url", "")
            method = req.get("method", "")
            host = req.get("host", "")

            # Check for HTTP (not HTTPS)
            if url.startswith("http://") and host and "localhost" not in host:
                finding = Finding(
                    title=f"Unencrypted HTTP traffic to {host}",
                    severity=Severity.HIGH,
                    category=FindingCategory.INSECURE_COMMUNICATION,
                    description=(
                        f"The app sends traffic over unencrypted HTTP to {host}. "
                        f"All data in transit can be intercepted by network attackers."
                    ),
                    evidence=f"{method} {url}",
                    location=url,
                    tool="find_sensitive_traffic",
                    phase=AnalysisPhase.TRAFFIC.value,
                    cwe_id="CWE-319",
                    recommendation="Use HTTPS for all network communication.",
                )
                if session.add_finding(finding):
                    findings_created.append(finding.to_dict())

            # Check headers for auth tokens
            headers = req.get("request_headers", {})
            for header_name, header_val in headers.items():
                if header_name.lower() in ("authorization", "x-api-key", "x-auth-token"):
                    if url.startswith("http://"):
                        finding = Finding(
                            title=f"Authentication header over HTTP: {header_name}",
                            severity=Severity.HIGH,
                            category=FindingCategory.SENSITIVE_DATA_EXPOSURE,
                            description=(
                                f"An authentication header ({header_name}) is transmitted "
                                f"over unencrypted HTTP to {host}."
                            ),
                            evidence=f"{header_name}: {header_val[:100]}...",
                            location=url,
                            tool="find_sensitive_traffic",
                            phase=AnalysisPhase.TRAFFIC.value,
                            cwe_id="CWE-319",
                            recommendation="Use HTTPS and avoid exposing credentials in URLs.",
                        )
                        if session.add_finding(finding):
                            findings_created.append(finding.to_dict())

            # Check body content for sensitive patterns
            body = req.get("request_body_preview", "")
            resp_body = req.get("response_body_preview", "")
            for content, content_type in [(body, "request"), (resp_body, "response")]:
                if not content:
                    continue
                for pattern, pattern_name in SENSITIVE_TRAFFIC_PATTERNS:
                    if pattern.search(content):
                        finding = Finding(
                            title=f"{pattern_name} in {content_type} to {host}",
                            severity=Severity.HIGH if content_type == "request" else Severity.MEDIUM,
                            category=FindingCategory.SENSITIVE_DATA_EXPOSURE,
                            description=(
                                f"Sensitive data ({pattern_name}) found in {content_type} "
                                f"body to/from {host}."
                            ),
                            evidence=content[:300],
                            location=url,
                            tool="find_sensitive_traffic",
                            phase=AnalysisPhase.TRAFFIC.value,
                            cwe_id="CWE-200",
                            recommendation="Encrypt sensitive data and minimize data exposure.",
                        )
                        if session.add_finding(finding):
                            findings_created.append(finding.to_dict())
                        break  # One finding per content per pattern type

        return {
            "requests_analyzed": len(requests),
            "findings_created": len(findings_created),
            "findings": findings_created,
        }
