"""ADB and device lifecycle tools.

Manages the Android device/emulator: starting dynamic sessions, installing
APKs, launching apps, capturing logcat, and taking screenshots.
"""

from __future__ import annotations

import asyncio
import base64
from pathlib import Path
import re
from typing import Any, Optional

from loguru import logger

from mcp_server.backends.local_backend import run_local, read_file_content
from mcp_server.config import config
from mcp_server.models.enums import AnalysisPhase, FindingCategory, Severity
from mcp_server.models.finding import Finding
from mcp_server.models.session import AnalysisSession
from mcp_server.tools.base import BaseTool
from mcp_server.tools.workspace import session_workspace

FRIDA_BRIDGE_HOST = "127.0.0.1"
FRIDA_SERVER_REMOTE_PATH = "/data/local/tmp/frida-server"
FRIDA_SERVER_PORT = config.docker.frida_port
FRIDA_SERVER_PORT_HEX = f"{FRIDA_SERVER_PORT:04X}"
DROZER_BRIDGE_HOST = "127.0.0.1"
DROZER_BRIDGE_PORT = 31415
MITMPROXY_CA_CERT = Path("/mitmproxy/mitmproxy-ca-cert.cer")


async def _wait_for_device_boot(
    device_id: str,
    *,
    max_attempts: int = 30,
    delay_seconds: int = 5,
) -> bool:
    """Wait for the emulator to report boot completion."""
    for attempt in range(max_attempts):
        await run_local(["adb", "connect", "android:5555"], timeout=15)
        boot_out, _, boot_rc = await run_local(
            ["adb", "-s", device_id, "shell", "getprop", "sys.boot_completed"],
            timeout=10,
        )
        if boot_rc == 0 and boot_out.strip() == "1":
            logger.info("Android device ready after {} attempts", attempt + 1)
            return True
        if attempt < max_attempts - 1:
            logger.debug(
                "Waiting for device boot (attempt {}/{})",
                attempt + 1,
                max_attempts,
            )
            await asyncio.sleep(delay_seconds)
    return False


async def _reboot_and_wait(device_id: str) -> bool:
    """Reboot the emulator and wait for it to boot again."""
    await run_local(["adb", "-s", device_id, "reboot"], timeout=15)
    await asyncio.sleep(3)
    return await _wait_for_device_boot(device_id, max_attempts=60, delay_seconds=5)


async def _wait_for_mitmproxy_ca(max_attempts: int = 10) -> Path | None:
    """Wait briefly for mitmproxy to generate its CA certificate."""
    for _ in range(max_attempts):
        if MITMPROXY_CA_CERT.exists():
            return MITMPROXY_CA_CERT
        await asyncio.sleep(1)
    return None


async def _probe_frida_server_status(device_id: str) -> dict[str, Any]:
    """Return process/port status for frida-server on the Android device."""
    process_stdout, process_stderr, process_rc = await run_local(
        [
            "adb",
            "-s",
            device_id,
            "shell",
            "sh",
            "-c",
            "pidof frida-server >/dev/null 2>&1 || ps -A 2>/dev/null | grep -q '[f]rida-server'",
        ],
        timeout=10,
    )
    _, port_stderr, port_rc = await run_local(
        [
            "adb",
            "-s",
            device_id,
            "shell",
            "sh",
            "-c",
            (
                f"cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | "
                f"grep -i ':{FRIDA_SERVER_PORT_HEX}' | "
                "grep -Eq '[[:space:]]0A[[:space:]]'"
            ),
        ],
        timeout=10,
    )
    return {
        "process_running": process_rc == 0,
        "port_listening": port_rc == 0,
        "pid_hint": process_stdout.strip().splitlines()[0] if process_stdout.strip() else None,
        "process_probe_error": process_stderr[:300] if process_stderr else None,
        "port_probe_error": port_stderr[:300] if port_stderr else None,
        "port": FRIDA_SERVER_PORT,
    }


async def _get_frida_server_readiness(device_id: str) -> dict[str, Any]:
    """Return the best-effort usability state for frida-server."""
    status = await _probe_frida_server_status(device_id)
    bridge_reachable = False
    bridge_error = None

    # A real Frida client handshake is more authoritative than the procfs port probe.
    if status["process_running"] or status["port_listening"]:
        bridge_reachable, bridge_error = await _is_frida_bridge_reachable(device_id)

    return {
        **status,
        "bridge_reachable": bridge_reachable,
        "running": bridge_reachable,
        **({"bridge_error": bridge_error} if bridge_error else {}),
    }


async def _is_frida_server_running(device_id: str) -> bool:
    """Return whether frida-server is usable from the host-side Frida client."""
    readiness = await _get_frida_server_readiness(device_id)
    return bool(readiness["running"])


async def _is_frida_bridge_reachable(device_id: str) -> tuple[bool, str | None]:
    """Verify that the host Frida client can talk to the device's frida-server."""
    _, stderr, rc = await run_local(
        [
            "adb",
            "-s",
            device_id,
            "forward",
            f"tcp:{FRIDA_SERVER_PORT}",
            f"tcp:{FRIDA_SERVER_PORT}",
        ],
        timeout=10,
    )
    if rc != 0:
        return False, f"adb forward failed: {stderr[:300]}"

    stdout, stderr, rc = await run_local(
        ["frida-ps", "-H", f"{FRIDA_BRIDGE_HOST}:{FRIDA_SERVER_PORT}"],
        timeout=15,
    )
    if rc != 0:
        return False, (stderr or stdout)[:300]
    return True, None


async def _stop_frida_server(device_id: str) -> None:
    """Best-effort stop for stale frida-server processes on the device."""
    stop_commands = [
        [
            "adb",
            "-s",
            device_id,
            "shell",
            "sh",
            "-c",
            "for p in $(pidof frida-server 2>/dev/null); do kill \"$p\" 2>/dev/null; done",
        ],
        [
            "adb",
            "-s",
            device_id,
            "shell",
            "su",
            "-c",
            "for p in $(pidof frida-server 2>/dev/null); do kill \"$p\" 2>/dev/null; done",
        ],
    ]
    for command in stop_commands:
        await run_local(command, timeout=10)


async def _wait_for_frida_server(device_id: str, *, attempts: int = 10, delay_seconds: float = 1.0) -> bool:
    """Wait briefly for frida-server to come up."""
    for _ in range(attempts):
        if await _is_frida_server_running(device_id):
            return True
        await asyncio.sleep(delay_seconds)
    return False


async def ensure_frida_server_running(device_id: str, *, force_restart: bool = False) -> dict[str, Any]:
    """Ensure frida-server is running on the Android device."""
    readiness = await _get_frida_server_readiness(device_id)

    if readiness["running"] and not force_restart:
        return {
            "running": True,
            "already_running": True,
            "remote_path": FRIDA_SERVER_REMOTE_PATH,
            "process_running": readiness["process_running"],
            "port_listening": readiness["port_listening"],
            "bridge_reachable": True,
            **({"pid_hint": readiness["pid_hint"]} if readiness.get("pid_hint") else {}),
        }

    if force_restart or readiness["process_running"] or readiness["port_listening"]:
        await _stop_frida_server(device_id)
        await asyncio.sleep(1)
        readiness = await _get_frida_server_readiness(device_id)

    if readiness["running"]:
        return {
            "running": True,
            "already_running": False,
            "remote_path": FRIDA_SERVER_REMOTE_PATH,
            "process_running": readiness["process_running"],
            "port_listening": readiness["port_listening"],
            "bridge_reachable": True,
            **({"pid_hint": readiness["pid_hint"]} if readiness.get("pid_hint") else {}),
        }

    if not readiness["process_running"] and not readiness["port_listening"]:
        pass
    elif not force_restart:
        return {
            "running": False,
            "already_running": False,
            "remote_path": FRIDA_SERVER_REMOTE_PATH,
            "process_running": readiness["process_running"],
            "port_listening": readiness["port_listening"],
            "bridge_reachable": readiness["bridge_reachable"],
            "error": (
                "frida-server is in an inconsistent state on the device. "
                "Use force_restart=true to stop stale processes and try again."
            ),
            **({"pid_hint": readiness["pid_hint"]} if readiness.get("pid_hint") else {}),
            **({"bridge_error": readiness["bridge_error"]} if readiness.get("bridge_error") else {}),
            **({"process_probe_error": readiness["process_probe_error"]} if readiness.get("process_probe_error") else {}),
            **({"port_probe_error": readiness["port_probe_error"]} if readiness.get("port_probe_error") else {}),
        }

    _, stderr, rc = await run_local(
        ["adb", "-s", device_id, "shell", "ls", FRIDA_SERVER_REMOTE_PATH],
        timeout=10,
    )
    if rc != 0:
        return {
            "running": False,
            "already_running": False,
            "remote_path": FRIDA_SERVER_REMOTE_PATH,
            "error": (
                "frida-server is not running and the expected binary was not found "
                f"at {FRIDA_SERVER_REMOTE_PATH}: {stderr[:300]}"
            ),
            "hint": (
                "Rebuild or restart the Android container so its bootstrap script can "
                "push the Frida server binary back onto the emulator."
            ),
        }

    launch_attempts = [
        {
            "method": "direct",
            "command": [
                "adb",
                "-s",
                device_id,
                "shell",
                "sh",
                "-c",
                f"nohup {FRIDA_SERVER_REMOTE_PATH} >/dev/null 2>&1 &",
            ],
        },
        {
            "method": "su",
            "command": [
                "adb",
                "-s",
                device_id,
                "shell",
                "su",
                "-c",
                f"nohup {FRIDA_SERVER_REMOTE_PATH} >/dev/null 2>&1 &",
            ],
        },
    ]

    last_error = ""
    used_method = None

    for attempt in launch_attempts:
        stdout, stderr, rc = await run_local(attempt["command"], timeout=15)
        if rc == 0 and await _wait_for_frida_server(device_id):
            readiness = await _get_frida_server_readiness(device_id)
            if readiness["running"]:
                used_method = attempt["method"]
                break
            last_error = (
                readiness.get("bridge_error")
                or (
                    "frida-server became a process on the device but the Frida client "
                    "could not complete a handshake"
                )
            )[:300]
        else:
            last_error = (stderr or stdout)[:300]

    if used_method is None:
        stdout, stderr, rc = await run_local(["adb", "-s", device_id, "root"], timeout=15)
        if rc == 0:
            await asyncio.sleep(2)
            await run_local(["adb", "connect", "android:5555"], timeout=15)

            stdout, stderr, rc = await run_local(
                [
                    "adb",
                    "-s",
                    device_id,
                    "shell",
                    "sh",
                    "-c",
                    f"nohup {FRIDA_SERVER_REMOTE_PATH} >/dev/null 2>&1 &",
                ],
                timeout=15,
            )
            if rc == 0 and await _wait_for_frida_server(device_id):
                readiness = await _get_frida_server_readiness(device_id)
                if readiness["running"]:
                    used_method = "adb_root"
                else:
                    last_error = (
                        readiness.get("bridge_error")
                        or (
                            "frida-server became a process on the device but the Frida client "
                            "could not complete a handshake"
                        )
                    )[:300]
            else:
                last_error = (stderr or stdout)[:300]
        else:
            last_error = (stderr or stdout)[:300]

    if used_method is None:
        readiness = await _get_frida_server_readiness(device_id)
        return {
            "running": False,
            "already_running": False,
            "remote_path": FRIDA_SERVER_REMOTE_PATH,
            "process_running": readiness["process_running"],
            "port_listening": readiness["port_listening"],
            "bridge_reachable": readiness["bridge_reachable"],
            "error": (
                "frida-server is present on the device but could not be started. "
                f"Last error: {last_error}"
            ),
            "hint": (
                "Check emulator logs and verify the Android image allows launching "
                "the server binary from /data/local/tmp and that port 27042 becomes reachable."
            ),
            **({"pid_hint": readiness["pid_hint"]} if readiness.get("pid_hint") else {}),
            **({"bridge_error": readiness["bridge_error"]} if readiness.get("bridge_error") else {}),
            **({"process_probe_error": readiness["process_probe_error"]} if readiness.get("process_probe_error") else {}),
            **({"port_probe_error": readiness["port_probe_error"]} if readiness.get("port_probe_error") else {}),
        }

    readiness = await _get_frida_server_readiness(device_id)
    return {
        "running": True,
        "already_running": False,
        "remote_path": FRIDA_SERVER_REMOTE_PATH,
        "start_method": used_method,
        "process_running": readiness["process_running"],
        "port_listening": readiness["port_listening"],
        "bridge_reachable": readiness["bridge_reachable"],
        **({"pid_hint": readiness["pid_hint"]} if readiness.get("pid_hint") else {}),
    }


async def ensure_mitmproxy_ca_installed(
    session: AnalysisSession,
    device_id: str,
) -> dict[str, Any]:
    """Install the mitmproxy CA into the emulator's system trust store."""
    cert_path = await _wait_for_mitmproxy_ca()
    if cert_path is None:
        return {
            "available": False,
            "installed": False,
            "error": (
                "mitmproxy CA certificate was not found at /mitmproxy/mitmproxy-ca-cert.cer. "
                "Ensure the mitmproxy service is running and has initialized its config directory."
            ),
        }

    stdout, stderr, rc = await run_local(
        ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(cert_path)],
        timeout=10,
    )
    if rc != 0 or not stdout.strip():
        return {
            "available": True,
            "installed": False,
            "error": f"Failed to calculate the Android CA hash: {stderr[:500] or stdout[:500]}",
        }

    subject_hash = stdout.splitlines()[0].strip()
    system_cert_path = f"/system/etc/security/cacerts/{subject_hash}.0"

    _, _, check_rc = await run_local(
        ["adb", "-s", device_id, "shell", "ls", system_cert_path],
        timeout=10,
    )
    if check_rc == 0:
        return {
            "available": True,
            "installed": True,
            "already_present": True,
            "subject_hash": subject_hash,
            "system_path": system_cert_path,
        }

    local_cert_path = session_workspace(session) / f"{subject_hash}.0"
    local_cert_path.write_bytes(cert_path.read_bytes())

    stdout, stderr, rc = await run_local(["adb", "-s", device_id, "root"], timeout=15)
    if rc != 0:
        return {
            "available": True,
            "installed": False,
            "error": f"adb root failed while preparing CA install: {stderr[:500] or stdout[:500]}",
        }

    await asyncio.sleep(2)
    await run_local(["adb", "connect", "android:5555"], timeout=15)

    # Best-effort: disabling verified boot helps adb remount on modern emulator images.
    await run_local(
        ["adb", "-s", device_id, "shell", "avbctl", "disable-verification"],
        timeout=20,
    )

    if not await _reboot_and_wait(device_id):
        return {
            "available": True,
            "installed": False,
            "error": "Device rebooted while preparing CA install but did not come back online.",
        }

    stdout, stderr, rc = await run_local(["adb", "-s", device_id, "root"], timeout=15)
    if rc != 0:
        return {
            "available": True,
            "installed": False,
            "error": f"adb root failed after reboot: {stderr[:500] or stdout[:500]}",
        }

    remount_out, remount_err, remount_rc = await run_local(
        ["adb", "-s", device_id, "remount"],
        timeout=20,
    )
    remount_text = f"{remount_out}\n{remount_err}".strip()
    if remount_rc != 0 and "reboot" in remount_text.lower():
        if not await _reboot_and_wait(device_id):
            return {
                "available": True,
                "installed": False,
                "error": "Device requested another reboot during remount but did not come back online.",
            }
        await run_local(["adb", "-s", device_id, "root"], timeout=15)
        remount_out, remount_err, remount_rc = await run_local(
            ["adb", "-s", device_id, "remount"],
            timeout=20,
        )
        remount_text = f"{remount_out}\n{remount_err}".strip()

    if remount_rc != 0:
        return {
            "available": True,
            "installed": False,
            "error": f"adb remount failed: {remount_text[:500]}",
        }

    push_out, push_err, push_rc = await run_local(
        ["adb", "-s", device_id, "push", str(local_cert_path), system_cert_path],
        timeout=20,
    )
    if push_rc != 0:
        return {
            "available": True,
            "installed": False,
            "error": f"Failed to push the CA certificate into /system: {push_err[:500] or push_out[:500]}",
        }

    chmod_out, chmod_err, chmod_rc = await run_local(
        ["adb", "-s", device_id, "shell", "chmod", "644", system_cert_path],
        timeout=10,
    )
    if chmod_rc != 0:
        return {
            "available": True,
            "installed": False,
            "error": f"Failed to set CA certificate permissions: {chmod_err[:500] or chmod_out[:500]}",
        }

    _, verify_err, verify_rc = await run_local(
        ["adb", "-s", device_id, "shell", "ls", system_cert_path],
        timeout=10,
    )
    if verify_rc != 0:
        return {
            "available": True,
            "installed": False,
            "error": f"Certificate push could not be verified: {verify_err[:500]}",
        }

    if not await _reboot_and_wait(device_id):
        return {
            "available": True,
            "installed": False,
            "error": "Device rebooted after CA install but did not come back online.",
        }

    return {
        "available": True,
        "installed": True,
        "already_present": False,
        "subject_hash": subject_hash,
        "system_path": system_cert_path,
    }


class StartDynamicSessionTool(BaseTool):
    """Start a dynamic analysis session with an Android device/emulator.

    Starts the Android backend, waits for the device to be ready,
    and configures the Frida/drozer bridges.
    """

    name = "start_dynamic_session"
    description = (
        "Start the Android device/emulator for dynamic analysis. "
        "Waits for boot, creates the Frida and drozer bridges, and returns "
        "device info. Leaves the device on direct network access by default; "
        "traffic interception and mitmproxy CA installation are enabled explicitly "
        "with start_traffic_capture so generic runtime setup stays non-disruptive. "
        "Must be called before install_apk, launch_app, or Frida/drozer tools."
    )

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        # Connect ADB to the sibling Android container over the Docker network
        stdout, stderr, rc = await run_local(
            ["adb", "connect", "android:5555"],
            timeout=15,
        )
        if rc != 0:
            return {"error": f"Failed to connect to Android container: {stderr}"}

        device_id = "android:5555"

        if not await _wait_for_device_boot(device_id, max_attempts=30, delay_seconds=5):
            return {
                "error": (
                    "Android device connected but did not finish booting within "
                    "150s. Check that the emulator container is healthy."
                )
            }

        session.device_id = device_id
        session.current_phase = AnalysisPhase.DYNAMIC_SETUP

        # Get Android version
        stdout, _, _ = await run_local(
            ["adb", "shell", "getprop", "ro.build.version.release"],
            timeout=10,
        )
        android_version = stdout.strip()

        # Clear any stale proxy from previous runs so app networking is not
        # implicitly forced through mitmproxy.
        await run_local(
            ["adb", "shell", "settings", "put", "global", "http_proxy", ":0"],
            timeout=10,
        )

        frida_status = await ensure_frida_server_running(device_id)
        session.metadata["frida_server"] = frida_status
        if not frida_status.get("running"):
            return {
                "error": "Frida server is not running on the Android device.",
                "frida_server": frida_status,
            }

        mitmproxy_ca = session.metadata.get("mitmproxy_ca", {})

        # Bridge the emulator's Frida server back into the local adb namespace
        # so the MCP server can talk to it via localhost.
        stdout, stderr, rc = await run_local(
            [
                "adb",
                "-s",
                device_id,
                "forward",
                f"tcp:{config.docker.frida_port}",
                f"tcp:{config.docker.frida_port}",
            ],
            timeout=10,
        )

        if rc != 0:
            return {
                "error": (
                    "Failed to bridge Frida server into the local adb "
                    f"namespace: {stderr[:500] or stdout[:500]}"
                )
            }

        # Bridge drozer's default server port back into the local adb
        # namespace so drozer console can connect via localhost.
        stdout, stderr, rc = await run_local(
            [
                "adb",
                "-s",
                device_id,
                "forward",
                f"tcp:{DROZER_BRIDGE_PORT}",
                f"tcp:{DROZER_BRIDGE_PORT}",
            ],
            timeout=10,
        )

        if rc != 0:
            return {
                "error": (
                    "Failed to bridge drozer into the local adb namespace: "
                    f"{stderr[:500] or stdout[:500]}"
                )
            }

        return {
            "device_id": device_id,
            "android_version": android_version,
            "ready": True,
            "proxy_configured": False,
            "https_interception_ready": bool(mitmproxy_ca.get("installed")),
            "mitmproxy_ca_available": bool(mitmproxy_ca.get("available")),
            "mitmproxy_ca_installed": bool(mitmproxy_ca.get("installed")),
            "mitmproxy_ca_subject_hash": mitmproxy_ca.get("subject_hash"),
            "frida_server_running": True,
            "frida_server_start_method": frida_status.get("start_method"),
            "frida_bridge_configured": True,
            "frida_endpoint": f"{FRIDA_BRIDGE_HOST}:{config.docker.frida_port}",
            "drozer_bridge_configured": True,
            "drozer_endpoint": f"{DROZER_BRIDGE_HOST}:{DROZER_BRIDGE_PORT}",
            **({"mitmproxy_ca_error": mitmproxy_ca["error"]} if mitmproxy_ca.get("error") else {}),
        }


class EnsureFridaServerTool(BaseTool):
    """Ensure the remote frida-server process is running."""

    name = "ensure_frida_server"
    description = (
        "Check whether frida-server is running on the Android device and start "
        "it when the binary is already present on the emulator."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "force_restart": {
                    "type": "boolean",
                    "description": "Stop stale frida-server processes and start it again even if a partial process is detected.",
                    "default": False,
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        if not session.device_id:
            return {"error": "No device connected. Run start_dynamic_session first."}

        result = await ensure_frida_server_running(
            session.device_id,
            force_restart=bool(kwargs.get("force_restart", False)),
        )
        session.metadata["frida_server"] = result
        return result


class InstallApkTool(BaseTool):
    """Install the session's APK on the Android device."""

    name = "install_apk"
    description = (
        "Install the APK from the current session onto the Android device. "
        "The device must be started first with start_dynamic_session."
    )

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        if not session.device_id:
            return {"error": "No device connected. Run start_dynamic_session first."}

        ws = str(session_workspace(session))
        apk = f"{ws}/app.apk"

        stdout, stderr, rc = await run_local(
            ["adb", "install", "-r", apk],
            timeout=60,
        )

        if rc != 0:
            return {"error": f"APK installation failed: {stderr[:500]}"}

        return {
            "installed": True,
            "package": session.package_name or "unknown",
            "output": stdout.strip(),
        }


class LaunchAppTool(BaseTool):
    """Launch the analyzed app on the device."""

    name = "launch_app"
    description = (
        "Launch the app on the Android device. Optionally specify an activity. "
        "Defaults to the app's main/launcher activity."
    )

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "activity": {
                    "type": "string",
                    "description": "Activity to launch (defaults to main activity)",
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        if not session.device_id:
            return {"error": "No device connected."}

        package = session.package_name
        if not package:
            return {"error": "Package name unknown. Run get_apk_metadata first."}

        activity = kwargs.get("activity")

        if activity:
            cmd = ["adb", "shell", "am", "start", "-n", f"{package}/{activity}"]
        else:
            # Launch main activity
            cmd = [
                "adb", "shell", "monkey", "-p", package,
                "-c", "android.intent.category.LAUNCHER", "1",
            ]

        stdout, stderr, rc = await run_local(cmd, timeout=15)

        if rc == 0:
            session.current_phase = AnalysisPhase.RUNTIME

        return {
            "launched": rc == 0,
            "package": package,
            "activity": activity or "(main/launcher)",
            "output": stdout.strip(),
        }


class StopAppTool(BaseTool):
    """Force-stop the analyzed app."""

    name = "stop_app"
    description = "Force-stop the app on the device."

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        package = session.package_name
        if not package:
            return {"error": "Package name unknown."}

        stdout, stderr, rc = await run_local(
            ["adb", "shell", "am", "force-stop", package],
            timeout=10,
        )

        return {"stopped": rc == 0, "package": package}


class GetLogcatTool(BaseTool):
    """Capture and filter logcat output from the device.

    Automatically creates findings for sensitive data leaks in logs
    (passwords, tokens, keys).
    """

    name = "get_logcat"
    description = (
        "Get filtered logcat output from the device. Optionally filter by tag "
        "or grep pattern. Automatically flags sensitive data in logs."
    )

    # Patterns that indicate sensitive data in logcat
    SENSITIVE_PATTERNS = [
        (re.compile(r"password\s*[:=]\s*\S+", re.IGNORECASE), "Password in logcat"),
        (re.compile(r"token\s*[:=]\s*\S+", re.IGNORECASE), "Token in logcat"),
        (re.compile(r"(api[_-]?key|apikey)\s*[:=]\s*\S+", re.IGNORECASE), "API key in logcat"),
        (re.compile(r"(secret|private[_-]?key)\s*[:=]\s*\S+", re.IGNORECASE), "Secret in logcat"),
    ]

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "Active analysis session ID",
                },
                "filter_tag": {
                    "type": "string",
                    "description": "Logcat tag filter (e.g. 'MyApp')",
                },
                "lines": {
                    "type": "integer",
                    "description": "Number of lines to capture (default: 200)",
                    "default": 200,
                },
                "grep_pattern": {
                    "type": "string",
                    "description": "Grep pattern to filter output",
                },
                "app_only": {
                    "type": "boolean",
                    "description": (
                        "Filter logcat to only the session's application process "
                        "(uses --pid=<pidof package>). The app must be running. "
                        "Default: false."
                    ),
                    "default": False,
                },
            },
            "required": ["session_id"],
        }

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        lines = kwargs.get("lines", 200)
        filter_tag = kwargs.get("filter_tag")
        grep_pattern = kwargs.get("grep_pattern")
        app_only = kwargs.get("app_only", False)

        cmd = ["adb", "logcat", "-d"]

        if app_only:
            package = session.package_name
            if not package:
                return {
                    "error": "Package name unknown — run get_apk_metadata first.",
                    "hint": "app_only requires session.package_name to be set.",
                }

            pid_out, pid_err, pid_rc = await run_local(
                ["adb", "shell", "pidof", "-s", package],
                timeout=10,
            )
            pid = pid_out.strip()
            if not pid or not pid.isdigit():
                return {
                    "error": f"Could not resolve PID for '{package}' — is the app running?",
                    "pidof_output": pid_out.strip(),
                    "hint": "Launch the app first with launch_app, then call get_logcat again.",
                }

            cmd += [f"--pid={pid}"]
            logger.info("Filtering logcat to PID {} ({})", pid, package)

        stdout, stderr, rc = await run_local(cmd, timeout=15)

        log_lines = stdout.splitlines()[-lines:]

        # Filter by tag (case-insensitive match against the tag column)
        # ADB's -s flag is exact/case-sensitive, so we do it ourselves.
        # Logcat brief/threadtime format: <priority>/<tag>( pid): ...
        if filter_tag:
            tag_pattern = re.compile(r"[A-Z]/([^(:\s]+)", re.IGNORECASE)
            filtered = []
            for line in log_lines:
                m = tag_pattern.search(line)
                if m and filter_tag.lower() in m.group(1).lower():
                    filtered.append(line)
            log_lines = filtered

        # Apply grep filter
        if grep_pattern:
            pattern = re.compile(grep_pattern, re.IGNORECASE)
            log_lines = [l for l in log_lines if pattern.search(l)]

        # Check for sensitive data leaks
        findings_created = []
        for line in log_lines:
            for pattern, title in self.SENSITIVE_PATTERNS:
                if pattern.search(line):
                    finding = Finding(
                        title=title,
                        severity=Severity.HIGH,
                        category=FindingCategory.SENSITIVE_DATA_EXPOSURE,
                        description=(
                            f"Sensitive data was found in logcat output. "
                            f"Log data can be read by other apps on older Android versions."
                        ),
                        evidence=line[:300],
                        location="logcat",
                        tool="get_logcat",
                        phase=AnalysisPhase.RUNTIME.value,
                        cwe_id="CWE-532",
                        recommendation="Remove sensitive data from log statements.",
                    )
                    if session.add_finding(finding):
                        findings_created.append(finding.to_dict())
                    break  # One finding per line

        result: dict[str, Any] = {
            "total_lines": len(log_lines),
            "log_lines": log_lines[:lines],
            "findings_created": len(findings_created),
        }
        if app_only:
            result["filtered_by_pid"] = pid
            result["filtered_by_package"] = package
        return result


class ListRunningProcessesTool(BaseTool):
    """List running processes on the device."""

    name = "list_running_processes"
    description = "List running processes on the Android device."

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        stdout, _, rc = await run_local(
            ["adb", "shell", "ps", "-A"],
            timeout=10,
        )

        if rc != 0:
            return {"error": "Failed to list processes"}

        processes = []
        lines = stdout.strip().splitlines()
        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 9:
                processes.append({
                    "user": parts[0],
                    "pid": parts[1],
                    "name": parts[-1],
                })

        return {
            "total_processes": len(processes),
            "processes": processes,
        }


class TakeScreenshotTool(BaseTool):
    """Take a screenshot of the device screen."""

    name = "take_screenshot"
    description = "Take a screenshot of the device screen. Returns the image path."

    async def run(self, session: Optional[AnalysisSession], **kwargs: Any) -> dict:
        if session is None:
            return {"error": "No active session"}

        ws = str(session_workspace(session))
        remote_path = "/sdcard/screenshot.png"
        local_path = f"{ws}/screenshot.png"

        # Capture
        await run_local(
            ["adb", "shell", "screencap", "-p", remote_path],
            timeout=10,
        )

        # Pull
        stdout, stderr, rc = await run_local(
            ["adb", "pull", remote_path, local_path],
            timeout=10,
        )

        if rc != 0:
            return {"error": f"Screenshot failed: {stderr[:200]}"}

        return {
            "screenshot_path": local_path,
            "saved": True,
        }
