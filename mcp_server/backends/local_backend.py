"""Execution helpers for the active Mobilytix runtime.

Runs commands directly where the MCP server process is running.
In the current Docker Compose setup, that means inside the static container.
"""

from __future__ import annotations

import asyncio
import os

from loguru import logger


async def _drain_stream(stream: asyncio.StreamReader) -> bytes:
    """Read a subprocess stream until EOF."""
    chunks: list[bytes] = []
    while True:
        chunk = await stream.read(8192)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


async def run_local(
    command: list[str],
    timeout: int = 300,
    cwd: str | None = None,
    keep_stdin_open: bool = False,
    stdin_data: str | None = None,
) -> tuple[str, str, int]:
    """Execute a command locally as a subprocess.

    In the current architecture the MCP server runs inside the static
    container, so tools can execute binaries on ``$PATH`` directly.

    Args:
        command: Command and arguments to execute.
        timeout: Maximum seconds to wait.
        cwd: Optional working directory.
        keep_stdin_open: Keep stdin open instead of inheriting the parent's
            (often ``/dev/null`` in a container).  Required for tools like
            ``frida -q`` that exit on stdin EOF before their scripts produce
            output.
        stdin_data: Optional initial stdin payload to write without closing
            the stream. Useful for tools that prompt once and then continue
            running, such as Frida CodeShare trust confirmation.

    Returns:
        Tuple of (stdout, stderr, return_code).
    """
    logger.debug("Local exec: {}", " ".join(command[:6]))

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE if keep_stdin_open or stdin_data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )

        if keep_stdin_open:
            if stdin_data and proc.stdin is not None:
                proc.stdin.write(stdin_data.encode("utf-8"))
                await proc.stdin.drain()

            # Read stdout/stderr without closing stdin so the child process
            # stays alive (frida -q exits on stdin EOF).
            stdout_task = asyncio.create_task(_drain_stream(proc.stdout))
            stderr_task = asyncio.create_task(_drain_stream(proc.stderr))

            timed_out = False
            try:
                await asyncio.wait_for(proc.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                timed_out = True

            # Signal the child to detach, then force-kill.
            if proc.returncode is None:
                try:
                    proc.stdin.close()
                except Exception:
                    pass
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await proc.wait()

            stdout_bytes = await asyncio.wait_for(stdout_task, timeout=5)
            stderr_bytes = await asyncio.wait_for(stderr_task, timeout=5)

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            rc = proc.returncode if proc.returncode is not None else -1

            if timed_out:
                timeout_msg = f"Command timed out after {timeout}s"
                stderr = "\n".join(
                    chunk
                    for chunk in (stderr, timeout_msg)
                    if chunk and chunk.strip()
                )
                rc = -1

            if rc != 0 and not timed_out:
                logger.warning(
                    "Command exited {}: {} stderr={}",
                    rc,
                    " ".join(command[:3]),
                    stderr[:200],
                )

            return stdout, stderr, rc

        # Default path: inherit stdin, use communicate().
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(
                input=stdin_data.encode("utf-8") if stdin_data is not None else None
            ),
            timeout=timeout,
        )
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        rc = proc.returncode or 0

        if rc != 0:
            logger.warning(
                "Command exited {}: {} stderr={}",
                rc,
                " ".join(command[:3]),
                stderr[:200],
            )

        return stdout, stderr, rc

    except asyncio.TimeoutError:
        logger.error("Command timed out after {}s: {}", timeout, command[:3])
        if proc:
            proc.kill()
            stdout_bytes, stderr_bytes = await proc.communicate()
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            timeout_msg = f"Command timed out after {timeout}s"
            stderr = "\n".join(
                chunk for chunk in (stderr, timeout_msg) if chunk and chunk.strip()
            )
            return stdout, stderr, -1
        return "", f"Command timed out after {timeout}s", -1
    except FileNotFoundError:
        cmd_name = command[0] if command else "unknown"
        logger.error("{} not found on PATH", cmd_name)
        return "", f"{cmd_name} is not installed or not in PATH", -1
    except Exception as e:
        logger.exception("Local exec failed: {}", e)
        return "", str(e), -1


async def read_file_content(path: str) -> tuple[str, str, int]:
    """Read a file from the local filesystem.

    Reads a file from the current runtime filesystem.
    """
    try:
        if not os.path.exists(path):
            return "", f"File not found: {path}", 1
        with open(path, "r", errors="replace") as f:
            return f.read(), "", 0
    except Exception as e:
        return "", str(e), 1


async def ensure_directory(path: str) -> None:
    """Create a directory (and parents) if it doesn't exist.

    Creates a directory in the current runtime filesystem.
    """
    os.makedirs(path, exist_ok=True)
