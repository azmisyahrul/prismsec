"""Base tool wrapper and async subprocess helper for MCP Recon.

Every security tool wrapper inherits from ToolWrapper and reuses run_command()
for safe, async subprocess execution without shell injection risk.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Input validation utilities
# ---------------------------------------------------------------------------

_SHELL_CHARS = set(";&|`$(){}[]!#~<>\\")
_PATH_CHARS = set(";&|`$!#~<>\\\"'")


def validate_target(target: str) -> str:
    """Validate and sanitize a target string (IP, hostname, CIDR, URL)."""
    if not target or not target.strip():
        raise ValueError("Target cannot be empty")
    target = target.strip()
    if len(target) > 2048:
        raise ValueError("Target string too long (max 2048 chars)")
    if any(c in _SHELL_CHARS for c in target):
        raise ValueError(f"Target contains unsafe characters: {target}")
    return target


def validate_url(url: str) -> str:
    """Basic URL validation."""
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty")
    if not url.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    if any(c in _SHELL_CHARS for c in url):
        raise ValueError("URL contains unsafe characters")
    return url


def validate_port(port: int) -> int:
    """Validate a port number."""
    if not (1 <= port <= 65535):
        raise ValueError(f"Port must be between 1 and 65535, got {port}")
    return port


def validate_severity(severity: str) -> str:
    """Validate nuclei severity filter."""
    valid = {"info", "low", "medium", "high", "critical"}
    parts = [s.strip().lower() for s in severity.split(",")]
    for p in parts:
        if p not in valid:
            raise ValueError(
                f"Invalid severity '{p}'. Must be one of: {', '.join(sorted(valid))}"
            )
    return ",".join(parts)


def validate_path(path: str) -> str:
    """Validate a file path (wordlist, etc.)."""
    if not path or not path.strip():
        raise ValueError("Path cannot be empty")
    path = path.strip()
    if len(path) > 4096:
        raise ValueError("Path too long (max 4096 chars)")
    if any(c in _PATH_CHARS for c in path):
        raise ValueError(f"Path contains unsafe characters: {path}")
    return path


# ---------------------------------------------------------------------------
# Tool existence check
# ---------------------------------------------------------------------------

class ToolNotFoundError(FileNotFoundError):
    """Raised when a required security tool is not installed."""


def require_tool(name: str) -> str:
    """Find tool binary path or raise ToolNotFoundError.

    Searches PATH and common install locations (~/go/bin).
    """
    path = shutil.which(name)
    if path:
        return path

    go_bin = os.path.expanduser("~/go/bin")
    candidate = os.path.join(go_bin, name)
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate

    raise ToolNotFoundError(
        f"{name} not found in PATH. Install it before using this tool."
    )


def check_tool(name: str) -> dict[str, Any]:
    """Check if a tool is installed and return status dict."""
    try:
        path = require_tool(name)
        return {"installed": True, "path": path}
    except ToolNotFoundError as e:
        return {"installed": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Structured output container
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ToolResult:
    """Immutable container for tool execution results.

    Attributes:
        success: Whether the tool exited with code 0.
        stdout: Captured standard output.
        stderr: Captured standard error.
        exit_code: Process exit code (0 = success).
        parsed: Structured/parsed output (tool-specific).
        error: Human-readable error message, if any.
        command: The command that was executed (for auditability).
    """

    success: bool
    stdout: str
    stderr: str
    exit_code: int
    parsed: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    command: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict for JSON responses."""
        return {
            "success": self.success,
            "exit_code": self.exit_code,
            "stdout": self.stdout[:4096],
            "stderr": self.stderr[:2048],
            "parsed": self.parsed,
            "error": self.error,
            "command": self.command,
        }

    def to_json(self) -> str:
        """Serialise to a JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)


# ---------------------------------------------------------------------------
# Async command runner
# ---------------------------------------------------------------------------

async def run_command(
    args: list[str],
    *,
    timeout: float = 300.0,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    stdin_data: str | bytes | None = None,
) -> ToolResult:
    """Execute a command asynchronously via ``asyncio.create_subprocess_exec``.

    **Never uses ``shell=True``** — every argument is passed as a separate
    list element, eliminating shell injection vectors.

    Args:
        args: Command and arguments as a list.
        timeout: Maximum seconds to wait before killing the process.
        cwd: Working directory for the subprocess.
        env: Extra environment variables (merged with current env).
        stdin_data: Optional data to write to the process's stdin.

    Returns:
        A ``ToolResult`` with stdout, stderr, exit code, and any errors.
    """
    if not args:
        raise ValueError("args must not be empty")

    command_str = " ".join(args)
    logger.info("Running: %s", command_str)

    # Verify the binary exists before spawning
    binary = args[0]
    if not shutil.which(binary):
        # Check ~/go/bin as fallback
        go_bin = os.path.expanduser("~/go/bin")
        go_path = os.path.join(go_bin, binary)
        if not (os.path.isfile(go_path) and os.access(go_path, os.X_OK)):
            return ToolResult(
                success=False,
                stdout="",
                stderr=f"Binary not found: {binary}",
                exit_code=-1,
                error=f"Required binary '{binary}' is not installed or not in PATH",
                command=command_str,
            )

    # Merge env if provided
    process_env = None
    if env:
        process_env = {**os.environ, **env}

    try:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=process_env,
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(
                    input=stdin_data.encode() if isinstance(stdin_data, str) else stdin_data
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return ToolResult(
                success=False,
                stdout="",
                stderr="",
                exit_code=-1,
                error=f"Command timed out after {timeout:.0f}s",
                command=command_str,
            )

        stdout = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
        stderr = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""
        exit_code = process.returncode or 0

        return ToolResult(
            success=exit_code == 0,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            command=command_str,
        )

    except FileNotFoundError as exc:
        logger.error("Failed to execute %s: %s", binary, exc)
        return ToolResult(
            success=False,
            stdout="",
            stderr=str(exc),
            exit_code=-1,
            error=f"Failed to execute '{binary}': {exc}",
            command=command_str,
        )
    except OSError as exc:
        logger.error("OS error running %s: %s", command_str, exc)
        return ToolResult(
            success=False,
            stdout="",
            stderr=str(exc),
            exit_code=-1,
            error=f"OS error: {exc}",
            command=command_str,
        )


# ---------------------------------------------------------------------------
# Abstract tool wrapper base class
# ---------------------------------------------------------------------------

class ToolWrapper(ABC):
    """Base class for all MCP Recon tool wrappers.

    Subclasses must implement:
    - ``tool_name``: unique identifier for the MCP tool
    - ``tool_description``: human-readable description
    - ``input_schema``: JSON Schema dict for the tool's parameters
    - ``execute()``: core logic that calls ``run_command`` and parses output
    """

    def __init__(self) -> None:
        logger.debug("Tool wrapper registered: %s", self.tool_name)

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Unique tool identifier used in MCP registration."""
        ...

    @property
    @abstractmethod
    def tool_description(self) -> str:
        """Human-readable description shown to LLM consumers."""
        ...

    @property
    @abstractmethod
    def input_schema(self) -> dict[str, Any]:
        """JSON Schema describing the tool's input parameters."""
        ...

    @abstractmethod
    async def execute(self, **kwargs: Any) -> ToolResult:
        """Run the tool with the given parameters."""
        ...

    def to_mcp_tool(self) -> dict[str, Any]:
        """Return an MCP-compatible tool definition dict."""
        return {
            "name": self.tool_name,
            "description": self.tool_description,
            "inputSchema": self.input_schema,
        }

    @staticmethod
    def error_response(message: str, **extra: Any) -> dict[str, Any]:
        """Create a standardized error response dict."""
        return {"status": "error", "error": message, **extra}

    @staticmethod
    def success_response(data: Any = None, **extra: Any) -> dict[str, Any]:
        """Create a standardized success response dict."""
        return {"status": "success", "data": data, **extra}

    def __repr__(self) -> str:
        return f"<{type(self).__name__} tool_name={self.tool_name!r}>"
