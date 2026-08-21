"""Async subprocess runner with timeout management and structured output.

Wraps ``asyncio.create_subprocess_exec`` with:
- Configurable timeouts
- Resource limits (max output size)
- Audit logging
- Structured ``RunResult`` containers

This module is the low-level execution layer; most tool wrappers call
``run_command()`` from ``tools.base`` instead of using this directly.
Use ``AsyncRunner`` when you need reusable runner instances with custom
configurations.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default limits
DEFAULT_TIMEOUT: float = 300.0  # 5 minutes
MAX_TIMEOUT: float = 3600.0  # 1 hour
MAX_OUTPUT_BYTES: int = 10 * 1024 * 1024  # 10 MB


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class RunConfig:
    """Configuration for an async subprocess run.

    Attributes:
        timeout: Maximum seconds before the process is killed.
        cwd: Working directory.
        env: Extra environment variables.
        max_output: Maximum bytes to read from stdout/stderr.
        binary: Override the binary path (auto-detected by default).
    """

    timeout: float = DEFAULT_TIMEOUT
    cwd: str | Path | None = None
    env: dict[str, str] | None = None
    max_output: int = MAX_OUTPUT_BYTES
    binary: str | None = None


# ---------------------------------------------------------------------------
# Structured result
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class RunResult:
    """Result of an async subprocess execution.

    Attributes:
        success: Whether the process exited with code 0.
        exit_code: The process return code.
        stdout: Decoded standard output.
        stderr: Decoded standard error.
        duration_ms: Wall-clock time in milliseconds.
        timed_out: Whether the run was killed due to timeout.
        command: The full command string (for logging / audit).
        error: Human-readable error, if any.
    """

    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False
    command: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict for JSON responses."""
        return {
            "success": self.success,
            "exit_code": self.exit_code,
            "stdout": self.stdout[:4096],
            "stderr": self.stderr[:2048],
            "duration_ms": round(self.duration_ms, 1),
            "timed_out": self.timed_out,
            "command": self.command,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Async runner
# ---------------------------------------------------------------------------

class AsyncRunner:
    """Reusable async subprocess runner with configuration.

    Unlike the standalone ``run_command()`` function in ``tools.base``,
    this class allows callers to pre-configure timeout, env, and cwd
    across multiple runs.

    Example::

        runner = AsyncRunner(RunConfig(timeout=60, cwd="/tmp"))
        result = await runner.run(["nmap", "-sV", "10.0.0.1"])
        print(result.to_dict())
    """

    def __init__(self, config: RunConfig | None = None) -> None:
        self._config = config or RunConfig()

    @property
    def config(self) -> RunConfig:
        return self._config

    async def run(
        self,
        args: list[str],
        *,
        config_override: RunConfig | None = None,
        stdin_data: str | bytes | None = None,
    ) -> RunResult:
        """Execute a command asynchronously.

        Args:
            args: Command and arguments (never shell-joined).
            config_override: Per-run config override (merges with instance config).
            stdin_data: Optional data to pipe to stdin.

        Returns:
            A ``RunResult`` with exit code, stdout, stderr, and timing info.

        Raises:
            ValueError: If *args* is empty.
        """
        if not args:
            raise ValueError("args must not be empty")

        cfg = config_override or self._config
        binary = cfg.binary or args[0]
        command_str = " ".join(args)

        # Validate binary exists
        if not shutil.which(binary):
            return RunResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr="",
                duration_ms=0,
                error=f"Binary not found: {binary}",
                command=command_str,
            )

        # Clamp timeout
        timeout = min(max(cfg.timeout, 1.0), MAX_TIMEOUT)

        start = time.monotonic()
        timed_out = False

        logger.info("Runner executing: %s (timeout=%.0fs)", command_str, timeout)

        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cfg.cwd,
                env=cfg.env,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(input=stdin_data),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                timed_out = True
                process.kill()
                await process.wait()
                stdout_bytes, stderr_bytes = b"", b""
                logger.warning("Runner: %s timed out after %.0fs", command_str, timeout)

            duration_ms = (time.monotonic() - start) * 1000
            exit_code = process.returncode or 0

            # Decode and cap output
            stdout = _decode_and_cap(stdout_bytes, cfg.max_output)
            stderr = _decode_and_cap(stderr_bytes, cfg.max_output // 2)

            return RunResult(
                success=exit_code == 0 and not timed_out,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
                timed_out=timed_out,
                command=command_str,
            )

        except FileNotFoundError as exc:
            duration_ms = (time.monotonic() - start) * 1000
            return RunResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(exc),
                duration_ms=duration_ms,
                error=f"Binary not found: {binary}",
                command=command_str,
            )
        except OSError as exc:
            duration_ms = (time.monotonic() - start) * 1000
            return RunResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(exc),
                duration_ms=duration_ms,
                error=f"OS error: {exc}",
                command=command_str,
            )

    async def run_with_verify(
        self,
        args: list[str],
        *,
        config_override: RunConfig | None = None,
        stdin_data: str | bytes | None = None,
        expected_exit_codes: tuple[int, ...] = (0,),
    ) -> RunResult:
        """Run a command and verify the exit code is in the expected set.

        Useful for tools where exit code 0 means "found something" but
        exit code 1 might mean "no results" (both are valid).

        Args:
            args: Command and arguments.
            config_override: Optional config override.
            stdin_data: Optional stdin data.
            expected_exit_codes: Tuple of acceptable exit codes.

        Returns:
            A ``RunResult`` with ``success`` set based on exit code membership.
        """
        result = await self.run(args, config_override=config_override, stdin_data=stdin_data)
        return RunResult(
            success=result.exit_code in expected_exit_codes,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_ms=result.duration_ms,
            timed_out=result.timed_out,
            command=result.command,
            error=result.error,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode_and_cap(data: bytes | None, max_bytes: int) -> str:
    """Decode bytes to string, capping at *max_bytes*."""
    if data is None:
        return ""
    if len(data) > max_bytes:
        data = data[:max_bytes]
    return data.decode("utf-8", errors="replace")
