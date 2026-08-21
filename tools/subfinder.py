"""
Subfinder tool wrapper for MCP server.

Wraps subfinder for subdomain enumeration with output parsing.
"""

from __future__ import annotations

import json as _json
import logging
from typing import Any

from .base import (
    ToolWrapper,
    ToolResult,
    run_command,
    validate_target,
)
from parsers.text_parser import parse_subfinder_output

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 120


class SubfinderTool(ToolWrapper):
    """Wrapper for subfinder subdomain enumerator."""

    @property
    def tool_name(self) -> str:
        return "subfinder"

    @property
    def tool_description(self) -> str:
        return "Passive subdomain enumeration with Subfinder"

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain"},
                "sources": {"type": "string", "description": "Comma-separated sources"},
                "timeout": {"type": "integer", "description": "Max seconds"},
            },
            "required": ["target"],
        }

    async def scan(
        self, target: str, sources: str = "", silent: bool = True, timeout: int = 0,
    ) -> dict[str, Any]:
        """Enumerate subdomains for a domain."""
        try:
            target = validate_target(target)
        except ValueError as e:
            return self.error_response(str(e), target=target)

        timeout = timeout or _DEFAULT_TIMEOUT

        cmd = ["subfinder", "-d", target, "-silent"]
        if sources:
            cmd.extend(["-sources", sources])

        result = await run_command(cmd, timeout=timeout)

        if result.error and "timed out" in result.error:
            return self.error_response(f"subfinder timed out after {timeout}s", target=target)

        # Try JSON output parsing first
        subdomains: list[str] = []
        try:
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = _json.loads(line)
                    if isinstance(data, dict):
                        host = data.get("host", "")
                        if host:
                            subdomains.append(host)
                    elif isinstance(data, str):
                        subdomains.append(data)
                except _json.JSONDecodeError:
                    pass
        except Exception:
            pass

        # Fallback to text parsing
        if not subdomains:
            subdomains = parse_subfinder_output(result.stdout)

        subdomains = sorted(set(subdomains))

        return {
            "status": "success" if result.success else "error",
            "target": target,
            "subdomains_count": len(subdomains),
            "subdomains": subdomains,
            "sources": sources if sources else "all",
        }

    async def execute(self, **kwargs: Any) -> ToolResult:
        result = await self.scan(**kwargs)
        return ToolResult(
            success=result.get("status") == "success",
            stdout=str(result), stderr=result.get("error", ""),
            exit_code=0 if result.get("status") == "success" else -1, parsed=result,
        )


subfinder_tool = SubfinderTool()


async def subfinder_scan(target: str, sources: str = "", silent: bool = True, timeout: int = 0) -> dict[str, Any]:
    """Subfinder subdomain enumeration."""
    return await subfinder_tool.scan(target, sources, silent, timeout)
