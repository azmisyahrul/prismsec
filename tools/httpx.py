"""
httpx tool wrapper for MCP server.

Wraps httpx for web probing and fingerprinting with JSON output parsing.
"""

from __future__ import annotations

import logging
from typing import Any

from .base import (
    ToolWrapper,
    ToolResult,
    run_command,
    validate_target,
)
from parsers.text_parser import parse_httpx_output

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 120


class HttpxTool(ToolWrapper):
    """Wrapper for httpx web prober."""

    @property
    def tool_name(self) -> str:
        return "httpx"

    @property
    def tool_description(self) -> str:
        return "Web probing and fingerprinting with httpx"

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "targets": {"type": "string", "description": "Comma-separated URLs/hosts"},
                "ports": {"type": "string", "description": "Ports to probe"},
                "tech_detect": {"type": "boolean", "description": "Enable tech detection"},
                "follow_redirects": {"type": "boolean", "description": "Follow redirects"},
                "status_codes": {"type": "string", "description": "Status code filter"},
                "timeout": {"type": "integer", "description": "Max seconds"},
            },
            "required": ["targets"],
        }

    async def scan(
        self, targets: str, ports: str = "", tech_detect: bool = True,
        follow_redirects: bool = True, status_codes: str = "", timeout: int = 0,
    ) -> dict[str, Any]:
        """Probe web targets for alive services and fingerprinting."""
        try:
            targets = validate_target(targets)
        except ValueError as e:
            return self.error_response(str(e), target=targets)

        timeout = timeout or _DEFAULT_TIMEOUT

        target_list = [t.strip() for t in targets.split(",") if t.strip()]
        stdin_data = "\n".join(target_list)

        cmd = ["httpx", "-json", "-silent"]
        if tech_detect:
            cmd.append("-td")
        if follow_redirects:
            cmd.append("-fr")
        if ports:
            cmd.extend(["-ports", ports])
        if status_codes:
            cmd.extend(["-sc", status_codes])
        cmd.extend(["-l", "-"])

        result = await run_command(cmd, timeout=timeout, stdin_data=stdin_data)

        if result.error and "timed out" in result.error:
            return self.error_response(f"httpx timed out after {timeout}s", target=targets)

        parsed = parse_httpx_output(result.stdout)

        alive_count = len(parsed)
        status_summary: dict[str, int] = {}
        tech_summary: dict[str, int] = {}
        for entry in parsed:
            code = str(entry.get("status_code", 0))
            status_summary[code] = status_summary.get(code, 0) + 1
            for tech in entry.get("technologies", []):
                tech_summary[tech] = tech_summary.get(tech, 0) + 1

        return {
            "status": "success" if result.success else "error",
            "targets_input": targets,
            "alive_count": alive_count,
            "status_summary": status_summary,
            "technologies": tech_summary,
            "results": parsed,
        }

    async def execute(self, **kwargs: Any) -> ToolResult:
        result = await self.scan(**kwargs)
        return ToolResult(
            success=result.get("status") == "success",
            stdout=str(result), stderr=result.get("error", ""),
            exit_code=0 if result.get("status") == "success" else -1, parsed=result,
        )


httpx_tool = HttpxTool()


async def httpx_scan(targets: str, ports: str = "", tech_detect: bool = True, follow_redirects: bool = True, status_codes: str = "", timeout: int = 0) -> dict[str, Any]:
    """httpx web probing and fingerprinting."""
    return await httpx_tool.scan(targets, ports, tech_detect, follow_redirects, status_codes, timeout)
