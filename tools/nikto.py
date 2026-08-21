"""
Nikto tool wrapper for MCP server.

Wraps nikto for web server vulnerability scanning with text output parsing.
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
    validate_port,
)
from parsers.text_parser import parse_nikto_output

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 600


class NiktoTool(ToolWrapper):
    """Wrapper for nikto web vulnerability scanner."""

    @property
    def tool_name(self) -> str:
        return "nikto"

    @property
    def tool_description(self) -> str:
        return "Web server vulnerability scanning with Nikto"

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target hostname or IP"},
                "port": {"type": "integer", "description": "Target port"},
                "ssl": {"type": "boolean", "description": "Enable SSL mode"},
                "timeout": {"type": "integer", "description": "Max seconds"},
            },
            "required": ["target"],
        }

    async def scan(
        self, target: str, port: int = 80, ssl: bool = False, timeout: int = 0,
    ) -> dict[str, Any]:
        """Run nikto web server vulnerability scan."""
        try:
            target = validate_target(target)
            port = validate_port(port)
        except ValueError as e:
            return self.error_response(str(e), target=target)

        timeout = timeout or _DEFAULT_TIMEOUT

        cmd = [
            "nikto", "-h", target, "-p", str(port),
            "-Format", "json", "-output", "-", "-nointeractive",
        ]
        if ssl:
            cmd.append("-ssl")

        result = await run_command(cmd, timeout=timeout)

        if result.error and "timed out" in result.error:
            return self.error_response(f"nikto scan timed out after {timeout}s", target=f"{target}:{port}")

        parsed = parse_nikto_output(result.stdout)

        # Try JSON parsing from stdout
        try:
            json_data = _json.loads(result.stdout)
            if isinstance(json_data, dict):
                if "vulnerabilities" in json_data:
                    parsed["findings"] = json_data["vulnerabilities"]
                if "host" in json_data:
                    parsed["server_info"] = json_data.get("host", parsed["server_info"])
        except (_json.JSONDecodeError, TypeError):
            pass

        return {
            "status": "success" if result.success else "error",
            "target": target, "port": port,
            "server_info": parsed.get("server_info", {}),
            "findings_count": parsed.get("total", len(parsed.get("findings", []))),
            "findings": parsed.get("findings", []),
            "errors": parsed.get("errors", []),
        }

    async def execute(self, **kwargs: Any) -> ToolResult:
        result = await self.scan(**kwargs)
        return ToolResult(
            success=result.get("status") == "success",
            stdout=str(result), stderr=result.get("error", ""),
            exit_code=0 if result.get("status") == "success" else -1, parsed=result,
        )


nikto_tool = NiktoTool()


async def nikto_scan(target: str, port: int = 80, ssl: bool = False, timeout: int = 0) -> dict[str, Any]:
    """Nikto web vulnerability scan."""
    return await nikto_tool.scan(target, port, ssl, timeout)
