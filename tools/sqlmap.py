"""
SQLMap tool wrapper for MCP server.

Wraps sqlmap for SQL injection testing with text output parsing.
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
from parsers.text_parser import parse_sqlmap_output

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 600


class SqlmapTool(ToolWrapper):
    """Wrapper for sqlmap SQL injection tester."""

    @property
    def tool_name(self) -> str:
        return "sqlmap"

    @property
    def tool_description(self) -> str:
        return "SQL injection testing with SQLMap"

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Target URL with parameter"},
                "data": {"type": "string", "description": "POST data string"},
                "level": {"type": "integer", "description": "Test level 1-5"},
                "risk": {"type": "integer", "description": "Risk level 1-3"},
                "tamper": {"type": "string", "description": "Tamper script name"},
                "timeout": {"type": "integer", "description": "Max seconds"},
            },
            "required": ["target_url"],
        }

    async def scan(
        self, target_url: str, data: str = "", level: int = 1,
        risk: int = 1, tamper: str = "", timeout: int = 0,
    ) -> dict[str, Any]:
        """Test a URL for SQL injection vulnerabilities."""
        try:
            target_url = validate_target(target_url)
        except ValueError as e:
            return self.error_response(str(e), target=target_url)

        if not (1 <= level <= 5):
            return self.error_response(f"Level must be 1-5, got {level}", target=target_url)
        if not (1 <= risk <= 3):
            return self.error_response(f"Risk must be 1-3, got {risk}", target=target_url)

        timeout = timeout or _DEFAULT_TIMEOUT

        cmd = [
            "sqlmap", "-u", target_url, "--batch",
            "--level", str(level), "--risk", str(risk),
            "--output-dir=/tmp/sqlmap_out",
        ]
        if data:
            cmd.extend(["--data", data])
        if tamper:
            cmd.extend(["--tamper", tamper])

        result = await run_command(cmd, timeout=timeout)

        if result.error and "timed out" in result.error:
            return self.error_response(f"sqlmap timed out after {timeout}s", target=target_url)

        parsed = parse_sqlmap_output(result.stdout)

        combined = (result.stdout + result.stderr).lower()
        if "sqlmap identified" in combined or "is vulnerable" in combined:
            parsed["injectable"] = True

        for line in result.stderr.split("\n"):
            line = line.strip()
            if "back-end dbms:" in line.lower():
                parsed["summary"] = line

        max_output_len = 4000
        output_excerpt = result.stdout[:max_output_len]
        if len(result.stdout) > max_output_len:
            output_excerpt += f"\n... (truncated, {len(result.stdout)} total chars)"

        return {
            "status": "success" if result.success else "error",
            "target": target_url,
            "injectable": parsed["injectable"],
            "injection_points": parsed["injection_points"],
            "parameters": parsed["parameters"],
            "databases": parsed["databases"],
            "techniques": parsed["techniques"],
            "summary": parsed["summary"],
            "total_injection_points": parsed["total_injection_points"],
            "output_excerpt": output_excerpt,
        }

    async def execute(self, **kwargs: Any) -> ToolResult:
        result = await self.scan(**kwargs)
        return ToolResult(
            success=result.get("status") == "success",
            stdout=str(result), stderr=result.get("error", ""),
            exit_code=0 if result.get("status") == "success" else -1, parsed=result,
        )


sqlmap_tool = SqlmapTool()


async def sqlmap_scan(target_url: str, data: str = "", level: int = 1, risk: int = 1, tamper: str = "", timeout: int = 0) -> dict[str, Any]:
    """SQLMap SQL injection testing."""
    return await sqlmap_tool.scan(target_url, data, level, risk, tamper, timeout)
