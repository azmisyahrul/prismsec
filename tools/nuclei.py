"""
Nuclei tool wrapper for MCP server.

Wraps nuclei with JSON output parsing, supporting scan, scan_severity,
and scan_template operations.
"""

from __future__ import annotations

import logging
from typing import Any

from .base import (
    ToolWrapper,
    ToolResult,
    run_command,
    validate_target,
    validate_severity,
)
from parsers.json_parser import parse_json_lines, parse_nuclei_findings

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 600


class NucleiTool(ToolWrapper):
    """Wrapper for nuclei vulnerability scanner."""

    @property
    def tool_name(self) -> str:
        return "nuclei"

    @property
    def tool_description(self) -> str:
        return "Vulnerability scanning with Nuclei templates"

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "templates": {"type": "string", "description": "Template filter"},
                "severity": {"type": "string", "description": "Severity filter"},
                "rate_limit": {"type": "integer", "description": "Requests/sec"},
                "tags": {"type": "string", "description": "Tag filter"},
                "timeout": {"type": "integer", "description": "Max seconds"},
            },
            "required": ["target"],
        }

    async def scan(
        self,
        target: str,
        templates: str = "",
        severity: str = "",
        rate_limit: int = 150,
        tags: str = "",
        timeout: int = 0,
    ) -> dict[str, Any]:
        """Run nuclei vulnerability scan."""
        try:
            target = validate_target(target)
        except ValueError as e:
            return self.error_response(str(e), target=target)

        if severity:
            try:
                severity = validate_severity(severity)
            except ValueError as e:
                return self.error_response(str(e), target=target)

        timeout = timeout or _DEFAULT_TIMEOUT

        cmd = ["nuclei", "-u", target, "-jsonl", "-silent"]
        cmd.extend(["-rate-limit", str(rate_limit)])

        if templates:
            cmd.extend(["-t", templates])
        if severity:
            cmd.extend(["-severity", severity])
        if tags:
            cmd.extend(["-tags", tags])

        result = await run_command(cmd, timeout=timeout)

        if result.error and "timed out" in result.error:
            return self.error_response(f"nuclei scan timed out after {timeout}s", target=target)

        raw_findings = parse_json_lines(result.stdout)
        findings = parse_nuclei_findings(raw_findings)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 5))

        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        response: dict[str, Any] = {
            "status": "success" if result.success else "error",
            "target": target,
            "findings_count": len(findings),
            "severity_counts": severity_counts,
            "findings": findings,
        }

        if not result.success and result.stderr:
            response["warnings"] = [result.stderr]

        return response

    async def scan_severity(
        self, target: str, severity: str, rate_limit: int = 150, timeout: int = 0,
    ) -> dict[str, Any]:
        """Run nuclei scan filtered by severity."""
        return await self.scan(target=target, severity=severity, rate_limit=rate_limit, timeout=timeout)

    async def scan_template(
        self, target: str, template: str, rate_limit: int = 150, timeout: int = 0,
    ) -> dict[str, Any]:
        """Run nuclei scan with specific template."""
        return await self.scan(target=target, templates=template, rate_limit=rate_limit, timeout=timeout)

    async def execute(self, **kwargs: Any) -> ToolResult:
        action = kwargs.pop("action", "scan")
        method = getattr(self, action, None)
        if method is None:
            return ToolResult(success=False, stdout="", stderr=f"Unknown action: {action}", exit_code=-1)
        result = await method(**kwargs)
        return ToolResult(
            success=result.get("status") == "success",
            stdout=str(result), stderr=result.get("error", ""),
            exit_code=0 if result.get("status") == "success" else -1, parsed=result,
        )


nuclei_tool = NucleiTool()


async def nuclei_scan(target: str, templates: str = "", severity: str = "", rate_limit: int = 150, tags: str = "", timeout: int = 0) -> dict[str, Any]:
    """Nuclei vulnerability scan."""
    return await nuclei_tool.scan(target, templates, severity, rate_limit, tags, timeout)

async def nuclei_scan_severity(target: str, severity: str, rate_limit: int = 150, timeout: int = 0) -> dict[str, Any]:
    """Nuclei scan filtered by severity."""
    return await nuclei_tool.scan_severity(target, severity, rate_limit, timeout)

async def nuclei_scan_template(target: str, template: str, rate_limit: int = 150, timeout: int = 0) -> dict[str, Any]:
    """Nuclei scan with specific template."""
    return await nuclei_tool.scan_template(target, template, rate_limit, timeout)
