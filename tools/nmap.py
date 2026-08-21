"""
Nmap tool wrapper for MCP server.

Wraps nmap with XML output parsing, supporting scan, service_detection,
and full_port_scan operations.
"""

from __future__ import annotations

import logging
from typing import Any

from .base import (
    ToolWrapper,
    ToolResult,
    run_command,
    require_tool,
    validate_target,
    validate_port,
)
from parsers.xml_parser import parse_nmap_xml

logger = logging.getLogger(__name__)

_TIMEOUTS = {
    "scan": 120,
    "service_detection": 180,
    "full_port_scan": 600,
    "stealth": 120,
    "aggressive": 300,
}


class NmapTool(ToolWrapper):
    """Wrapper for nmap port scanner."""

    @property
    def tool_name(self) -> str:
        return "nmap"

    @property
    def tool_description(self) -> str:
        return "Port scanning and service detection with nmap"

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP, hostname, or CIDR"},
                "ports": {"type": "string", "description": "Port spec (e.g. 80,443)"},
                "scan_type": {"type": "string", "description": "quick|full|service|stealth|aggressive"},
                "timeout": {"type": "integer", "description": "Max seconds"},
            },
            "required": ["target"],
        }

    async def scan(
        self,
        target: str,
        ports: str = "",
        scan_type: str = "quick",
        timeout: int = 0,
    ) -> dict[str, Any]:
        """Run an nmap port scan."""
        try:
            target = validate_target(target)
        except ValueError as e:
            return self.error_response(str(e), target=target)

        timeout = timeout or _TIMEOUTS.get(scan_type, 120)

        cmd = ["nmap", "-oX", "-", "--open"]

        type_args = {
            "quick": ["-F", "-T4"],
            "full": ["-p-", "-T4"],
            "service": ["-sV", "-T3"],
            "stealth": ["-sS", "-T2"],
            "aggressive": ["-A", "-T4"],
        }
        cmd.extend(type_args.get(scan_type, type_args["quick"]))

        if ports:
            cmd.extend(["-p", ports])

        cmd.append(target)

        result = await run_command(cmd, timeout=timeout)

        if result.error and "timed out" in result.error:
            return self.error_response(
                f"nmap scan timed out after {timeout}s",
                target=target, scan_type=scan_type,
            )

        parsed = parse_nmap_xml(result.stdout)
        parsed["target"] = target
        parsed["scan_type"] = scan_type
        parsed["command"] = result.command

        if result.success:
            parsed["status"] = "success"
        else:
            parsed["status"] = "error"
            parsed["error"] = result.error or result.stderr or "Scan failed"

        return parsed

    async def service_detection(
        self,
        target: str,
        ports: str = "",
        timeout: int = 0,
    ) -> dict[str, Any]:
        """Run service/version detection scan."""
        return await self.scan(
            target=target,
            ports=ports,
            scan_type="service",
            timeout=timeout or _TIMEOUTS["service_detection"],
        )

    async def full_port_scan(
        self,
        target: str,
        timeout: int = 0,
    ) -> dict[str, Any]:
        """Scan all 65535 ports."""
        return await self.scan(
            target=target,
            scan_type="full",
            timeout=timeout or _TIMEOUTS["full_port_scan"],
        )

    async def execute(self, **kwargs: Any) -> ToolResult:
        action = kwargs.pop("action", "scan")
        method = getattr(self, action, None)
        if method is None:
            return ToolResult(
                success=False, stdout="", stderr=f"Unknown action: {action}",
                exit_code=-1, error=f"Unknown nmap action: {action}",
            )
        result = await method(**kwargs)
        return ToolResult(
            success=result.get("status") == "success",
            stdout=str(result),
            stderr=result.get("error", ""),
            exit_code=0 if result.get("status") == "success" else -1,
            parsed=result,
        )


nmap_tool = NmapTool()


async def nmap_scan(target: str, ports: str = "", scan_type: str = "quick", timeout: int = 0) -> dict[str, Any]:
    """Nmap port scan - wrapper function for MCP tool registration."""
    return await nmap_tool.scan(target, ports, scan_type, timeout)


async def nmap_service_detection(target: str, ports: str = "", timeout: int = 0) -> dict[str, Any]:
    """Nmap service/version detection scan."""
    return await nmap_tool.service_detection(target, ports, timeout)


async def nmap_full_port_scan(target: str, timeout: int = 0) -> dict[str, Any]:
    """Nmap full port scan (all 65535 ports)."""
    return await nmap_tool.full_port_scan(target, timeout)
