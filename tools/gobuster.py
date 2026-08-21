"""
Gobuster tool wrapper for MCP server.

Wraps gobuster for directory and DNS brute-forcing with text output parsing.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from .base import (
    ToolWrapper,
    ToolResult,
    run_command,
    validate_target,
    validate_path,
)
from parsers.text_parser import parse_gobuster_output

logger = logging.getLogger(__name__)

_DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
_DEFAULT_TIMEOUT = 300


class GobusterTool(ToolWrapper):
    """Wrapper for gobuster directory/DNS brute-forcer."""

    @property
    def tool_name(self) -> str:
        return "gobuster"

    @property
    def tool_description(self) -> str:
        return "Directory and DNS brute-forcing with Gobuster"

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or domain"},
                "wordlist": {"type": "string", "description": "Wordlist path"},
                "extensions": {"type": "string", "description": "File extensions"},
                "threads": {"type": "integer", "description": "Thread count"},
                "status_codes": {"type": "string", "description": "Status code filter"},
                "timeout": {"type": "integer", "description": "Max seconds"},
            },
            "required": ["target"],
        }

    async def dir_mode(
        self, target: str, wordlist: str = "", extensions: str = "php,html,js,txt",
        threads: int = 50, status_codes: str = "", timeout: int = 0,
    ) -> dict[str, Any]:
        """Run gobuster in directory brute-force mode."""
        try:
            target = validate_target(target)
        except ValueError as e:
            return self.error_response(str(e), target=target)

        wordlist = wordlist.strip() if wordlist else ""
        if not wordlist:
            wordlist = _DEFAULT_WORDLIST
        else:
            try:
                wordlist = validate_path(wordlist)
            except (ValueError, FileNotFoundError) as e:
                return self.error_response(str(e), target=target)

        if not os.path.isfile(wordlist):
            return self.error_response(f"Wordlist not found: {wordlist}", target=target)

        timeout = timeout or _DEFAULT_TIMEOUT

        cmd = [
            "gobuster", "dir", "-u", target, "-w", wordlist,
            "-t", str(threads), "--no-color", "-q",
        ]
        if extensions:
            cmd.extend(["-x", extensions])
        if status_codes:
            cmd.extend(["-s", status_codes])

        result = await run_command(cmd, timeout=timeout)

        if result.error and "timed out" in result.error:
            return self.error_response(f"gobuster dir timed out after {timeout}s", target=target)

        parsed = parse_gobuster_output(result.stdout, mode="dir")
        return {
            "status": "success" if result.success else "error",
            "target": target, "mode": "dir", "wordlist": wordlist,
            "extensions": extensions,
            "findings_count": parsed["total"], "findings": parsed["findings"],
            "warnings": parsed["warnings"],
        }

    async def dns_mode(
        self, target: str, wordlist: str = "", threads: int = 50, timeout: int = 0,
    ) -> dict[str, Any]:
        """Run gobuster in DNS brute-force mode."""
        try:
            target = validate_target(target)
        except ValueError as e:
            return self.error_response(str(e), target=target)

        wordlist = wordlist.strip() if wordlist else ""
        if not wordlist:
            wordlist = "/usr/share/wordlists/dns/subdomains-top1mil-5000.txt"
        else:
            try:
                wordlist = validate_path(wordlist)
            except (ValueError, FileNotFoundError) as e:
                return self.error_response(str(e), target=target)

        if not os.path.isfile(wordlist):
            return self.error_response(f"Wordlist not found: {wordlist}", target=target)

        timeout = timeout or _DEFAULT_TIMEOUT

        cmd = [
            "gobuster", "dns", "-d", target, "-w", wordlist,
            "-t", str(threads), "--no-color", "-q",
        ]

        result = await run_command(cmd, timeout=timeout)

        if result.error and "timed out" in result.error:
            return self.error_response(f"gobuster dns timed out after {timeout}s", target=target)

        parsed = parse_gobuster_output(result.stdout, mode="dns")
        return {
            "status": "success" if result.success else "error",
            "target": target, "mode": "dns", "wordlist": wordlist,
            "findings_count": parsed["total"], "findings": parsed["findings"],
            "warnings": parsed["warnings"],
        }

    async def execute(self, **kwargs: Any) -> ToolResult:
        action = kwargs.pop("action", "dir_mode")
        method = getattr(self, action, None)
        if method is None:
            return ToolResult(success=False, stdout="", stderr=f"Unknown action: {action}", exit_code=-1)
        result = await method(**kwargs)
        return ToolResult(
            success=result.get("status") == "success",
            stdout=str(result), stderr=result.get("error", ""),
            exit_code=0 if result.get("status") == "success" else -1, parsed=result,
        )


gobuster_tool = GobusterTool()


async def gobuster_dir_mode(target: str, wordlist: str = "", extensions: str = "php,html,js,txt", threads: int = 50, status_codes: str = "", timeout: int = 0) -> dict[str, Any]:
    """Gobuster directory brute-force."""
    return await gobuster_tool.dir_mode(target, wordlist, extensions, threads, status_codes, timeout)

async def gobuster_dns_mode(target: str, wordlist: str = "", threads: int = 50, timeout: int = 0) -> dict[str, Any]:
    """Gobuster DNS brute-force."""
    return await gobuster_tool.dns_mode(target, wordlist, threads, timeout)
