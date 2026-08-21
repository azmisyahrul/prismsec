#!/usr/bin/env python3
"""
MCP Security Tools Server

A modular MCP server wrapping offensive security tools (nmap, nuclei, gobuster,
subfinder, httpx, nikto, sqlmap). Uses MCP SDK with FastMCP for tool registration.

Usage:
    python server.py                    # stdio transport (default)
    python server.py --transport sse    # SSE transport
    python server.py --transport http   # Streamable HTTP transport
    python server.py --port 9000        # Custom port (for SSE/HTTP)
"""

import argparse
import asyncio
import json
import logging
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.fastmcp import FastMCP

# Import all tool functions
from tools import (
    nmap_scan,
    nmap_service_detection,
    nmap_full_port_scan,
    nuclei_scan,
    nuclei_scan_severity,
    nuclei_scan_template,
    gobuster_dir_mode,
    gobuster_dns_mode,
    subfinder_scan,
    httpx_scan,
    nikto_scan,
    sqlmap_scan,
    get_tool_status,
)
from tools.base import check_tool
from utils.logging import setup_logging

# ──────────────────────────────────────────────────────────────
#  Initialize MCP server
# ──────────────────────────────────────────────────────────────

logger = setup_logging(level=os.environ.get("LOG_LEVEL", "INFO"))
mcp = FastMCP(
    "MCP Recon Security Tools",
    instructions="Modular security tools server for reconnaissance, vulnerability "
                "scanning, and penetration testing.",
)


# ──────────────────────────────────────────────────────────────
#  NMAP Tools
# ──────────────────────────────────────────────────────────────

@mcp.tool()
async def nmap_port_scan(
    target: str,
    ports: str = "",
    scan_type: str = "quick",
    timeout: int = 0,
) -> dict:
    """Run an nmap port scan on a target.

    Performs port scanning with various scan types. Results are parsed from
    nmap XML output into structured JSON.

    Args:
        target: IP address, hostname, or CIDR range (e.g., 192.168.1.1, scanme.nmap.org)
        ports: Port specification (e.g., "80,443", "1-1000"). Empty = default ports.
        scan_type: Type of scan - "quick" (common ports), "full" (all 65535),
                   "service" (version detection), "stealth" (SYN scan), "aggressive" (-A)
        timeout: Max seconds before scan is killed (0 = auto)

    Returns:
        Structured scan results with hosts, ports, services, and OS detection.
    """
    return await nmap_scan(target, ports, scan_type, timeout)


@mcp.tool()
async def nmap_service_detect(
    target: str,
    ports: str = "",
    timeout: int = 0,
) -> dict:
    """Run nmap service/version detection scan.

    Identifies services running on open ports and their versions.
    Useful for identifying vulnerable service versions.

    Args:
        target: IP address, hostname, or CIDR range
        ports: Port specification. Empty = default.
        timeout: Max seconds (0 = auto)

    Returns:
        Structured results with service names, versions, and products.
    """
    return await nmap_service_detection(target, ports, timeout)


@mcp.tool()
async def nmap_full_scan(
    target: str,
    timeout: int = 0,
) -> dict:
    """Scan all 65535 TCP ports on a target.

    Comprehensive port scan that checks every possible TCP port.
    Warning: This is slow, use nmap_port_scan with scan_type="quick" for faster results.

    Args:
        target: IP address, hostname, or CIDR range
        timeout: Max seconds (0 = auto, default 600s)

    Returns:
        All open ports with service information.
    """
    return await nmap_full_port_scan(target, timeout)


# ──────────────────────────────────────────────────────────────
#  Nuclei Tools
# ──────────────────────────────────────────────────────────────

@mcp.tool()
async def nuclei_vuln_scan(
    target: str,
    templates: str = "",
    severity: str = "",
    rate_limit: int = 150,
    tags: str = "",
    timeout: int = 0,
) -> dict:
    """Run a Nuclei vulnerability scan against a target URL.

    Scans for known vulnerabilities using Nuclei templates. Results include
    CVE IDs, severity ratings, and matched URLs.

    Args:
        target: Target URL (e.g., https://example.com)
        templates: Template filter (e.g., "cves", "misconfiguration"). Empty = all.
        severity: Severity filter (e.g., "high,critical"). Empty = all.
        rate_limit: Requests per second limit
        tags: Comma-separated tag filter (e.g., "sqli,xss")
        timeout: Max seconds (0 = default 600s)

    Returns:
        Structured findings with severity, template IDs, and match details.
    """
    return await nuclei_scan(target, templates, severity, rate_limit, tags, timeout)


@mcp.tool()
async def nuclei_severity_scan(
    target: str,
    severity: str,
    rate_limit: int = 150,
    timeout: int = 0,
) -> dict:
    """Run Nuclei scan filtered by severity level.

    Focused scan that only reports findings at specified severity levels.

    Args:
        target: Target URL (e.g., https://example.com)
        severity: Severity levels (e.g., "high,critical")
        rate_limit: Requests per second
        timeout: Max seconds

    Returns:
        Findings at specified severity levels.
    """
    return await nuclei_scan_severity(target, severity, rate_limit, timeout)


@mcp.tool()
async def nuclei_template_scan(
    target: str,
    template: str,
    rate_limit: int = 150,
    timeout: int = 0,
) -> dict:
    """Run Nuclei scan with a specific template.

    Targeted scan using a single template or template path.

    Args:
        target: Target URL (e.g., https://example.com)
        template: Template name or path (e.g., "cves/CVE-2021-44228")
        rate_limit: Requests per second
        timeout: Max seconds

    Returns:
        Findings from the specified template.
    """
    return await nuclei_scan_template(target, template, rate_limit, timeout)


# ──────────────────────────────────────────────────────────────
#  Gobuster Tools
# ──────────────────────────────────────────────────────────────

@mcp.tool()
async def gobuster_directory(
    target: str,
    wordlist: str = "",
    extensions: str = "php,html,js,txt",
    threads: int = 50,
    status_codes: str = "",
    timeout: int = 0,
) -> dict:
    """Run directory brute-force scan with Gobuster.

    Discovers hidden directories and files on web servers.

    Args:
        target: Target URL (e.g., http://example.com)
        wordlist: Path to wordlist file. Empty = default common wordlist.
        extensions: File extensions to search (comma-separated)
        threads: Number of concurrent threads (default 50)
        status_codes: Filter results by status codes (e.g., "200,301")
        timeout: Max seconds (0 = default 300s)

    Returns:
        Discovered paths with status codes and sizes.
    """
    return await gobuster_dir_mode(target, wordlist, extensions, threads, status_codes, timeout)


@mcp.tool()
async def gobuster_dns(
    target: str,
    wordlist: str = "",
    threads: int = 50,
    timeout: int = 0,
) -> dict:
    """Run DNS brute-force scan with Gobuster.

    Discovers subdomains by brute-forcing DNS entries.

    Args:
        target: Base domain (e.g., example.com)
        wordlist: Path to wordlist. Empty = default DNS wordlist.
        threads: Number of concurrent threads
        timeout: Max seconds

    Returns:
        Discovered subdomains.
    """
    return await gobuster_dns_mode(target, wordlist, threads, timeout)


# ──────────────────────────────────────────────────────────────
#  Subfinder Tool
# ──────────────────────────────────────────────────────────────

@mcp.tool()
async def subfinder_enumerate(
    target: str,
    sources: str = "",
    timeout: int = 0,
) -> dict:
    """Enumerate subdomains using Subfinder.

    Passive subdomain enumeration using multiple online sources
    (crt.sh, SecurityTrails, VirusTotal, etc.).

    Args:
        target: Target domain (e.g., example.com)
        sources: Comma-separated sources to use. Empty = all sources.
        timeout: Max seconds (0 = default 120s)

    Returns:
        List of discovered subdomains with deduplication.
    """
    return await subfinder_scan(target, sources, timeout=timeout)


# ──────────────────────────────────────────────────────────────
#  httpx Tool
# ──────────────────────────────────────────────────────────────

@mcp.tool()
async def httpx_probe(
    targets: str,
    ports: str = "",
    tech_detect: bool = True,
    follow_redirects: bool = True,
    status_codes: str = "",
    timeout: int = 0,
) -> dict:
    """Probe web targets for alive services and fingerprinting.

    Checks which targets are alive, extracts titles, status codes,
    technologies, and other metadata.

    Args:
        targets: Comma-separated URLs or hostnames (e.g., "example.com,192.168.1.1")
        ports: Comma-separated ports (e.g., "80,443,8080"). Empty = default.
        tech_detect: Enable technology detection
        follow_redirects: Follow HTTP redirects
        status_codes: Filter by status codes (e.g., "200,301")
        timeout: Max seconds

    Returns:
        Alive targets with status codes, titles, technologies, and metadata.
    """
    return await httpx_scan(targets, ports, tech_detect, follow_redirects, status_codes, timeout)


# ──────────────────────────────────────────────────────────────
#  Nikto Tool
# ──────────────────────────────────────────────────────────────

@mcp.tool()
async def nikto_web_scan(
    target: str,
    port: int = 80,
    ssl: bool = False,
    timeout: int = 0,
) -> dict:
    """Run Nikto web server vulnerability scan.

    Scans web servers for known vulnerabilities, misconfigurations,
    and dangerous files/CGIs.

    Args:
        target: Target hostname or IP
        port: Target port (default: 80)
        ssl: Enable SSL mode
        timeout: Max seconds (0 = default 600s)

    Returns:
        Vulnerability findings with OSVDB IDs and descriptions.
    """
    return await nikto_scan(target, port, ssl, timeout)


# ──────────────────────────────────────────────────────────────
#  SQLMap Tool
# ──────────────────────────────────────────────────────────────

@mcp.tool()
async def sqlmap_injection_test(
    target_url: str,
    data: str = "",
    level: int = 1,
    risk: int = 1,
    tamper: str = "",
    timeout: int = 0,
) -> dict:
    """Test a URL for SQL injection vulnerabilities with SQLMap.

    Automates SQL injection detection and exploitation testing.

    Args:
        target_url: Target URL with parameter (e.g., http://site.com/page?id=1)
        data: POST data string (e.g., "username=admin&password=test")
        level: Test level 1-5 (higher = more comprehensive, slower)
        risk: Risk level 1-3 (higher = more intrusive)
        tamper: Tamper script name (e.g., "between,randomcase")
        timeout: Max seconds (0 = default 600s)

    Returns:
        Injection status, injection points, vulnerable parameters, and databases.
    """
    return await sqlmap_scan(target_url, data, level, risk, tamper, timeout)


# ──────────────────────────────────────────────────────────────
#  Meta tool: Check all tool installations
# ──────────────────────────────────────────────────────────────

@mcp.tool()
async def check_tools() -> dict:
    """Check installation status of all security tools.

    Returns which tools are installed and their binary paths.
    Useful for diagnosing missing tool dependencies.

    Returns:
        Status of each tool (nmap, nuclei, gobuster, etc.).
    """
    return get_tool_status()


# ──────────────────────────────────────────────────────────────
#  Main entry point
# ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="MCP Security Tools Server"
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "http"],
        default="stdio",
        help="Transport type (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for SSE/HTTP transport (default: 8000)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host for SSE/HTTP transport (default: 127.0.0.1)",
    )
    args = parser.parse_args()

    logger.info(
        "Starting MCP Security Tools Server (transport=%s)", args.transport
    )

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    elif args.transport == "sse":
        mcp.run(transport="sse", port=args.port, host=args.host)
    elif args.transport == "http":
        mcp.run(transport="streamable-http", port=args.port, host=args.host)


if __name__ == "__main__":
    main()
