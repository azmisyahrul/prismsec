"""
Security tools package for MCP server.

Exports all tool wrapper instances and their async functions.
"""

from .nmap import NmapTool, nmap_tool, nmap_scan, nmap_service_detection, nmap_full_port_scan
from .nuclei import NucleiTool, nuclei_tool, nuclei_scan, nuclei_scan_severity, nuclei_scan_template
from .gobuster import GobusterTool, gobuster_tool, gobuster_dir_mode, gobuster_dns_mode
from .subfinder import SubfinderTool, subfinder_tool, subfinder_scan
from .httpx import HttpxTool, httpx_tool, httpx_scan
from .nikto import NiktoTool, nikto_tool, nikto_scan
from .sqlmap import SqlmapTool, sqlmap_tool, sqlmap_scan

__all__ = [
    # Tool classes
    "NmapTool",
    "NucleiTool",
    "GobusterTool",
    "SubfinderTool",
    "HttpxTool",
    "NiktoTool",
    "SqlmapTool",
    # Tool instances
    "nmap_tool",
    "nuclei_tool",
    "gobuster_tool",
    "subfinder_tool",
    "httpx_tool",
    "nikto_tool",
    "sqlmap_tool",
    # Async functions (for MCP registration)
    "nmap_scan",
    "nmap_service_detection",
    "nmap_full_port_scan",
    "nuclei_scan",
    "nuclei_scan_severity",
    "nuclei_scan_template",
    "gobuster_dir_mode",
    "gobuster_dns_mode",
    "subfinder_scan",
    "httpx_scan",
    "nikto_scan",
    "sqlmap_scan",
]

# Tool registry: maps tool name to list of (function, description)
TOOL_REGISTRY: dict[str, list[tuple]] = {
    "nmap": [
        (nmap_scan, "Run an nmap port scan"),
        (nmap_service_detection, "Run nmap service/version detection"),
        (nmap_full_port_scan, "Run nmap full port scan (all 65535 ports)"),
    ],
    "nuclei": [
        (nuclei_scan, "Run nuclei vulnerability scan"),
        (nuclei_scan_severity, "Run nuclei scan filtered by severity"),
        (nuclei_scan_template, "Run nuclei scan with specific template"),
    ],
    "gobuster": [
        (gobuster_dir_mode, "Directory brute-force with gobuster"),
        (gobuster_dns_mode, "DNS brute-force with gobuster"),
    ],
    "subfinder": [
        (subfinder_scan, "Enumerate subdomains with subfinder"),
    ],
    "httpx": [
        (httpx_scan, "Probe and fingerprint web targets with httpx"),
    ],
    "nikto": [
        (nikto_scan, "Web server vulnerability scan with nikto"),
    ],
    "sqlmap": [
        (sqlmap_scan, "SQL injection testing with sqlmap"),
    ],
}


def get_all_functions() -> list[tuple]:
    """Get all tool functions as (func, description) tuples."""
    funcs = []
    for tool_funcs in TOOL_REGISTRY.values():
        funcs.extend(tool_funcs)
    return funcs


def get_tool_status() -> dict[str, dict]:
    """Check installation status of all tools."""
    from .base import check_tool
    return {name: check_tool(name) for name in TOOL_REGISTRY}
