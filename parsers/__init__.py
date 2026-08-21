"""Output parsers for security tool results.

Each parser converts raw tool output (XML, JSON, JSONL, or plain text)
into structured Python dicts suitable for MCP JSON responses.
"""
from .xml_parser import parse_nmap_xml
from .json_parser import parse_json_output, parse_json_lines, parse_nuclei_findings
from .text_parser import parse_gobuster_output, parse_subfinder_output, parse_httpx_output, parse_sqlmap_output

__all__ = [
    "parse_nmap_xml",
    "parse_json_output",
    "parse_json_lines",
    "parse_nuclei_findings",
    "parse_gobuster_output",
    "parse_subfinder_output",
    "parse_httpx_output",
    "parse_sqlmap_output",
]
