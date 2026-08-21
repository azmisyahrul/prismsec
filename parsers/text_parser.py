"""Text output parsers for various security tools."""

import re
from typing import Any


def parse_gobuster_output(raw_output: str, mode: str = "dir") -> dict[str, Any]:
    """Parse gobuster text output.

    Args:
        raw_output: Raw stdout from gobuster.
        mode: 'dir' or 'dns'.

    Returns:
        Structured dict with findings.
    """
    results: dict[str, Any] = {
        "mode": mode,
        "findings": [],
        "warnings": [],
        "errors": [],
    }

    if not raw_output:
        return results

    lines = raw_output.split("\n")

    if mode == "dir":
        # Typical dir output lines:
        # /admin (Status: 301) [Size: 314]
        # /login (Status: 200) [Size: 4521]
        pattern = re.compile(
            r"^(\/\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]"
        )
        for line in lines:
            line = line.strip()
            m = pattern.match(line)
            if m:
                results["findings"].append({
                    "path": m.group(1),
                    "status_code": int(m.group(2)),
                    "size": int(m.group(3)),
                })
            elif line.startswith("Warning") or line.startswith("WARN"):
                results["warnings"].append(line)
            elif "Error" in line or "ERR" in line:
                results["errors"].append(line)

    elif mode == "dns":
        # DNS output lines:
        # Found: admin.example.com
        # or: admin.example.com [Status: Unknown] [Size: ...]
        for line in lines:
            line = line.strip()
            if not line:
                continue
            m = re.match(r"Found:\s+(\S+)", line)
            if m:
                results["findings"].append({
                    "subdomain": m.group(1),
                })
            elif line.startswith("[+]"):
                # Newer gobuster format
                m2 = re.match(r"\[\+\]\s+(\S+)", line)
                if m2:
                    results["findings"].append({
                        "subdomain": m2.group(1),
                    })

    results["total"] = len(results["findings"])
    return results


def parse_nikto_output(raw_output: str) -> dict[str, Any]:
    """Parse nikto text output.

    Returns structured findings from nikto scan.
    """
    results: dict[str, Any] = {
        "findings": [],
        "server_info": {},
        "target": "",
        "errors": [],
    }

    if not raw_output:
        return results

    lines = raw_output.split("\n")

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Server info lines
        if line.startswith("+ Server:"):
            results["server_info"]["server"] = line.split(":", 1)[1].strip()
        elif line.startswith("+ Target IP:"):
            results["server_info"]["ip"] = line.split(":", 1)[1].strip()
        elif line.startswith("+ Target Hostname:"):
            results["server_info"]["hostname"] = line.split(":", 1)[1].strip()
        elif line.startswith("+ Target Port:"):
            results["server_info"]["port"] = line.split(":", 1)[1].strip()
        elif line.startswith("+ Start Time:"):
            results["server_info"]["start_time"] = line.split(":", 1)[1].strip()

        # Finding lines (OSVDB entries)
        elif line.startswith("+ OSVDB-"):
            osvdb_match = re.match(r"\+ (OSVDB-\d+):\s*(.*)", line)
            if osvdb_match:
                results["findings"].append({
                    "id": osvdb_match.group(1),
                    "detail": osvdb_match.group(2).strip(),
                    "severity": "medium",
                })

        # Generic finding lines
        elif line.startswith("+ ") and "/" in line:
            detail = line[2:].strip()
            # Skip informational headers
            if any(skip in detail.lower() for skip in [
                "retrieved x-powered-by",
                "headers",
                "target ip",
                "start time",
                "end time",
            ]):
                continue
            if detail and not detail.startswith("+"):
                results["findings"].append({
                    "id": "",
                    "detail": detail,
                    "severity": "info",
                })

        # Error lines
        elif "error" in line.lower() or "failed" in line.lower():
            results["errors"].append(line)

    results["total"] = len(results["findings"])
    return results


def parse_subfinder_output(raw_output: str) -> list[str]:
    """Parse subfinder output (one subdomain per line)."""
    if not raw_output:
        return []

    subdomains = []
    for line in raw_output.strip().split("\n"):
        line = line.strip().lower()
        if not line:
            continue
        # Skip lines that look like status messages
        if line.startswith("[") or line.startswith(")") or line.startswith("="):
            continue
        # Validate it looks like a hostname
        if re.match(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$", line):
            subdomains.append(line)

    return sorted(set(subdomains))


def parse_httpx_output(raw_output: str) -> list[dict[str, Any]]:
    """Parse httpx JSONL output (expects -json flag).

    Each line is a JSON object with url, status_code, title, etc.
    """
    import json

    results = []
    if not raw_output:
        return results

    for line in raw_output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            entry: dict[str, Any] = {
                "url": data.get("url", ""),
                "status_code": data.get("status_code", 0),
                "title": data.get("title", ""),
                "content_length": data.get("content_length", 0),
                "content_type": data.get("content_type", ""),
                "webserver": data.get("webserver", ""),
                "technologies": data.get("tech", []),
                "response_time": data.get("response_time", ""),
                "method": data.get("method", "GET"),
                "host": data.get("host", ""),
                "port": data.get("port", ""),
                "scheme": data.get("scheme", ""),
                "tls": data.get("tls", {}),
            }
            # Extract JARM hash if present
            if "jarm" in data:
                entry["jarm"] = data["jarm"]
            # CDN detection
            if "cdn_name" in data:
                entry["cdn"] = data["cdn_name"]
            results.append(entry)
        except json.JSONDecodeError:
            continue

    return results


def parse_sqlmap_output(raw_output: str) -> dict[str, Any]:
    """Parse sqlmap text output for injection results."""
    results: dict[str, Any] = {
        "injectable": False,
        "injection_points": [],
        "databases": [],
        "parameters": [],
        "techniques": [],
        "summary": "",
    }

    if not raw_output:
        return results

    lines = raw_output.split("\n")

    for line in lines:
        line = line.strip()

        # Injectable detection
        if "is vulnerable" in line.lower() or "injectable" in line.lower():
            results["injectable"] = True
            # Extract parameter info
            param_match = re.search(
                r"Parameter:\s+'([^']+)'", line
            )
            if param_match:
                results["parameters"].append(param_match.group(1))

        # Injection type
        type_match = re.match(
            r"\s*Type:\s+(.+)", line
        )
        if type_match:
            results["injection_points"].append({
                "type": type_match.group(1).strip(),
            })

        # Title
        title_match = re.match(r"\s*Title:\s+(.+)", line)
        if title_match and results["injection_points"]:
            results["injection_points"][-1]["title"] = title_match.group(1).strip()

        # Payload
        payload_match = re.match(r"\s*Payload:\s+(.+)", line)
        if payload_match and results["injection_points"]:
            results["injection_points"][-1]["payload"] = payload_match.group(1).strip()

        # Database enumeration
        db_match = re.match(r"\[\*\]\s+(\S+)", line)
        if db_match and "available databases" in raw_output.lower():
            db_name = db_match.group(1)
            if db_name not in results["databases"] and not db_name.startswith("["):
                results["databases"].append(db_name)

        # Techniques
        if "sqlmap identified" in line.lower():
            results["techniques"].append(line)

        # Summary / back-end DBMS
        if "back-end dbms:" in line.lower():
            results["summary"] = line.strip()

    results["total_injection_points"] = len(results["injection_points"])
    return results
