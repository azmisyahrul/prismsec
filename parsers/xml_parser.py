"""XML parser for nmap output."""

import xml.etree.ElementTree as ET
from typing import Any


def parse_nmap_xml(xml_output: str) -> dict[str, Any]:
    """Parse nmap XML output into structured data.

    Args:
        xml_output: Raw XML string from nmap -oX - output.

    Returns:
        Structured dict with hosts, ports, services, and OS info.
    """
    if not xml_output or not xml_output.strip():
        return {"hosts": [], "error": "Empty XML output"}

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        return {"hosts": [], "error": f"XML parse error: {e}"}

    result: dict[str, Any] = {
        "scan_info": _parse_scan_info(root),
        "hosts": [],
    }

    for host_el in root.findall(".//host"):
        host = _parse_host(host_el)
        result["hosts"].append(host)

    # Summary stats from runstats
    runstats = root.find(".//finished")
    if runstats is not None:
        result["elapsed"] = runstats.get("elapsed", "")
        result["summary"] = runstats.get("summary", "")

    hosts_up = sum(1 for h in result["hosts"] if h.get("state") == "up")
    total_ports = sum(len(h.get("ports", [])) for h in result["hosts"])
    result["summary_stats"] = {
        "hosts_scanned": len(result["hosts"]),
        "hosts_up": hosts_up,
        "total_open_ports": total_ports,
    }

    return result


def _parse_scan_info(root: ET.Element) -> dict[str, str]:
    """Parse scan metadata."""
    scanner_el = root.find(".//scanner")
    info: dict[str, str] = {}
    if root is not None:
        info["scanner"] = root.get("scanner", "nmap")
        info["args"] = root.get("args", "")
        info["start"] = root.get("start", "")
        info["startstr"] = root.get("startstr", "")
        info["version"] = root.get("version", "")
    return info


def _parse_host(host_el: ET.Element) -> dict[str, Any]:
    """Parse a single host element."""
    host: dict[str, Any] = {
        "state": "",
        "addresses": [],
        "hostnames": [],
        "ports": [],
        "os_matches": [],
    }

    # State
    state_el = host_el.find("status")
    if state_el is not None:
        host["state"] = state_el.get("state", "unknown")

    # Addresses
    for addr_el in host_el.findall("address"):
        host["addresses"].append({
            "type": addr_el.get("addrtype", ""),
            "address": addr_el.get("addr", ""),
        })

    # Hostnames
    for hn_el in host_el.findall(".//hostname"):
        host["hostnames"].append({
            "name": hn_el.get("name", ""),
            "type": hn_el.get("type", ""),
        })

    # Ports
    for port_el in host_el.findall(".//port"):
        port = _parse_port(port_el)
        host["ports"].append(port)

    # OS detection
    for osmatch_el in host_el.findall(".//osmatch"):
        host["os_matches"].append({
            "name": osmatch_el.get("name", ""),
            "accuracy": osmatch_el.get("accuracy", ""),
            "type": osmatch_el.get("type", ""),
        })

    # Extract primary hostname
    if host["hostnames"]:
        host["hostname"] = host["hostnames"][0]["name"]

    # Extract primary IP
    for addr in host["addresses"]:
        if addr["type"] == "ipv4":
            host["ip"] = addr["address"]
            break
    else:
        for addr in host["addresses"]:
            if addr["type"] == "ipv6":
                host["ip"] = addr["address"]
                break

    return host


def _parse_port(port_el: ET.Element) -> dict[str, Any]:
    """Parse a single port element."""
    port: dict[str, Any] = {
        "port": int(port_el.get("portid", 0)),
        "protocol": port_el.get("protocol", "tcp"),
        "state": "",
        "service": {},
    }

    state_el = port_el.find("state")
    if state_el is not None:
        port["state"] = state_el.get("state", "")
        port["reason"] = state_el.get("reason", "")

    svc_el = port_el.find("service")
    if svc_el is not None:
        port["service"] = {
            "name": svc_el.get("name", ""),
            "product": svc_el.get("product", ""),
            "version": svc_el.get("version", ""),
            "extra": svc_el.get("extrainfo", ""),
            "method": svc_el.get("method", ""),
            "conf": svc_el.get("conf", ""),
        }
        # Build version string
        parts = [
            svc_el.get("product", ""),
            svc_el.get("version", ""),
        ]
        port["service"]["version_string"] = " ".join(p for p in parts if p).strip()

    # Script output
    scripts = []
    for script_el in port_el.findall("script"):
        scripts.append({
            "id": script_el.get("id", ""),
            "output": script_el.get("output", ""),
        })
    if scripts:
        port["scripts"] = scripts

    return port
