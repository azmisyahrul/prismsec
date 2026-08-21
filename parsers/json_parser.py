"""JSON parser for security tool outputs."""

import json
from typing import Any


def parse_json_lines(text: str) -> list[dict[str, Any]]:
    """Parse newline-delimited JSON (JSONL) output.

    Used by nuclei, subfinder, httpx -sje, etc.
    """
    results = []
    if not text or not text.strip():
        return results

    for line in text.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            results.append(data)
        except json.JSONDecodeError:
            continue

    return results


def parse_json_output(text: str) -> dict[str, Any] | list[Any] | None:
    """Parse a single JSON object or array from output.

    Used when tool outputs a complete JSON document.
    """
    if not text or not text.strip():
        return None

    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        # Try to find JSON within the output (tools sometimes mix text + JSON)
        for start_char, end_char in [('{', '}'), ('[', ']')]:
            start = text.find(start_char)
            end = text.rfind(end_char)
            if start != -1 and end > start:
                try:
                    return json.loads(text[start:end + 1])
                except json.JSONDecodeError:
                    continue
        return None


def parse_nuclei_findings(raw_lines: list[dict]) -> list[dict[str, Any]]:
    """Parse nuclei JSONL output into structured findings."""
    findings = []
    for item in raw_lines:
        info = item.get("info", {})
        finding: dict[str, Any] = {
            "template_id": item.get("template-id", "unknown"),
            "template_url": item.get("template-url", ""),
            "name": info.get("name", ""),
            "severity": info.get("severity", "unknown"),
            "type": info.get("type", ""),
            "matcher_name": item.get("matcher-name", ""),
            "matched_at": item.get("matched-at", ""),
            "extracted_results": item.get("extracted-results", []),
            "ip": item.get("ip", ""),
            "timestamp": item.get("timestamp", ""),
        }

        # Tags
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        finding["tags"] = tags

        # Classification
        classification = item.get("classification", {})
        if classification:
            finding["classification"] = {
                "cve_id": classification.get("cvss-metrics", ""),
                "cwe_id": classification.get("cwe-id", ""),
                "cvss_score": classification.get("cvss-score", ""),
            }

        # Description
        finding["description"] = info.get("description", "")
        finding["reference"] = info.get("reference", [])

        findings.append(finding)

    return findings
