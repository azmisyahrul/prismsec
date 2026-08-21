# MCP Recon

**Secure, modular MCP server wrapping 7 pentesting tools with 13 registered tools.**

A hardened alternative to [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) (11k⭐) — built with security-first principles, zero `shell=True`, input validation, and modular architecture.

---

## Why MCP Recon?

HexStrike AI has **5+ unauthenticated RCE vulnerabilities** and 90+ command injection points. Its entire codebase is 22K lines in 2 files. The "AI" is just hardcoded lookup tables.

MCP Recon fixes every one of these:

| Problem | HexStrike AI | MCP Recon |
|---------|-------------|-----------|
| Code structure | 2 monolithic files (22K LOC) | 19 modular files (~3.5K LOC) |
| Shell injection | `shell=True` everywhere | `asyncio.create_subprocess_exec` (never shell) |
| Input validation | None | Injection detection + whitelisting |
| RCE vulnerabilities | **5+ critical** | **0** |
| MCP SDK | v1 (deprecated) | **v2** |
| "AI" claims | Fake (hardcoded IF/ELSE) | Honest (no fake AI) |

---

## Security Features

| Feature | Description |
|---------|-------------|
| **Zero shell=True** | All subprocess calls use `create_subprocess_exec` with argument lists |
| **Input validation** | Target, URL, port, severity — all validated before execution |
| **Injection detection** | Blocks shell metacharacters (`;`, `$()`, backticks, `\|`) |
| **Timeout enforcement** | Every tool has configurable timeout (auto-kills hung processes) |
| **Tool existence check** | Verifies binary exists before spawning subprocess |
| **Structured output** | Parsed XML/JSON/text → clean JSON for AI agents |
| **Rate limiting** | Token bucket rate limiter included |
| **Audit logging** | Every command logged with timestamps |

---

## Installation

### From source (recommended)

```bash
git clone https://github.com/azmisyahrul/mcp-recon.git
cd mcp-recon
pip install -e .
```

### With uv

```bash
uv pip install mcp-recon
```

### Prerequisites

Install the security tools you need:

```bash
# Ubuntu/Debian
apt install nmap nikto sqlmap

# Go-based tools (nuclei, subfinder, httpx)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Gobuster
go install github.com/OJ/gobuster/v3@latest
```

---

## Tools (13 registered)

### Nmap (Port Scanning)
| MCP Tool | Description |
|----------|-------------|
| `nmap_port_scan` | Port scan with quick/full/service/stealth/aggressive modes |
| `nmap_service_detect` | Service/version detection on open ports |
| `nmap_full_scan` | Scan all 65535 TCP ports |

### Nuclei (Vulnerability Scanning)
| MCP Tool | Description |
|----------|-------------|
| `nuclei_vuln_scan` | Full vulnerability scan with all templates |
| `nuclei_severity_scan` | Scan filtered by severity (critical, high, etc.) |
| `nuclei_template_scan` | Targeted scan with specific template |

### Gobuster (Directory/DNS Brute)
| MCP Tool | Description |
|----------|-------------|
| `gobuster_directory` | Directory brute-force with configurable extensions |
| `gobuster_dns` | DNS subdomain brute-force |

### Other Tools
| MCP Tool | Description |
|----------|-------------|
| `subfinder_enumerate` | Passive subdomain enumeration (crt.sh, VirusTotal, etc.) |
| `httpx_probe` | Web probing — alive detection, titles, tech fingerprinting |
| `nikto_web_scan` | Web server vulnerability scanning |
| `sqlmap_injection_test` | SQL injection detection and testing |

### Meta
| MCP Tool | Description |
|----------|-------------|
| `check_tools` | Check which security tools are installed |

---

## Usage

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mcp-recon": {
      "command": "python3",
      "args": ["/path/to/mcp-recon/server.py"],
      "env": {}
    }
  }
}
```

### Claude Code

```bash
claude mcp add mcp-recon python3 /path/to/mcp-recon/server.py
```

### Cursor / Windsurf / Cline

Add to `.cursor/mcp.json` or equivalent:

```json
{
  "mcpServers": {
    "mcp-recon": {
      "command": "python3",
      "args": ["/path/to/mcp-recon/server.py"]
    }
  }
}
```

### SSE Transport (Remote)

```bash
# Server side
python3 server.py --transport sse --host 0.0.0.0 --port 8000

# Client config
{
  "mcpServers": {
    "mcp-recon": {
      "url": "http://localhost:8000/sse"
    }
  }
}
```

---

## Project Structure

```
mcp-recon/
├── server.py              # MCP server entry point (13 tools registered)
├── pyproject.toml         # Project config + dependencies
├── tools/                 # Tool wrappers (one file per tool)
│   ├── base.py           # ToolWrapper ABC + run_command (no shell=True!)
│   ├── nmap.py           # Nmap XML parsing + scan modes
│   ├── nuclei.py         # Nuclei JSON output parsing
│   ├── gobuster.py       # Gobuster text output parsing
│   ├── subfinder.py      # Subfinder subdomain enum
│   ├── httpx.py          # Httpx web probing
│   ├── nikto.py          # Nikto web vuln scan
│   └── sqlmap.py         # Sqlmap SQL injection testing
├── parsers/               # Output parsers (XML, JSON, text)
│   ├── xml_parser.py     # nmap XML → structured JSON
│   ├── json_parser.py    # JSON/JSONL parsing (nuclei, httpx)
│   └── text_parser.py    # Gobuster, nikto, sqlmap text parsing
└── utils/                 # Shared utilities
    ├── runner.py          # AsyncRunner with timeout + output capping
    ├── validator.py       # Input validation + injection detection
    ├── rate_limiter.py    # Token bucket rate limiter
    └── logging.py         # Structured logging setup
```

---

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |

---

## Development

```bash
# Clone
git clone https://github.com/azmisyahrul/mcp-recon.git
cd mcp-recon

# Syntax check
python3 -c "import ast; [ast.parse(open(f).read()) for f in __import__('glob').glob('**/*.py', recursive=True)]"

# Test imports
python3 -c "import sys; sys.path.insert(0,'.'); from server import mcp; print(f'{len(mcp._tool_manager.list_tools())} tools registered')"
```

---

## Security Considerations

⚠️ **Authorized testing only.** Use against systems you own or have written permission to test.

- Tool outputs may contain sensitive information (IPs, open ports, vulnerabilities)
- The server binds to `127.0.0.1` by default — never expose to untrusted networks
- Each tool has configurable timeouts to prevent resource exhaustion

---

## License

MIT

---

## Acknowledgments

Built as a secure alternative to HexStrike AI MCP. Uses the [Model Context Protocol](https://modelcontextprotocol.io/) standard for broad client compatibility.
