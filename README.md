# PrismSec 🔷

**Secure, modular MCP server for pentesting tools.**

Wraps 7 industry-standard security tools (nmap, nuclei, gobuster, subfinder, httpx, nikto, sqlmap) into 13 registered MCP tools — ready to use with Claude, Cursor, Copilot, and any MCP-compatible AI agent.

---

## Features

| Feature | Description |
|---------|-------------|
| **Zero shell=True** | All subprocess calls use `asyncio.create_subprocess_exec` — no shell injection |
| **Input validation** | Target, URL, port, severity — all validated before execution |
| **Injection detection** | Blocks shell metacharacters (`;`, `$()`, backticks, `\|`) |
| **Timeout enforcement** | Every tool has configurable timeout — auto-kills hung processes |
| **Structured output** | Parsed XML/JSON/text → clean JSON for AI agents |
| **Modular architecture** | One file per tool — easy to add, maintain, and test |
| **MCP SDK v2** | Built on the latest Model Context Protocol SDK |

---

## Installation

### From source

```bash
git clone https://github.com/azmisyahrul/prismsec.git
cd prismsec
pip install -e .
```

### Prerequisites

Install the security tools you need:

```bash
# Ubuntu/Debian
apt install nmap nikto sqlmap

# Go-based tools
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/OJ/gobuster/v3@latest
```

---

## Tools (13 registered)

### Nmap — Port Scanning
| MCP Tool | Description |
|----------|-------------|
| `nmap_port_scan` | Port scan with quick/full/service/stealth/aggressive modes |
| `nmap_service_detect` | Service/version detection on open ports |
| `nmap_full_scan` | Scan all 65535 TCP ports |

### Nuclei — Vulnerability Scanning
| MCP Tool | Description |
|----------|-------------|
| `nuclei_vuln_scan` | Full vulnerability scan with all templates |
| `nuclei_severity_scan` | Scan filtered by severity (critical, high, etc.) |
| `nuclei_template_scan` | Targeted scan with specific template |

### Gobuster — Directory/DNS Brute
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
    "prismsec": {
      "command": "python3",
      "args": ["/path/to/prismsec/server.py"],
      "env": {}
    }
  }
}
```

### Claude Code

```bash
claude mcp add prismsec python3 /path/to/prismsec/server.py
```

### Cursor / Windsurf / Cline

Add to `.cursor/mcp.json` or equivalent:

```json
{
  "mcpServers": {
    "prismsec": {
      "command": "python3",
      "args": ["/path/to/prismsec/server.py"]
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
    "prismsec": {
      "url": "http://localhost:8000/sse"
    }
  }
}
```

---

## Project Structure

```
prismsec/
├── server.py              # MCP server entry point (13 tools)
├── pyproject.toml         # Project config + dependencies
├── tools/                 # Tool wrappers (one file per tool)
│   ├── base.py           # ToolWrapper ABC + async runner
│   ├── nmap.py           # Nmap — XML parsing, scan modes
│   ├── nuclei.py         # Nuclei — JSON output parsing
│   ├── gobuster.py       # Gobuster — text output parsing
│   ├── subfinder.py      # Subfinder — subdomain enum
│   ├── httpx.py          # Httpx — web probing
│   ├── nikto.py          # Nikto — web vuln scan
│   └── sqlmap.py         # Sqlmap — SQL injection testing
├── parsers/               # Output parsers
│   ├── xml_parser.py     # nmap XML → structured JSON
│   ├── json_parser.py    # JSON/JSONL parsing
│   └── text_parser.py    # Gobuster, nikto, sqlmap text
└── utils/                 # Shared utilities
    ├── runner.py          # AsyncRunner with timeout
    ├── validator.py       # Input validation + injection detection
    ├── rate_limiter.py    # Token bucket rate limiter
    └── logging.py         # Structured logging
```

---

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |

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

Built with the [Model Context Protocol](https://modelcontextprotocol.io/) standard for broad client compatibility.
