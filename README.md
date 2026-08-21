# MCP Recon

**Secure MCP server for security reconnaissance and analysis tools.**

A hardened alternative to [HexStrike AI](https://github.com/hexstrike/hexstrike-mcp-server) — built with security-first principles, input validation, command sanitization, and zero trust by default.

---

## Why MCP Recon?

HexStrike AI exposed critical security flaws:

- **No input validation** — tools accepted arbitrary unsanitized input
- **Shell injection vectors** — commands passed directly to `subprocess` without escaping
- **No rate limiting** — unbounded resource consumption
- **No audit logging** — no trace of what was executed or when
- **Implicit trust model** — tools ran with full permissions, no scoping

MCP Recon fixes every one of these. It's a drop-in replacement that gives you the same recon capabilities without the attack surface.

---

## Security Features

| Feature | Description |
|---------|-------------|
| **Input validation** | Every tool parameter is type-checked and sanitized via Pydantic models before execution |
| **Command sanitization** | Shell commands are built with `shlex` — no injection, no raw string concatenation |
| **Sandboxed execution** | Subprocess calls run with restricted permissions, timeouts, and output limits |
| **Allowlist-only design** | Only explicitly registered tools are exposed — no dynamic code execution |
| **Audit logging** | Every tool invocation is logged with timestamp, caller, parameters, and exit status |
| **Rate limiting** | Configurable per-tool rate limits prevent abuse and resource exhaustion |
| **Read-only defaults** | Recon tools read data; they don't modify, delete, or write to your system without explicit opt-in |
| **No credentials stored** | API keys and tokens are passed at runtime, never persisted to disk |

---

## Installation

### With `uv` (recommended)

```bash
uv pip install mcp-recon
```

Or add to an existing project:

```bash
uv add mcp-recon
```

### With `pip`

```bash
pip install mcp-recon
```

### From source

```bash
git clone https://github.com/nousresearch/mcp-recon.git
cd mcp-recon
pip install -e ".[dev]"
```

### Verify installation

```bash
mcp-recon --version
```

---

## Tools

MCP Recon ships with the following security reconnaissance tools:

### Reconnaissance

| Tool | Description |
|------|-------------|
| `dns_lookup` | DNS record enumeration — A, AAAA, MX, NS, TXT, SOA, CNAME lookups |
| `whois_lookup` | Domain registration and ownership information retrieval |
| `subdomain_enum` | Subdomain enumeration via DNS brute-forcing and certificate transparency logs |
| `port_scan` | TCP/UDP port scanning with configurable timeout and concurrency |
| `http_headers` | HTTP response header analysis (security headers, server info, caching) |
| `ssl_inspect` | TLS/SSL certificate inspection — issuer, expiry, chain, protocol versions |
| `tech_detect` | Web technology fingerprinting — CMS, frameworks, libraries, CDN detection |

### OSINT

| Tool | Description |
|------|-------------|
| `shodan_query` | Query Shodan for host information, open ports, and services |
| `cve_lookup` | CVE vulnerability database search by ID or keyword |
| `paste_search` | Search public paste sites for leaked credentials or sensitive data |

### Analysis

| Tool | Description |
|------|-------------|
| `url_analyze` | URL safety analysis — redirects, reputation, content type detection |
| `email_validate` | Email address validation — format, domain, MX record verification |
| `ip_geolocate` | IP address geolocation and ASN information |

---

## Usage Examples

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mcp-recon": {
      "command": "mcp-recon",
      "args": ["--transport", "stdio"],
      "env": {}
    }
  }
}
```

### Claude Code

```bash
claude mcp add mcp-recon mcp-recon --transport stdio
```

### Cursor

Add to `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "mcp-recon": {
      "command": "mcp-recon",
      "args": ["--transport", "stdio"]
    }
  }
}
```

### Windsurf

Add to your Windsurf MCP config:

```json
{
  "mcpServers": {
    "mcp-recon": {
      "command": "mcp-recon",
      "args": ["--transport", "stdio"]
    }
  }
}
```

### Cline (VS Code)

Add to `~/.cline/mcp_settings.json`:

```json
{
  "mcpServers": {
    "mcp-recon": {
      "command": "mcp-recon",
      "args": ["--transport", "stdio"]
    }
  }
}
```

### SSE transport (remote/shared server)

```bash
# Server side
mcp-recon --transport sse --host 0.0.0.0 --port 8080

# Client config (e.g. Claude Desktop)
{
  "mcpServers": {
    "mcp-recon": {
      "url": "http://localhost:8080/sse"
    }
  }
}
```

---

## Configuration

MCP Recon supports configuration via environment variables and a config file.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_RECON_LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `MCP_RECON_LOG_FILE` | *(none)* | Path to log file (logs to stderr by default) |
| `MCP_RECON_RATE_LIMIT` | `60` | Max tool invocations per minute |
| `MCP_RECON_TIMEOUT` | `30` | Default subprocess timeout in seconds |
| `MCP_RECON_SSHOC_API_KEY` | *(none)* | API key for Shodan integration |
| `MCP_RECON_NVD_API_KEY` | *(none)* | API key for NVD CVE lookups |

### Config file

Place a `mcp-recon.toml` in your project root or `~/.config/mcp-recon/`:

```toml
[server]
transport = "stdio"
host = "127.0.0.1"
port = 8080
timeout = 30

[security]
rate_limit = 60
max_output_bytes = 1048576  # 1MB
allowed_schemes = ["http", "https"]
blocked_domains = ["localhost", "127.0.0.1", "0.0.0.0"]

[tools]
# Disable specific tools you don't need
disabled = ["shodan_query", "paste_search"]

[tools.port_scan]
max_concurrency = 10
default_timeout = 2
```

### Tool-specific options

Some tools accept additional configuration:

```toml
[tools.dns_lookup]
timeout = 10
dns_servers = ["1.1.1.1", "8.8.8.8"]

[tools.port_scan]
max_ports = 100
max_concurrency = 10
common_ports_only = true

[tools.subdomain_enum]
max_depth = 2
wordlist = "common"  # or path to custom wordlist
```

---

## Comparison with HexStrike AI

| Feature | HexStrike AI | MCP Recon |
|---------|-------------|-----------|
| **Input validation** | ❌ None — raw string pass-through | ✅ Pydantic models, type-checked |
| **Shell injection protection** | ❌ `subprocess` with raw strings | ✅ `shlex` sanitization on all commands |
| **Audit logging** | ❌ No logging | ✅ Structured logging with timestamps |
| **Rate limiting** | ❌ None | ✅ Per-tool configurable limits |
| **Timeout enforcement** | ❌ No timeouts | ✅ Configurable per-tool timeouts |
| **Output size limits** | ❌ Unbounded | ✅ Configurable max output bytes |
| **Read-only by default** | ❌ Full filesystem access | ✅ Recon tools read-only, write requires explicit opt-in |
| **Domain allowlisting** | ❌ None | ✅ Blocked domains configurable |
| **Credential handling** | ⚠️ Stored in code | ✅ Runtime-only, never persisted |
| **Transport options** | ⚠️ stdio only | ✅ stdio + SSE |
| **Config file** | ❌ None | ✅ TOML-based configuration |
| **Python version** | ⚠️ Python 3.8+ | ✅ Python 3.10+ (modern type hints, async) |
| **Maintained** | ❌ Deprecated | ✅ Active development |
| **Open source** | ✅ MIT | ✅ MIT |

---

## Development

```bash
# Clone and set up
git clone https://github.com/nousresearch/mcp-recon.git
cd mcp-recon
uv sync

# Run tests
uv run pytest

# Type checking
uv run mypy src/

# Linting
uv run ruff check src/
```

### Project structure

```
mcp-recon/
├── mcp_recon/
│   ├── __init__.py
│   ├── server.py          # MCP server entry point
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── recon.py       # DNS, port scan, HTTP, SSL tools
│   │   ├── osint.py       # Shodan, CVE, paste search
│   │   └── analysis.py    # URL analysis, email validation
│   ├── parsers/
│   │   ├── __init__.py
│   │   └── output.py      # Output parsers for tool results
│   └── utils/
│       ├── __init__.py
│       ├── sanitize.py    # Input sanitization utilities
│       └── logging.py     # Audit logging
├── pyproject.toml
├── README.md
└── LICENSE
```

---

## Security Considerations

MCP Recon is designed for **authorized security testing only**. Use it against systems you own or have explicit written permission to test.

- Tool outputs may contain sensitive information (IPs, hostnames, open ports). Handle responsibly.
- When using Shodan/CVE tools, ensure your API keys are kept secret and not committed to version control.
- The server binds to `127.0.0.1` by default when using SSE transport — never expose it to untrusted networks without authentication.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Contributing

Contributions welcome. Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-tool`)
3. Add tests for new tools
4. Run `uv run ruff check` and `uv run mypy src/` before submitting
5. Open a pull request

---

## Acknowledgments

Built as a secure alternative to HexStrike AI MCP, inspired by the need for hardened security tools in the AI-assisted pentesting workflow. Uses the [Model Context Protocol](https://modelcontextprotocol.io/) standard for broad client compatibility.
