"""Input validation for MCP Recon tool parameters.

Provides:
- Target validation (IP, CIDR, hostname, URL)
- Argument whitelisting to prevent injection
- Timeout and numeric validation
- General sanitisation helpers

All validators return ``tuple[bool, str]`` — ``(True, "")`` on success,
``(False, "reason")`` on failure.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Whitelist of allowed characters in tool arguments.
# Covers: alphanumerics, dots, dashes, underscores, slashes, colons (for URLs),
# equals (for key=value), spaces (for multi-word values), hashes (for fragments),
# question marks, ampersands (for query strings), tildes, percentage signs.
_SAFE_ARG_RE = re.compile(r"^[a-zA-Z0-9._/:\-=?&#@!%+~\[\] ]+$")

# Maximum length for any single argument
MAX_ARG_LENGTH: int = 2048

# Allowed target patterns
_TARGET_RE = re.compile(
    r"^[a-zA-Z0-9._:/\-@?=&%+~\[\]]+$"
)

# Forbidden patterns that indicate injection attempts
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r";\s*"),      # command chaining
    re.compile(r"\|\s*"),     # piping (unless explicitly allowed)
    re.compile(r"`[^`]+`"),   # backtick substitution
    re.compile(r"\$\("),      # $() command substitution
    re.compile(r"\$\{"),      # ${} variable expansion
    re.compile(r">\s*/"),      # redirect to file
    re.compile(r"&&\s*"),     # AND chaining
    re.compile(r"\|\|\s*"),   # OR chaining
]


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------

def validate_target(target: str) -> tuple[bool, str]:
    """Validate a scan target (IP, CIDR, hostname, or URL).

    Accepts:
    - IPv4 addresses: ``10.0.0.1``
    - IPv6 addresses: ``::1``, ``fe80::1``
    - CIDR notation: ``192.168.0.0/24``
    - Hostnames: ``example.com``, ``sub.domain.local``
    - URLs: ``https://example.com:8443/path``

    Rejects:
    - Empty strings
    - Arguments exceeding ``MAX_ARG_LENGTH``
    - Shell metacharacters indicative of injection
    - Characters outside the safe character set

    Args:
        target: The target string to validate.

    Returns:
        ``(True, "")`` if valid, ``(False, reason)`` if invalid.
    """
    if not target or not target.strip():
        return False, "Target must not be empty"

    target = target.strip()

    if len(target) > MAX_ARG_LENGTH:
        return False, f"Target exceeds maximum length of {MAX_ARG_LENGTH}"

    # Check for injection patterns
    is_injection, reason = _check_injection(target)
    if is_injection:
        return False, reason

    # Check safe character set
    if not _SAFE_ARG_RE.match(target):
        return False, "Target contains disallowed characters"

    # Try parsing as various target types
    if _is_valid_ip_or_cidr(target):
        return True, ""

    if _is_valid_hostname(target):
        return True, ""

    if _is_valid_url(target):
        return True, ""

    return False, f"Target is not a valid IP, CIDR, hostname, or URL: {target}"


def _is_valid_ip_or_cidr(target: str) -> bool:
    """Check if target is a valid IP address or CIDR range."""
    try:
        if "/" in target:
            ipaddress.ip_network(target, strict=False)
        else:
            ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _is_valid_hostname(target: str) -> bool:
    """Check if target is a plausible hostname.

    Allows:
    - Single-label names (e.g. ``localhost``)
    - Multi-label names (e.g. ``sub.example.com``)
    - Names with hyphens and digits
    - Wildcard patterns (e.g. ``*.example.com``)
    """
    # Strip leading wildcard
    name = target.lstrip("*.")
    if not name:
        return False

    labels = name.split(".")
    if len(labels) > 127:
        return False

    for label in labels:
        if not label:
            return False
        if len(label) > 63:
            return False
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$", label):
            return False

    return True


def _is_valid_url(target: str) -> bool:
    """Check if target is a valid HTTP/HTTPS URL."""
    try:
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            return False
        if not parsed.hostname:
            return False
        return True
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

def validate_args(args: list[str], *, allowed_flags: set[str] | None = None) -> tuple[bool, str]:
    """Validate a list of command arguments.

    Checks each argument for:
    - Injection patterns
    - Safe character set
    - Length limits
    - Optional flag whitelisting

    Args:
        args: List of arguments to validate.
        allowed_flags: If provided, only these flags (e.g. ``{"-sV", "-p", "-oX"}``)
                       are permitted. None allows all flags.

    Returns:
        ``(True, "")`` if all arguments pass, ``(False, reason)`` on first failure.
    """
    for arg in args:
        if not arg:
            continue

        if len(arg) > MAX_ARG_LENGTH:
            return False, f"Argument exceeds maximum length: {arg[:80]}..."

        # Check injection
        is_injection, reason = _check_injection(arg)
        if is_injection:
            return False, f"Injection detected in argument '{arg[:50]}': {reason}"

        # Check safe characters
        if not _SAFE_ARG_RE.match(arg):
            return False, f"Argument contains disallowed characters: {arg[:50]}"

        # Flag whitelisting
        if allowed_flags is not None and arg.startswith("-"):
            if arg not in allowed_flags:
                return False, f"Flag not in allowlist: {arg}"

    return True, ""


def sanitize_arg(arg: str) -> str:
    """Strip potentially dangerous characters from an argument.

    This is a last-resort sanitiser — prefer proper validation via
    ``validate_target`` or ``validate_args`` before calling this.

    Args:
        arg: The argument to sanitise.

    Returns:
        The sanitised argument (leading/trailing whitespace stripped,
        null bytes removed).
    """
    return arg.strip().replace("\x00", "")


# ---------------------------------------------------------------------------
# Numeric / timeout validation
# ---------------------------------------------------------------------------

def validate_timeout(value: Any, *, min_val: float = 1.0, max_val: float = 3600.0) -> tuple[bool, str]:
    """Validate a timeout value.

    Args:
        value: The value to check (must be numeric).
        min_val: Minimum allowed value (seconds).
        max_val: Maximum allowed value (seconds).

    Returns:
        ``(True, "")`` if valid, ``(False, reason)`` if invalid.
    """
    try:
        num = float(value)
    except (TypeError, ValueError):
        return False, f"Timeout must be a number, got {type(value).__name__}: {value!r}"

    if num < min_val:
        return False, f"Timeout must be >= {min_val}s, got {num}"
    if num > max_val:
        return False, f"Timeout must be <= {max_val}s, got {num}"

    return True, ""


def validate_port(value: Any) -> tuple[bool, str]:
    """Validate a port number or port range string.

    Accepts:
    - Single port: ``443``
    - Port range: ``1-1024``
    - Comma-separated: ``80,443,8080``
    - Mixed: ``80,443,8000-9000``

    Returns:
        ``(True, "")`` if valid, ``(False, reason)`` if invalid.
    """
    s = str(value).strip()
    if not s:
        return False, "Port specification must not be empty"

    # Split by commas and validate each part
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            # Port range
            try:
                start_s, end_s = part.split("-", 1)
                start, end = int(start_s), int(end_s)
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    return False, f"Port range out of bounds: {part}"
                if start > end:
                    return False, f"Port range start > end: {part}"
            except ValueError:
                return False, f"Invalid port range: {part}"
        else:
            try:
                port = int(part)
                if not 1 <= port <= 65535:
                    return False, f"Port out of range (1-65535): {port}"
            except ValueError:
                return False, f"Invalid port number: {part}"

    return True, ""


def validate_url(url: str) -> tuple[bool, str]:
    """Validate a URL for scanning targets.

    Checks scheme, hostname presence, and character safety.

    Returns:
        ``(True, "")`` if valid, ``(False, reason)`` if invalid.
    """
    if not url or not url.strip():
        return False, "URL must not be empty"

    url = url.strip()

    if len(url) > MAX_ARG_LENGTH:
        return False, f"URL exceeds maximum length of {MAX_ARG_LENGTH}"

    is_injection, reason = _check_injection(url)
    if is_injection:
        return False, reason

    try:
        parsed = urlparse(url)
    except (ValueError, AttributeError):
        return False, f"Malformed URL: {url}"

    if parsed.scheme not in ("http", "https"):
        return False, f"URL scheme must be http or https, got: {parsed.scheme}"

    if not parsed.hostname:
        return False, "URL must have a hostname"

    return True, ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_injection(value: str) -> tuple[bool, str]:
    """Check for shell injection patterns.

    Returns:
        ``(True, reason)`` if injection detected, ``(False, "")`` otherwise.
    """
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(value):
            return True, f"Suspicious pattern detected: {pattern.pattern!r}"
    return False, ""
