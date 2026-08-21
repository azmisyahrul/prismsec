"""Logging setup for the MCP security tools server."""

import logging
import sys


def setup_logging(level: str = "INFO", name: str = "mcp-recon") -> logging.Logger:
    """Configure structured logging for the server.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR).
        name: Logger name.

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter(
                "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
        logger.addHandler(handler)

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    return logger
