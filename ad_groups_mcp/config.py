"""CLI argument parsing and policy configuration loading."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import yaml

from ad_groups_mcp.models import PolicyConfig

logger = logging.getLogger(__name__)

VALID_TRANSPORTS = ("stdio", "sse", "streamable-http")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for the AD Groups MCP server."""
    parser = argparse.ArgumentParser(
        prog="ad-groups-mcp",
        description="Read-only Active Directory group management MCP server",
    )
    parser.add_argument(
        "--transport",
        choices=VALID_TRANSPORTS,
        default="stdio",
        help="MCP transport to use (default: stdio)",
    )
    parser.add_argument(
        "--policy-file",
        type=str,
        default="policy.yaml",
        help="Path to YAML policy configuration file (default: policy.yaml)",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default="reviews.db",
        help="Path to SQLite database file (default: reviews.db)",
    )
    return parser.parse_args(argv)


def load_policy_config(policy_file: str) -> PolicyConfig:
    """Load PolicyConfig from a YAML file.

    Falls back to defaults if the file is missing.
    Raises SystemExit if the file exists but contains malformed YAML.
    """
    path = Path(policy_file)

    if not path.exists():
        logger.warning(
            "Policy file '%s' not found, using built-in defaults.", policy_file
        )
        return PolicyConfig()

    try:
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        logger.error("Malformed YAML in policy file '%s': %s", policy_file, exc)
        print(
            f"Error: Policy file '{policy_file}' contains invalid YAML: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)

    if data is None:
        # Empty file — treat as defaults
        return PolicyConfig()

    if not isinstance(data, dict):
        msg = f"Policy file '{policy_file}' must contain a YAML mapping, got {type(data).__name__}"
        logger.error(msg)
        print(f"Error: {msg}", file=sys.stderr)
        sys.exit(1)

    return PolicyConfig(**data)
