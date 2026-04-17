"""Entry point for the AD Groups MCP server.

Startup sequence:
1. Parse CLI arguments (transport, policy file, db path)
2. Check AD module availability (refuse to start if missing)
3. Load policy configuration from YAML (fallback to defaults)
4. Initialize SQLite store (create schema if needed)
5. Create FastMCP server and register tools/resources/prompts
6. Run server with selected transport
"""

from __future__ import annotations

import asyncio
import logging
import sys

from ad_groups_mcp.config import load_policy_config, parse_args

logger = logging.getLogger(__name__)


async def check_ad_module() -> bool:
    """Check if the ActiveDirectory PowerShell module is available.

    Delegates to ad_query.test_ad_module() which runs a PowerShell subprocess.
    """
    from ad_groups_mcp.ad_query import test_ad_module  # noqa: E402

    return await test_ad_module()


def main() -> None:
    """Main entry point for the AD Groups MCP server."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # 1. Parse CLI arguments
    args = parse_args()
    logger.info(
        "Starting AD Groups MCP server (transport=%s, policy=%s, db=%s)",
        args.transport,
        args.policy_file,
        args.db_path,
    )

    # 2. Check AD module availability
    ad_available = asyncio.run(check_ad_module())
    if not ad_available:
        print(
            "Error: Active Directory PowerShell module is not available. "
            "Install RSAT or run on a domain controller.",
            file=sys.stderr,
        )
        sys.exit(1)

    # 3. Load policy configuration
    policy_config = load_policy_config(args.policy_file)
    logger.info("Policy loaded: %s", policy_config)

    # 4. Initialize SQLite store
    from ad_groups_mcp.sqlite_store import SQLiteStore  # noqa: E402

    store = SQLiteStore(args.db_path)
    store.initialize()
    logger.info("SQLite store initialized at '%s'", args.db_path)

    # 5. Create FastMCP server and register tools
    from ad_groups_mcp.server import create_server  # noqa: E402

    server = create_server(policy_config=policy_config, store=store)

    # 6. Run with selected transport
    logger.info("Running server with transport: %s", args.transport)
    server.run(transport=args.transport)


if __name__ == "__main__":
    main()
