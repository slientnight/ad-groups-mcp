"""Tests for startup behaviour: AD module check.

Validates Requirement 1.4 (AD module missing at startup).
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from ad_groups_mcp.__main__ import check_ad_module


class TestADModuleMissing:
    """Req 1.4: Server refuses to start when AD module is unavailable."""

    @pytest.mark.asyncio
    async def test_check_ad_module_returns_false_when_missing(self):
        """check_ad_module returns False when test_ad_module returns False."""
        with patch(
            "ad_groups_mcp.ad_query.test_ad_module",
            new_callable=AsyncMock,
            return_value=False,
        ):
            result = await check_ad_module()
        assert result is False

    @pytest.mark.asyncio
    async def test_check_ad_module_returns_true_when_present(self):
        """check_ad_module returns True when test_ad_module returns True."""
        with patch(
            "ad_groups_mcp.ad_query.test_ad_module",
            new_callable=AsyncMock,
            return_value=True,
        ):
            result = await check_ad_module()
        assert result is True

    def test_main_exits_when_ad_module_missing(self):
        """main() calls sys.exit(1) when AD module is unavailable."""
        import argparse

        fake_args = argparse.Namespace(
            transport="stdio", policy_file="policy.yaml", db_path="reviews.db"
        )
        with (
            patch("ad_groups_mcp.__main__.parse_args", return_value=fake_args),
            patch(
                "ad_groups_mcp.__main__.asyncio.run", return_value=False
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            from ad_groups_mcp.__main__ import main

            main()
        assert exc_info.value.code == 1
