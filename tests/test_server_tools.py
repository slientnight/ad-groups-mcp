"""Additional server tool tests covering gaps not in test_server.py.

- 9.5: Group not found (Req 4.3), empty search results (Req 3.3)
- 9.8: No replication metadata via get_group (Req 8.3)
- 9.9: No review records / empty review list (Req 11.3, 12.3)
- 9.10: Bulk audit error isolation (Req 6.4)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from ad_groups_mcp.models import PolicyConfig, ToolError
from ad_groups_mcp.server import create_server
from ad_groups_mcp.sqlite_store import SQLiteStore


@pytest.fixture
def store(tmp_path):
    db_path = str(tmp_path / "test_reviews.db")
    s = SQLiteStore(db_path)
    s.initialize()
    return s


@pytest.fixture
def server(store):
    return create_server(policy_config=PolicyConfig(), store=store)


# ---------------------------------------------------------------------------
# 9.5 — Empty search results and group not found (Req 3.3, 4.3)
# ---------------------------------------------------------------------------

class TestEmptySearchAndGroupNotFound:
    @pytest.mark.asyncio
    async def test_search_no_matches_returns_empty_with_message(self, server):
        """Req 3.3: No matches returns empty list with message."""
        tool_fn = server._tool_manager._tools["search_groups"].fn
        with patch(
            "ad_groups_mcp.ad_query.search_ad_groups",
            new_callable=AsyncMock,
            return_value=[],
        ):
            result = await tool_fn(query="nonexistent")
        assert result.groups == []
        assert result.message == "No matches found"

    @pytest.mark.asyncio
    async def test_get_group_not_found_returns_error(self, server):
        """Req 4.3: Group not found returns ToolError with GROUP_NOT_FOUND."""
        tool_fn = server._tool_manager._tools["get_group"].fn
        with patch(
            "ad_groups_mcp.ad_query.get_ad_group",
            new_callable=AsyncMock,
            side_effect=RuntimeError("Group not found in Active Directory"),
        ):
            result = await tool_fn(identity="CN=Missing,DC=example,DC=com")
        assert isinstance(result, ToolError)
        assert result.code == "GROUP_NOT_FOUND"

    @pytest.mark.asyncio
    async def test_get_group_ad_unreachable_returns_error(self, server):
        """AD unreachable returns ToolError with AD_UNREACHABLE."""
        tool_fn = server._tool_manager._tools["get_group"].fn
        with patch(
            "ad_groups_mcp.ad_query.get_ad_group",
            new_callable=AsyncMock,
            side_effect=RuntimeError("Connection timed out"),
        ):
            result = await tool_fn(identity="SEC_Finance")
        assert isinstance(result, ToolError)
        assert result.code == "AD_UNREACHABLE"


# ---------------------------------------------------------------------------
# 9.8 — No replication metadata via get_group tool (Req 8.3)
# ---------------------------------------------------------------------------

class TestNoReplicationMetadata:
    @pytest.mark.asyncio
    async def test_get_group_with_no_replication_metadata(self, server):
        """Req 8.3: get_group returns None replication_metadata when none exists."""
        from tests.conftest import MOCK_AD_GROUP_RAW

        tool_fn = server._tool_manager._tools["get_group"].fn
        with (
            patch(
                "ad_groups_mcp.ad_query.get_ad_group",
                new_callable=AsyncMock,
                return_value=MOCK_AD_GROUP_RAW,
            ),
            patch(
                "ad_groups_mcp.replication.get_member_replication_metadata",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            result = await tool_fn(identity="SEC_Finance")
        assert not isinstance(result, ToolError)
        assert result.replication_metadata is None


# ---------------------------------------------------------------------------
# 9.9 — No review records and empty review list (Req 11.3, 12.3)
# ---------------------------------------------------------------------------

class TestNoReviewRecords:
    @pytest.mark.asyncio
    async def test_get_group_review_no_record(self, server):
        """Req 11.3: get_group_review returns message when no review exists."""
        tool_fn = server._tool_manager._tools["get_group_review"].fn
        result = await tool_fn(group_dn="CN=NeverReviewed,DC=example,DC=com")
        assert isinstance(result, dict)
        assert "No review" in result["message"]

    @pytest.mark.asyncio
    async def test_list_recorded_reviews_empty(self, server):
        """Req 12.3: list_recorded_reviews returns empty list when none exist."""
        tool_fn = server._tool_manager._tools["list_recorded_reviews"].fn
        result = await tool_fn()
        assert isinstance(result, list)
        assert len(result) == 0


# ---------------------------------------------------------------------------
# 9.10 — Bulk audit error isolation (Req 6.4)
# ---------------------------------------------------------------------------

class TestBulkAuditErrorIsolation:
    @pytest.mark.asyncio
    async def test_one_group_fails_others_continue(self, server):
        """Req 6.4: Error on one group doesn't stop the rest."""
        good_group = {
            "DistinguishedName": "CN=SEC_Good,OU=Groups,DC=example,DC=com",
            "SamAccountName": "SEC_Good",
            "GroupScope": "Global",
            "GroupCategory": "Security",
            "Description": "Good group",
            "ManagedBy": "CN=Admin,DC=example,DC=com",
            "whenCreated": "2024-01-01T00:00:00+00:00",
            "whenChanged": "2024-06-01T00:00:00+00:00",
            "Member": [],
        }
        bad_group = {
            "DistinguishedName": "CN=SEC_Bad,OU=Groups,DC=example,DC=com",
            "SamAccountName": "SEC_Bad",
        }

        call_count = 0

        async def mock_get_ad_group(identity):
            nonlocal call_count
            call_count += 1
            if "SEC_Bad" in identity:
                raise RuntimeError("Simulated failure for SEC_Bad")
            return good_group

        tool_fn = server._tool_manager._tools["audit_group_inventory"].fn
        with (
            patch(
                "ad_groups_mcp.ad_query.get_all_ad_groups",
                new_callable=AsyncMock,
                return_value=[good_group, bad_group],
            ),
            patch(
                "ad_groups_mcp.ad_query.get_ad_group",
                new_callable=AsyncMock,
                side_effect=mock_get_ad_group,
            ),
            patch(
                "ad_groups_mcp.replication.get_member_replication_metadata",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            result = await tool_fn()

        # The audit should complete despite one group failing
        assert result.total_groups == 2
        assert len(result.errors) >= 1
        # The good group should have been evaluated
        assert result.compliant_count + len(result.per_group_violations) >= 1


# ---------------------------------------------------------------------------
# 5.5 — Dual-write partial failure scenarios (Req 3.4, 3.5)
# ---------------------------------------------------------------------------

class TestDualWritePartialFailures:
    @pytest.mark.asyncio
    async def test_dual_write_ad_failure(self, server, store):
        """Req 3.4: AD write fails → SQLite write succeeds + warning returned."""
        tool_fn = server._tool_manager._tools["record_group_review"].fn
        group_dn = "CN=SEC_TestGroup,OU=Groups,DC=example,DC=com"

        with patch(
            "ad_groups_mcp.ad_query.set_ad_group_review_attrs",
            new_callable=AsyncMock,
            side_effect=RuntimeError("Insufficient permissions"),
        ):
            result = await tool_fn(group_dn=group_dn, reviewer="jsmith")

        # Should succeed (not a ToolError)
        assert not isinstance(result, ToolError)
        assert result.group_dn == group_dn
        assert result.reviewer == "jsmith"
        # Should have a warning about AD failure
        assert len(result.warnings) == 1
        assert "AD attribute write failed" in result.warnings[0]
        # SQLite write should have succeeded
        sqlite_review = store.get_review(group_dn)
        assert sqlite_review is not None
        assert sqlite_review.reviewer == "jsmith"

    @pytest.mark.asyncio
    async def test_dual_write_sqlite_failure(self, server, store):
        """Req 3.5: SQLite write fails → AD write succeeds + warning returned."""
        tool_fn = server._tool_manager._tools["record_group_review"].fn
        group_dn = "CN=SEC_TestGroup,OU=Groups,DC=example,DC=com"

        with (
            patch.object(
                store,
                "record_review",
                side_effect=RuntimeError("Disk full"),
            ),
            patch(
                "ad_groups_mcp.ad_query.set_ad_group_review_attrs",
                new_callable=AsyncMock,
            ) as mock_ad_write,
        ):
            result = await tool_fn(group_dn=group_dn, reviewer="jsmith")

        # Should succeed (not a ToolError)
        assert not isinstance(result, ToolError)
        assert result.group_dn == group_dn
        assert result.reviewer == "jsmith"
        # Should have a warning about SQLite failure
        assert len(result.warnings) == 1
        assert "SQLite write failed" in result.warnings[0]
        # AD write should have been called
        mock_ad_write.assert_called_once()
