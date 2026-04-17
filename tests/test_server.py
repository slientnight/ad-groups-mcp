"""Tests for the MCP server tool registration and basic tool behavior."""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from ad_groups_mcp.models import (
    PolicyConfig,
    ReplicationMetadata,
    ReviewRecord,
    ToolError,
)
from ad_groups_mcp.server import create_server, _parse_ad_datetime
from ad_groups_mcp.sqlite_store import SQLiteStore


@pytest.fixture
def policy_config():
    return PolicyConfig()


@pytest.fixture
def store(tmp_path):
    db_path = str(tmp_path / "test_reviews.db")
    s = SQLiteStore(db_path)
    s.initialize()
    return s


@pytest.fixture
def server(policy_config, store):
    return create_server(policy_config=policy_config, store=store)


class TestCreateServer:
    def test_creates_fastmcp_instance(self, server):
        assert server is not None
        assert server.name == "ad-groups-mcp"

    def test_server_has_tools_registered(self, server):
        """Verify all 9 tools are registered on the server."""
        # FastMCP stores tools internally; we check the tool names exist
        tool_names = {
            "healthcheck",
            "search_groups",
            "get_group",
            "evaluate_group_policy",
            "audit_group_inventory",
            "get_group_change_events",
            "record_group_review",
            "get_group_review",
            "list_recorded_reviews",
            "list_privileged_groups",
            "record_membership_snapshot",
            "get_membership_drift",
            "review_coverage",
        }
        # Access the internal tool registry
        registered = set(server._tool_manager._tools.keys())
        assert tool_names.issubset(registered), (
            f"Missing tools: {tool_names - registered}"
        )


class TestSearchGroupsValidation:
    @pytest.mark.asyncio
    async def test_empty_query_returns_tool_error(self, server):
        """search_groups rejects empty query."""
        tool_fn = server._tool_manager._tools["search_groups"].fn
        result = await tool_fn(query="")
        assert isinstance(result, ToolError)
        assert result.code == "INVALID_INPUT"

    @pytest.mark.asyncio
    async def test_whitespace_query_returns_tool_error(self, server):
        """search_groups rejects whitespace-only query."""
        tool_fn = server._tool_manager._tools["search_groups"].fn
        result = await tool_fn(query="   ")
        assert isinstance(result, ToolError)
        assert result.code == "INVALID_INPUT"


class TestRecordGroupReviewValidation:
    @pytest.mark.asyncio
    async def test_empty_group_dn_returns_tool_error(self, server):
        """record_group_review rejects empty group_dn."""
        tool_fn = server._tool_manager._tools["record_group_review"].fn
        result = await tool_fn(group_dn="", reviewer="admin")
        assert isinstance(result, ToolError)
        assert result.code == "INVALID_INPUT"

    @pytest.mark.asyncio
    async def test_whitespace_group_dn_returns_tool_error(self, server):
        """record_group_review rejects whitespace-only group_dn."""
        tool_fn = server._tool_manager._tools["record_group_review"].fn
        result = await tool_fn(group_dn="   ", reviewer="admin")
        assert isinstance(result, ToolError)
        assert result.code == "INVALID_INPUT"

    @pytest.mark.asyncio
    async def test_valid_review_returns_confirmation(self, server):
        """record_group_review succeeds with valid inputs."""
        tool_fn = server._tool_manager._tools["record_group_review"].fn
        result = await tool_fn(
            group_dn="CN=TestGroup,DC=example,DC=com", reviewer="admin"
        )
        assert not isinstance(result, ToolError)
        assert result.group_dn == "CN=TestGroup,DC=example,DC=com"
        assert result.reviewer == "admin"


class TestGetGroupReview:
    @pytest.mark.asyncio
    async def test_no_review_returns_message(self, server):
        """get_group_review returns message when no review exists."""
        tool_fn = server._tool_manager._tools["get_group_review"].fn
        result = await tool_fn(group_dn="CN=NoReview,DC=example,DC=com")
        assert isinstance(result, dict)
        assert "message" in result

    @pytest.mark.asyncio
    async def test_existing_review_returns_record(self, server, store):
        """get_group_review returns record after one is created."""
        dn = "CN=Reviewed,DC=example,DC=com"
        store.record_review(dn, "reviewer1")
        tool_fn = server._tool_manager._tools["get_group_review"].fn
        result = await tool_fn(group_dn=dn)
        assert isinstance(result, dict)
        assert result["group_dn"] == dn
        assert result["reviewer"] == "reviewer1"


class TestListRecordedReviews:
    @pytest.mark.asyncio
    async def test_empty_list(self, server):
        """list_recorded_reviews returns empty list when no reviews exist."""
        tool_fn = server._tool_manager._tools["list_recorded_reviews"].fn
        result = await tool_fn()
        assert isinstance(result, list)
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_returns_recorded_reviews(self, server, store):
        """list_recorded_reviews returns all recorded reviews."""
        store.record_review("CN=G1,DC=example,DC=com", "r1")
        store.record_review("CN=G2,DC=example,DC=com", "r2")
        tool_fn = server._tool_manager._tools["list_recorded_reviews"].fn
        result = await tool_fn()
        assert isinstance(result, list)
        assert len(result) == 2


class TestHealthcheck:
    @pytest.mark.asyncio
    async def test_healthcheck_ad_failure(self, server):
        """healthcheck returns error status when AD is unreachable."""
        tool_fn = server._tool_manager._tools["healthcheck"].fn
        with patch(
            "ad_groups_mcp.ad_query.run_ps_command",
            new_callable=AsyncMock,
            side_effect=RuntimeError("AD unreachable"),
        ):
            result = await tool_fn()
        assert result.status == "error"
        assert result.error_message is not None

    @pytest.mark.asyncio
    async def test_healthcheck_success(self, server):
        """healthcheck returns ok status when AD responds."""
        tool_fn = server._tool_manager._tools["healthcheck"].fn
        with patch(
            "ad_groups_mcp.ad_query.run_ps_command",
            new_callable=AsyncMock,
            return_value={
                "DomainController": "DC01.example.com",
                "DomainName": "example.com",
            },
        ):
            result = await tool_fn()
        assert result.status == "ok"
        assert result.domain_controller == "DC01.example.com"
        assert result.domain_name == "example.com"


class TestParseAdDatetime:
    def test_none_returns_utc_now(self):
        before = datetime.now(timezone.utc)
        result = _parse_ad_datetime(None)
        after = datetime.now(timezone.utc)
        assert before <= result <= after

    def test_valid_iso_string(self):
        result = _parse_ad_datetime("2024-01-15T10:30:00+00:00")
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15

    def test_invalid_string_returns_utc_now(self):
        before = datetime.now(timezone.utc)
        result = _parse_ad_datetime("not-a-date")
        after = datetime.now(timezone.utc)
        assert before <= result <= after

    def test_microsoft_json_date(self):
        """AD ConvertTo-Json often returns /Date(1350561951000)/"""
        result = _parse_ad_datetime("/Date(1350561951000)/")
        assert result.year == 2012
        assert result.month == 10
        assert result.day == 18

    def test_us_locale_with_pm(self):
        """ADUC shows dates like '10/18/2012 2:45:51 PM'"""
        result = _parse_ad_datetime("10/18/2012 2:45:51 PM")
        assert result.year == 2012
        assert result.month == 10
        assert result.day == 18
        assert result.hour == 14
        assert result.minute == 45

    def test_us_locale_with_am(self):
        result = _parse_ad_datetime("8/4/2025 1:16:48 PM")
        assert result.year == 2025
        assert result.month == 8
        assert result.day == 4

    def test_epoch_milliseconds_integer(self):
        """ConvertTo-Json may return raw epoch ms as integer."""
        result = _parse_ad_datetime(1350561951000)
        assert result.year == 2012
        assert result.month == 10

    def test_epoch_milliseconds_string(self):
        result = _parse_ad_datetime("1350561951000")
        assert result.year == 2012

    def test_ad_generalized_time(self):
        """AD sometimes returns generalized time format."""
        result = _parse_ad_datetime("20121018144551.0Z")
        assert result.year == 2012
        assert result.month == 10
        assert result.day == 18
