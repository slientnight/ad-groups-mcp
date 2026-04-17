"""Shared fixtures for the AD Groups MCP test suite."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ad_groups_mcp.models import GroupDetail, PolicyConfig, ReviewRecord
from ad_groups_mcp.policy_engine import PolicyEngine
from ad_groups_mcp.sqlite_store import SQLiteStore


# ---------------------------------------------------------------------------
# Mock AD data
# ---------------------------------------------------------------------------

MOCK_AD_GROUP_RAW = {
    "DistinguishedName": "CN=SEC_Finance,OU=Groups,DC=example,DC=com",
    "SamAccountName": "SEC_Finance",
    "GroupScope": "Global",
    "GroupCategory": "Security",
    "Description": "Finance security group",
    "ManagedBy": "CN=Admin,DC=example,DC=com",
    "whenCreated": "2024-01-01T00:00:00+00:00",
    "whenChanged": "2024-06-01T00:00:00+00:00",
    "Member": ["CN=User1,DC=example,DC=com", "CN=User2,DC=example,DC=com"],
}

MOCK_AD_GROUP_MINIMAL = {
    "DistinguishedName": "CN=BadGroup,OU=Groups,DC=example,DC=com",
    "SamAccountName": "BadGroup",
    "GroupScope": "DomainLocal",
    "GroupCategory": "Distribution",
    "Description": None,
    "ManagedBy": None,
    "whenCreated": "2024-03-01T00:00:00+00:00",
    "whenChanged": "2024-03-01T00:00:00+00:00",
    "Member": [],
}


def make_group_detail(
    sam_name: str = "SEC_TestGroup",
    description: str | None = "A test group",
    managed_by: str | None = "CN=Admin,DC=example,DC=com",
    member_count: int = 10,
) -> GroupDetail:
    """Helper to build a GroupDetail with sensible defaults."""
    return GroupDetail(
        distinguished_name=f"CN={sam_name},OU=Groups,DC=example,DC=com",
        sam_account_name=sam_name,
        group_scope="Global",
        group_category="Security",
        description=description,
        managed_by=managed_by,
        when_created=datetime(2024, 1, 1, tzinfo=timezone.utc),
        when_changed=datetime(2024, 6, 1, tzinfo=timezone.utc),
        member_count=member_count,
    )


# ---------------------------------------------------------------------------
# PolicyEngine with default config
# ---------------------------------------------------------------------------

@pytest.fixture
def default_policy_config() -> PolicyConfig:
    """Return the default PolicyConfig."""
    return PolicyConfig()


@pytest.fixture
def policy_engine(default_policy_config: PolicyConfig) -> PolicyEngine:
    """Return a PolicyEngine initialised with default config."""
    return PolicyEngine(default_policy_config)


# ---------------------------------------------------------------------------
# Temporary SQLite DB
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db_path(tmp_path) -> str:
    """Return a path to a temporary SQLite database file."""
    return str(tmp_path / "test_reviews.db")


@pytest.fixture
def sqlite_store(tmp_db_path: str) -> SQLiteStore:
    """Return an initialised SQLiteStore backed by a temporary DB."""
    s = SQLiteStore(tmp_db_path)
    s.initialize()
    return s
