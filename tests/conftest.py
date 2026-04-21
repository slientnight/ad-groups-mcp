"""Shared fixtures for the AD Groups MCP test suite."""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Mock AD data (used by test_server_tools.py)
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
