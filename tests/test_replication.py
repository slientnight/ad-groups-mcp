"""Tests for the replication module."""

from __future__ import annotations

import pytest

from ad_groups_mcp.replication import get_member_replication_metadata


class TestGetMemberReplicationMetadata:
    """Tests for get_member_replication_metadata async function."""

    @pytest.mark.asyncio
    async def test_returns_metadata_when_present(self, monkeypatch):
        async def mock_run_ps(script, timeout=30):
            return {
                "LastOriginatingChangeTime": "2024-06-15T10:30:00+00:00",
                "LastOriginatingChangeDirectoryServerIdentity": "CN=DC01,CN=Servers,DC=example,DC=com",
                "OriginatingChangePrincipal": "DOMAIN\\Admin",
            }

        monkeypatch.setattr("ad_groups_mcp.replication.run_ps_command", mock_run_ps)

        result = await get_member_replication_metadata("SEC_Finance")

        assert result is not None
        assert result.last_originating_change_dc == "CN=DC01,CN=Servers,DC=example,DC=com"
        assert result.originating_change_principal == "DOMAIN\\Admin"
        assert result.last_originating_change_time is not None

    @pytest.mark.asyncio
    async def test_returns_none_when_empty_dict(self, monkeypatch):
        async def mock_run_ps(script, timeout=30):
            return {}

        monkeypatch.setattr("ad_groups_mcp.replication.run_ps_command", mock_run_ps)

        result = await get_member_replication_metadata("SEC_NoChanges")
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_when_empty_list(self, monkeypatch):
        async def mock_run_ps(script, timeout=30):
            return []

        monkeypatch.setattr("ad_groups_mcp.replication.run_ps_command", mock_run_ps)

        result = await get_member_replication_metadata("SEC_NoChanges")
        assert result is None

    @pytest.mark.asyncio
    async def test_handles_list_result(self, monkeypatch):
        """PowerShell may return a list; we take the first entry."""

        async def mock_run_ps(script, timeout=30):
            return [
                {
                    "LastOriginatingChangeTime": "2024-06-15T10:30:00+00:00",
                    "LastOriginatingChangeDirectoryServerIdentity": "DC01",
                    "OriginatingChangePrincipal": "DOMAIN\\Admin",
                },
            ]

        monkeypatch.setattr("ad_groups_mcp.replication.run_ps_command", mock_run_ps)

        result = await get_member_replication_metadata("SEC_Finance")
        assert result is not None
        assert result.last_originating_change_dc == "DC01"

    @pytest.mark.asyncio
    async def test_handles_null_fields(self, monkeypatch):
        async def mock_run_ps(script, timeout=30):
            return {
                "LastOriginatingChangeTime": None,
                "LastOriginatingChangeDirectoryServerIdentity": None,
                "OriginatingChangePrincipal": None,
            }

        monkeypatch.setattr("ad_groups_mcp.replication.run_ps_command", mock_run_ps)

        result = await get_member_replication_metadata("SEC_NullFields")
        assert result is not None
        assert result.last_originating_change_time is None
        assert result.last_originating_change_dc is None
        assert result.originating_change_principal is None

    @pytest.mark.asyncio
    async def test_identity_with_single_quotes_escaped(self, monkeypatch):
        captured_scripts: list[str] = []

        async def mock_run_ps(script, timeout=30):
            captured_scripts.append(script)
            return {}

        monkeypatch.setattr("ad_groups_mcp.replication.run_ps_command", mock_run_ps)

        await get_member_replication_metadata("O'Brien Group")
        assert "O''Brien Group" in captured_scripts[0]

    @pytest.mark.asyncio
    async def test_script_uses_get_adreplicationattributemetadata(self, monkeypatch):
        captured_scripts: list[str] = []

        async def mock_run_ps(script, timeout=30):
            captured_scripts.append(script)
            return {}

        monkeypatch.setattr("ad_groups_mcp.replication.run_ps_command", mock_run_ps)

        await get_member_replication_metadata("TestGroup")
        assert "Get-ADReplicationAttributeMetadata" in captured_scripts[0]
        assert "-Properties member" in captured_scripts[0]

    @pytest.mark.asyncio
    async def test_powershell_error_propagates(self, monkeypatch):
        async def mock_run_ps(script, timeout=30):
            raise RuntimeError("PowerShell error (exit 1): Object not found")

        monkeypatch.setattr("ad_groups_mcp.replication.run_ps_command", mock_run_ps)

        with pytest.raises(RuntimeError, match="Object not found"):
            await get_member_replication_metadata("SEC_Missing")
