"""Tests for the event_reader module."""

from __future__ import annotations

import pytest

from ad_groups_mcp.event_reader import get_group_change_events, _GROUP_CHANGE_EVENT_IDS


class TestGetGroupChangeEvents:
    """Tests for get_group_change_events async function."""

    @pytest.mark.asyncio
    async def test_returns_parsed_events(self, monkeypatch):
        async def mock_run_ps(script, timeout=30):
            return [
                {
                    "EventId": 4728,
                    "Timestamp": "2024-06-01T12:00:00+00:00",
                    "Account": "DOMAIN\\Admin",
                    "Member": "CN=JDoe,DC=example,DC=com",
                    "TargetGroup": "SEC_Finance",
                },
                {
                    "EventId": 4729,
                    "Timestamp": "2024-06-01T13:00:00+00:00",
                    "Account": "DOMAIN\\Admin",
                    "Member": "CN=JSmith,DC=example,DC=com",
                    "TargetGroup": "SEC_Finance",
                },
            ]

        monkeypatch.setattr("ad_groups_mcp.event_reader.run_ps_command", mock_run_ps)

        events = await get_group_change_events("SEC_Finance")

        assert len(events) == 2
        assert events[0].event_id == 4728
        assert events[0].account == "DOMAIN\\Admin"
        assert events[0].member == "CN=JDoe,DC=example,DC=com"
        assert events[0].target_group == "SEC_Finance"
        assert events[1].event_id == 4729

    @pytest.mark.asyncio
    async def test_empty_result_returns_empty_list(self, monkeypatch):
        async def mock_run_ps(script, timeout=30):
            return []

        monkeypatch.setattr("ad_groups_mcp.event_reader.run_ps_command", mock_run_ps)

        events = await get_group_change_events("SEC_Empty")
        assert events == []

    @pytest.mark.asyncio
    async def test_single_event_dict_normalised(self, monkeypatch):
        """PowerShell returns a single dict when only one event matches."""

        async def mock_run_ps(script, timeout=30):
            return {
                "EventId": 4732,
                "Timestamp": "2024-06-01T14:00:00+00:00",
                "Account": "DOMAIN\\Admin",
                "Member": "CN=User1,DC=example,DC=com",
                "TargetGroup": "DL_HR",
            }

        monkeypatch.setattr("ad_groups_mcp.event_reader.run_ps_command", mock_run_ps)

        events = await get_group_change_events("DL_HR")
        assert len(events) == 1
        assert events[0].event_id == 4732

    @pytest.mark.asyncio
    async def test_time_range_included_in_script(self, monkeypatch):
        captured_scripts: list[str] = []

        async def mock_run_ps(script, timeout=30):
            captured_scripts.append(script)
            return []

        monkeypatch.setattr("ad_groups_mcp.event_reader.run_ps_command", mock_run_ps)

        await get_group_change_events(
            "SEC_Test",
            start_time="2024-01-01T00:00:00Z",
            end_time="2024-12-31T23:59:59Z",
        )

        assert "2024-01-01T00:00:00Z" in captured_scripts[0]
        assert "2024-12-31T23:59:59Z" in captured_scripts[0]

    @pytest.mark.asyncio
    async def test_log_unavailable_raises_runtime_error(self, monkeypatch):
        async def mock_run_ps(script, timeout=30):
            raise RuntimeError("Security event log is unavailable on this host")

        monkeypatch.setattr("ad_groups_mcp.event_reader.run_ps_command", mock_run_ps)

        with pytest.raises(RuntimeError, match="unavailable"):
            await get_group_change_events("SEC_Test")

    @pytest.mark.asyncio
    async def test_access_denied_raises_runtime_error(self, monkeypatch):
        async def mock_run_ps(script, timeout=30):
            raise RuntimeError("Access denied reading Security event log")

        monkeypatch.setattr("ad_groups_mcp.event_reader.run_ps_command", mock_run_ps)

        with pytest.raises(RuntimeError, match="unavailable or access is denied"):
            await get_group_change_events("SEC_Test")

    @pytest.mark.asyncio
    async def test_identity_with_single_quotes_escaped(self, monkeypatch):
        captured_scripts: list[str] = []

        async def mock_run_ps(script, timeout=30):
            captured_scripts.append(script)
            return []

        monkeypatch.setattr("ad_groups_mcp.event_reader.run_ps_command", mock_run_ps)

        await get_group_change_events("O'Brien Group")
        assert "O''Brien Group" in captured_scripts[0]

    @pytest.mark.asyncio
    async def test_event_ids_constant(self):
        assert _GROUP_CHANGE_EVENT_IDS == (4728, 4729, 4732, 4733, 4756, 4757)

    @pytest.mark.asyncio
    async def test_script_uses_get_winevent(self, monkeypatch):
        captured_scripts: list[str] = []

        async def mock_run_ps(script, timeout=30):
            captured_scripts.append(script)
            return []

        monkeypatch.setattr("ad_groups_mcp.event_reader.run_ps_command", mock_run_ps)

        await get_group_change_events("TestGroup")
        assert "Get-WinEvent" in captured_scripts[0]
        assert "-LogName Security" in captured_scripts[0]
