"""Tests for the ACL Auditor module."""

from __future__ import annotations

import pytest

from ad_groups_mcp.acl_auditor import ACLAuditor, RISKY_PERMISSIONS


# ---------------------------------------------------------------------------
# 6.1 — ACLAuditor class construction
# ---------------------------------------------------------------------------

class TestACLAuditorInit:
    def test_stores_allow_list(self):
        auditor = ACLAuditor(allow_list=["Domain Admins", "Enterprise Admins"])
        assert auditor.allow_list == ["Domain Admins", "Enterprise Admins"]

    def test_empty_allow_list(self):
        auditor = ACLAuditor(allow_list=[])
        assert auditor.allow_list == []


# ---------------------------------------------------------------------------
# 6.3 — evaluate_ace (tested before audit_group_acl since it's a pure function)
# ---------------------------------------------------------------------------

class TestEvaluateAce:
    """Tests for ACLAuditor.evaluate_ace static method."""

    def test_risky_permission_not_in_allow_list_returns_violation(self):
        ace = {
            "IdentityReference": "DOMAIN\\SomeUser",
            "ActiveDirectoryRights": "GenericAll",
        }
        result = ACLAuditor.evaluate_ace(ace, ["Domain Admins"], group_dn="CN=TestGroup,DC=example,DC=com")
        assert result is not None
        assert result.principal == "DOMAIN\\SomeUser"
        assert result.permission == "GenericAll"
        assert result.group_dn == "CN=TestGroup,DC=example,DC=com"

    def test_risky_permission_in_allow_list_returns_none(self):
        ace = {
            "IdentityReference": "DOMAIN\\Domain Admins",
            "ActiveDirectoryRights": "WriteDacl",
        }
        result = ACLAuditor.evaluate_ace(ace, ["Domain Admins"], group_dn="CN=G,DC=x")
        assert result is None

    def test_risky_permission_full_match_in_allow_list(self):
        ace = {
            "IdentityReference": "DOMAIN\\Enterprise Admins",
            "ActiveDirectoryRights": "WriteOwner",
        }
        result = ACLAuditor.evaluate_ace(ace, ["DOMAIN\\Enterprise Admins"], group_dn="CN=G,DC=x")
        assert result is None

    def test_non_risky_permission_returns_none(self):
        ace = {
            "IdentityReference": "DOMAIN\\SomeUser",
            "ActiveDirectoryRights": "ReadProperty",
        }
        result = ACLAuditor.evaluate_ace(ace, [], group_dn="CN=G,DC=x")
        assert result is None

    def test_comma_separated_rights_with_risky(self):
        ace = {
            "IdentityReference": "DOMAIN\\Attacker",
            "ActiveDirectoryRights": "ReadProperty, WriteDacl, ListChildren",
        }
        result = ACLAuditor.evaluate_ace(ace, ["Domain Admins"], group_dn="CN=G,DC=x")
        assert result is not None
        assert result.permission == "WriteDacl"
        assert result.principal == "DOMAIN\\Attacker"

    def test_comma_separated_rights_all_non_risky(self):
        ace = {
            "IdentityReference": "DOMAIN\\User",
            "ActiveDirectoryRights": "ReadProperty, ListChildren",
        }
        result = ACLAuditor.evaluate_ace(ace, [], group_dn="CN=G,DC=x")
        assert result is None

    def test_empty_rights_returns_none(self):
        ace = {
            "IdentityReference": "DOMAIN\\User",
            "ActiveDirectoryRights": "",
        }
        result = ACLAuditor.evaluate_ace(ace, [], group_dn="CN=G,DC=x")
        assert result is None

    def test_missing_keys_returns_none(self):
        ace = {}
        result = ACLAuditor.evaluate_ace(ace, [], group_dn="CN=G,DC=x")
        assert result is None

    def test_multiple_risky_permissions_returns_first_alphabetically(self):
        ace = {
            "IdentityReference": "DOMAIN\\Attacker",
            "ActiveDirectoryRights": "WriteOwner, GenericAll, WriteDacl",
        }
        result = ACLAuditor.evaluate_ace(ace, [], group_dn="CN=G,DC=x")
        assert result is not None
        assert result.permission == "GenericAll"  # alphabetically first


# ---------------------------------------------------------------------------
# 6.2 — audit_group_acl (async, requires mocking run_ps_command)
# ---------------------------------------------------------------------------

class TestAuditGroupAcl:
    """Tests for ACLAuditor.audit_group_acl async method."""

    @pytest.mark.asyncio
    async def test_clean_result_when_all_allowed(self, monkeypatch):
        async def mock_run_ps(script, timeout=30):
            return [
                {"IdentityReference": "DOMAIN\\Domain Admins", "ActiveDirectoryRights": "GenericAll"},
                {"IdentityReference": "DOMAIN\\Enterprise Admins", "ActiveDirectoryRights": "WriteDacl"},
            ]

        monkeypatch.setattr("ad_groups_mcp.acl_auditor.run_ps_command", mock_run_ps)

        auditor = ACLAuditor(allow_list=["Domain Admins", "Enterprise Admins"])
        result = await auditor.audit_group_acl("CN=TestGroup,DC=example,DC=com")

        assert result.clean is True
        assert result.violations == []
        assert result.group_dn == "CN=TestGroup,DC=example,DC=com"

    @pytest.mark.asyncio
    async def test_violations_detected(self, monkeypatch):
        async def mock_run_ps(script, timeout=30):
            return [
                {"IdentityReference": "DOMAIN\\Domain Admins", "ActiveDirectoryRights": "GenericAll"},
                {"IdentityReference": "DOMAIN\\Rogue", "ActiveDirectoryRights": "WriteDacl"},
            ]

        monkeypatch.setattr("ad_groups_mcp.acl_auditor.run_ps_command", mock_run_ps)

        auditor = ACLAuditor(allow_list=["Domain Admins"])
        result = await auditor.audit_group_acl("CN=TestGroup,DC=example,DC=com")

        assert result.clean is False
        assert len(result.violations) == 1
        assert result.violations[0].principal == "DOMAIN\\Rogue"
        assert result.violations[0].permission == "WriteDacl"

    @pytest.mark.asyncio
    async def test_empty_aces_returns_clean(self, monkeypatch):
        async def mock_run_ps(script, timeout=30):
            return {}

        monkeypatch.setattr("ad_groups_mcp.acl_auditor.run_ps_command", mock_run_ps)

        auditor = ACLAuditor(allow_list=["Domain Admins"])
        result = await auditor.audit_group_acl("CN=Empty,DC=example,DC=com")

        assert result.clean is True
        assert result.violations == []

    @pytest.mark.asyncio
    async def test_single_ace_dict_normalised(self, monkeypatch):
        """PowerShell returns a single dict (not list) for one ACE."""

        async def mock_run_ps(script, timeout=30):
            return {"IdentityReference": "DOMAIN\\Attacker", "ActiveDirectoryRights": "WriteOwner"}

        monkeypatch.setattr("ad_groups_mcp.acl_auditor.run_ps_command", mock_run_ps)

        auditor = ACLAuditor(allow_list=["Domain Admins"])
        result = await auditor.audit_group_acl("CN=Single,DC=example,DC=com")

        assert result.clean is False
        assert len(result.violations) == 1
        assert result.violations[0].permission == "WriteOwner"

    @pytest.mark.asyncio
    async def test_identity_with_single_quotes_escaped(self, monkeypatch):
        captured_scripts: list[str] = []

        async def mock_run_ps(script, timeout=30):
            captured_scripts.append(script)
            return []

        monkeypatch.setattr("ad_groups_mcp.acl_auditor.run_ps_command", mock_run_ps)

        auditor = ACLAuditor(allow_list=[])
        await auditor.audit_group_acl("CN=O'Brien,DC=example,DC=com")

        assert "O''Brien" in captured_scripts[0]

    @pytest.mark.asyncio
    async def test_powershell_error_propagates(self, monkeypatch):
        async def mock_run_ps(script, timeout=30):
            raise RuntimeError("PowerShell error (exit 1): Group not found")

        monkeypatch.setattr("ad_groups_mcp.acl_auditor.run_ps_command", mock_run_ps)

        auditor = ACLAuditor(allow_list=[])
        with pytest.raises(RuntimeError, match="Group not found"):
            await auditor.audit_group_acl("CN=Missing,DC=example,DC=com")
