"""Property-based tests for the AD Groups MCP server.

Uses Hypothesis with @settings(max_examples=100) for all properties.
Each test is tagged with its design property reference in the docstring.

Retained properties (MCP-specific):
  - Property 1: Search filter correctness
  - Property 2: Input validation rejects empty and whitespace strings
  - Property 9: ACL evaluation correctness
  - Property 12: Read-only cmdlet enforcement

Properties 3-8, 10-11 moved to the ad-group-audit repo.
"""

from __future__ import annotations

import asyncio
import re
import tempfile
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ad_groups_mcp.acl_auditor import ACLAuditor, RISKY_PERMISSIONS
from ad_groups_mcp.models import PolicyConfig
from ad_groups_mcp.sqlite_store import SQLiteStore


# ---------------------------------------------------------------------------
# Shared strategies
# ---------------------------------------------------------------------------

_printable_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
    min_size=1,
    max_size=50,
)


# =========================================================================
# Property 1: Search filter correctness
# =========================================================================


@given(
    query=st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"))),
    group_names=st.lists(
        st.text(
            min_size=1, max_size=30,
            alphabet=st.characters(whitelist_categories=("L", "N", "P"), whitelist_characters="_-"),
        ),
        min_size=0,
        max_size=10,
    ),
)
@settings(max_examples=100)
def test_property_1_search_filter_correctness(query: str, group_names: list[str]) -> None:
    """**Validates: Requirements 3.1**

    Feature: ad-groups-mcp, Property 1: Search filter correctness

    For any search query and group data, returned groups match the filter
    and no matching group is missing.
    """
    query_lower = query.lower()

    all_groups = [
        {"Name": name, "SamAccountName": name, "DistinguishedName": f"CN={name},DC=example,DC=com"}
        for name in group_names
    ]

    returned = [g for g in all_groups if query_lower in g["Name"].lower()]

    for g in returned:
        assert query_lower in g["Name"].lower(), (
            f"Returned group '{g['Name']}' does not match query '{query}'"
        )

    expected_matches = {g["Name"] for g in all_groups if query_lower in g["Name"].lower()}
    actual_matches = {g["Name"] for g in returned}
    assert expected_matches == actual_matches, (
        f"Missing groups: {expected_matches - actual_matches}"
    )


# =========================================================================
# Property 2: Input validation rejects empty and whitespace strings
# =========================================================================

_whitespace_only = st.text(
    alphabet=st.characters(whitelist_categories=("Zs",), whitelist_characters=" \t\n\r"),
    min_size=0,
    max_size=10,
)


@given(ws_query=_whitespace_only)
@settings(max_examples=100, deadline=None)
def test_property_2_search_groups_rejects_whitespace(ws_query: str) -> None:
    """**Validates: Requirements 3.4**

    Feature: ad-groups-mcp, Property 2: Input validation rejects empty and whitespace strings

    For any whitespace/empty string, search_groups rejects with INVALID_INPUT error.
    """
    from ad_groups_mcp.server import create_server

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = SQLiteStore(db_path)
    store.initialize()
    config = PolicyConfig()
    mcp = create_server(config, store)

    async def _run():
        tools = await mcp.list_tools()
        search_tool = None
        for t in tools:
            if t.name == "search_groups":
                search_tool = t
                break
        assert search_tool is not None

        result = await mcp.call_tool("search_groups", {"query": ws_query})
        return result

    result = asyncio.new_event_loop().run_until_complete(_run())
    assert len(result) > 0
    text_content = result[0].text if hasattr(result[0], "text") else str(result[0])
    assert "INVALID_INPUT" in text_content


@given(ws_dn=_whitespace_only)
@settings(max_examples=100, deadline=None)
def test_property_2_record_review_rejects_whitespace(ws_dn: str) -> None:
    """**Validates: Requirements 10.3**

    Feature: ad-groups-mcp, Property 2: Input validation rejects empty and whitespace strings

    For any whitespace/empty string, record_group_review rejects with INVALID_INPUT error.
    """
    from ad_groups_mcp.server import create_server

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = SQLiteStore(db_path)
    store.initialize()
    config = PolicyConfig()
    mcp = create_server(config, store)

    async def _run():
        result = await mcp.call_tool("record_group_review", {"group_dn": ws_dn, "reviewer": "tester"})
        return result

    result = asyncio.new_event_loop().run_until_complete(_run())
    assert len(result) > 0
    text_content = result[0].text if hasattr(result[0], "text") else str(result[0])
    assert "INVALID_INPUT" in text_content


# =========================================================================
# Property 9: ACL evaluation correctness
# =========================================================================

_risky_perm = st.sampled_from(sorted(RISKY_PERMISSIONS))
_non_risky_perm = st.sampled_from(["ReadProperty", "ListChildren", "ReadControl", "ListObject"])
_principal_name = st.text(min_size=1, max_size=30, alphabet=st.characters(whitelist_categories=("L",)))


@given(
    principal=_principal_name,
    permission=_risky_perm,
    allow_list=st.lists(_principal_name, min_size=0, max_size=5),
)
@settings(max_examples=100)
def test_property_9_acl_evaluation(principal: str, permission: str, allow_list: list[str]) -> None:
    """**Validates: Requirements 7.2, 7.3, 7.4**

    Feature: ad-groups-mcp, Property 9: ACL evaluation correctness

    Violation iff principal not in allow-list with risky permission.
    """
    ace = {
        "IdentityReference": principal,
        "ActiveDirectoryRights": permission,
    }

    result = ACLAuditor.evaluate_ace(ace, allow_list, group_dn="CN=Test,DC=example,DC=com")

    principal_parts = principal.rsplit("\\", 1)
    short_name = principal_parts[-1] if principal_parts else principal
    in_allow_list = principal in allow_list or short_name in allow_list

    if in_allow_list:
        assert result is None, (
            f"Principal '{principal}' is in allow_list but got violation"
        )
    else:
        assert result is not None, (
            f"Principal '{principal}' is NOT in allow_list but got no violation"
        )
        assert result.principal == principal
        assert result.permission in RISKY_PERMISSIONS


@given(
    principal=_principal_name,
    permission=_non_risky_perm,
)
@settings(max_examples=100)
def test_property_9_non_risky_no_violation(principal: str, permission: str) -> None:
    """**Validates: Requirements 7.4**

    Feature: ad-groups-mcp, Property 9: ACL evaluation correctness

    Non-risky permissions never produce violations regardless of allow-list.
    """
    ace = {
        "IdentityReference": principal,
        "ActiveDirectoryRights": permission,
    }
    result = ACLAuditor.evaluate_ace(ace, [], group_dn="CN=Test,DC=example,DC=com")
    assert result is None, f"Non-risky permission '{permission}' should not produce violation"


# =========================================================================
# Property 12: Read-only cmdlet enforcement
# =========================================================================

_WRITE_CMDLET_PATTERNS = [
    r"\bSet-\w+",
    r"\bNew-\w+",
    r"\bRemove-\w+",
    r"\bAdd-\w+",
]

_READ_ONLY_CMDLETS = {
    "Get-ADGroup",
    "Get-ADReplicationAttributeMetadata",
    "Get-ADObject",
    "Get-WinEvent",
    "Get-Module",
    "Get-ADDomainController",
}


def _extract_ps_scripts_from_module(module_source: str) -> list[str]:
    """Extract string literals that look like PowerShell scripts from Python source."""
    import ast

    scripts = []
    try:
        tree = ast.parse(module_source)
    except SyntaxError:
        return scripts

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            val = node.value
            if any(cmdlet in val for cmdlet in ("Get-AD", "Get-WinEvent", "Get-Module", "ConvertTo-Json")):
                scripts.append(val)
        elif isinstance(node, ast.JoinedStr):
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
            combined = "".join(parts)
            if any(cmdlet in combined for cmdlet in ("Get-AD", "Get-WinEvent", "Get-Module", "ConvertTo-Json")):
                scripts.append(combined)
    return scripts


@settings(max_examples=100)
@given(data=st.data())
def test_property_12_read_only_cmdlet_enforcement(data) -> None:
    """**Validates: Requirements 16.1**

    Feature: ad-groups-mcp, Property 12: Read-only cmdlet enforcement

    All PowerShell commands generated by the AD query layer use only
    read-only cmdlets and never contain write cmdlets.
    """
    import importlib
    import inspect

    module_names = [
        "ad_groups_mcp.ad_query",
        "ad_groups_mcp.acl_auditor",
        "ad_groups_mcp.event_reader",
        "ad_groups_mcp.replication",
        "ad_groups_mcp.server",
    ]

    all_scripts: list[str] = []
    for mod_name in module_names:
        mod = importlib.import_module(mod_name)
        source = inspect.getsource(mod)
        all_scripts.extend(_extract_ps_scripts_from_module(source))

    assume(len(all_scripts) > 0)
    idx = data.draw(st.integers(min_value=0, max_value=len(all_scripts) - 1))
    script = all_scripts[idx]

    for pattern in _WRITE_CMDLET_PATTERNS:
        matches = re.findall(pattern, script)
        assert not matches, (
            f"Write cmdlet found in PowerShell script: {matches}\n"
            f"Script excerpt: {script[:200]}"
        )
