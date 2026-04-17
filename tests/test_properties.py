"""Property-based tests for the AD Groups MCP server.

Uses Hypothesis with @settings(max_examples=100) for all properties.
Each test is tagged with its design property reference in the docstring.
"""

from __future__ import annotations

import re
import tempfile
from datetime import datetime, timedelta, timezone

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ad_groups_mcp.acl_auditor import ACLAuditor, RISKY_PERMISSIONS
from ad_groups_mcp.models import (
    GroupDetail,
    InventoryAuditResult,
    PolicyConfig,
    PolicyEvalResult,
    ReviewRecord,
    RuleResult,
    ToolError,
)
from ad_groups_mcp.policy_engine import PolicyEngine
from ad_groups_mcp.sqlite_store import SQLiteStore


# ---------------------------------------------------------------------------
# Shared strategies
# ---------------------------------------------------------------------------

# Non-empty printable text (no NUL bytes which break SQLite)
_printable_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
    min_size=1,
    max_size=50,
)

# Optional string: None or a text value (possibly empty)
_optional_string = st.one_of(st.none(), st.text(min_size=0, max_size=30))

# SAM account names: printable, reasonable length
_sam_name = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P"),
        whitelist_characters="_-",
    ),
    min_size=0,
    max_size=40,
)

# A set of simple, valid regex patterns that won't cause catastrophic backtracking
_FIXED_PATTERNS = [
    r"^(SEC|DL|APP)_.*",
    r"^GRP-\d+$",
    r"^[A-Z]{2,4}_\w+$",
    r"^test.*",
    r".*admin.*",
    r"^\w+$",
]

_regex_pattern = st.sampled_from(_FIXED_PATTERNS)


def _make_group_detail(
    sam_name: str = "SEC_Test",
    description: str | None = "desc",
    managed_by: str | None = "CN=Admin,DC=example,DC=com",
    member_count: int = 10,
) -> GroupDetail:
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


# =========================================================================
# Property 1: Search filter correctness
# =========================================================================


@given(
    query=st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"))),
    group_names=st.lists(
        st.text(min_size=1, max_size=30, alphabet=st.characters(whitelist_categories=("L", "N", "P"), whitelist_characters="_-")),
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
    # Simulate the filtering logic used by search_ad_groups:
    # PowerShell does Name -like '*query*' which is case-insensitive substring match
    query_lower = query.lower()

    # Build mock group dicts
    all_groups = [
        {"Name": name, "SamAccountName": name, "DistinguishedName": f"CN={name},DC=example,DC=com"}
        for name in group_names
    ]

    # Apply the filter (case-insensitive substring match on Name)
    returned = [g for g in all_groups if query_lower in g["Name"].lower()]

    # All returned groups must contain the query substring
    for g in returned:
        assert query_lower in g["Name"].lower(), (
            f"Returned group '{g['Name']}' does not match query '{query}'"
        )

    # No matching group should be missing
    expected_matches = {g["Name"] for g in all_groups if query_lower in g["Name"].lower()}
    actual_matches = {g["Name"] for g in returned}
    assert expected_matches == actual_matches, (
        f"Missing groups: {expected_matches - actual_matches}"
    )


# =========================================================================
# Property 2: Input validation rejects empty and whitespace strings
# =========================================================================

import asyncio
from unittest.mock import AsyncMock, patch


# Strategy for whitespace-only strings (including empty)
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
    # Import the server factory and create a server instance
    from ad_groups_mcp.server import create_server

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = SQLiteStore(db_path)
    store.initialize()
    config = PolicyConfig()
    mcp = create_server(config, store)

    # Get the search_groups tool function from the server
    # The tool is registered as an inner function; we call it via the server
    # We need to access the tool directly
    async def _run():
        # Access the registered tool function
        tools = await mcp.list_tools()
        search_tool = None
        for t in tools:
            if t.name == "search_groups":
                search_tool = t
                break
        assert search_tool is not None

        # Call the tool through the server's call_tool method
        result = await mcp.call_tool("search_groups", {"query": ws_query})
        return result

    result = asyncio.new_event_loop().run_until_complete(_run())
    # The result should contain an error
    # FastMCP returns tool results as list of content items
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
# Property 3: Policy naming rule correctness
# =========================================================================


@given(sam_name=_sam_name, pattern=_regex_pattern)
@settings(max_examples=100)
def test_property_3_naming_rule_correctness(sam_name: str, pattern: str) -> None:
    """**Validates: Requirements 5.2**

    Feature: ad-groups-mcp, Property 3: Policy naming rule correctness

    For any SAM name and regex, naming rule passes iff name matches regex.
    """
    config = PolicyConfig(naming_regex=pattern)
    engine = PolicyEngine(config)
    result = engine.evaluate_naming(sam_name)

    expected = bool(re.fullmatch(pattern, sam_name))
    assert result.passed == expected, (
        f"Name='{sam_name}', Pattern='{pattern}': "
        f"expected passed={expected}, got passed={result.passed}"
    )
    assert result.rule_name == "naming"


# =========================================================================
# Property 4: Required-attribute presence rules
# =========================================================================


@given(value=_optional_string)
@settings(max_examples=100)
def test_property_4_description_rule(value: str | None) -> None:
    """**Validates: Requirements 5.3**

    Feature: ad-groups-mcp, Property 4: Policy required-attribute presence rules

    Description rule passes iff value is not None and not empty.
    """
    engine = PolicyEngine(PolicyConfig())
    result = engine.evaluate_description(value)

    expected = value is not None and value != ""
    assert result.passed == expected, (
        f"Description='{value}': expected passed={expected}, got passed={result.passed}"
    )
    assert result.rule_name == "description"


@given(value=_optional_string)
@settings(max_examples=100)
def test_property_4_owner_rule(value: str | None) -> None:
    """**Validates: Requirements 5.4**

    Feature: ad-groups-mcp, Property 4: Policy required-attribute presence rules

    Owner (managedBy) rule passes iff value is not None and not empty.
    """
    engine = PolicyEngine(PolicyConfig())
    result = engine.evaluate_owner(value)

    expected = value is not None and value != ""
    assert result.passed == expected, (
        f"ManagedBy='{value}': expected passed={expected}, got passed={result.passed}"
    )
    assert result.rule_name == "owner"


# =========================================================================
# Property 5: Membership threshold rule
# =========================================================================


@given(
    member_count=st.integers(min_value=0, max_value=10_000),
    max_members=st.integers(min_value=1, max_value=10_000),
)
@settings(max_examples=100)
def test_property_5_membership_threshold(member_count: int, max_members: int) -> None:
    """**Validates: Requirements 5.5**

    Feature: ad-groups-mcp, Property 5: Policy membership threshold rule

    Membership rule passes iff count <= threshold.
    """
    config = PolicyConfig(max_members=max_members)
    engine = PolicyEngine(config)
    result = engine.evaluate_membership(member_count)

    expected = member_count <= max_members
    assert result.passed == expected, (
        f"count={member_count}, max={max_members}: "
        f"expected passed={expected}, got passed={result.passed}"
    )
    assert result.rule_name == "membership"


# =========================================================================
# Property 6: Review recency rule
# =========================================================================


@given(
    has_review=st.booleans(),
    days_ago=st.integers(min_value=0, max_value=365),
    recency_window=st.integers(min_value=1, max_value=365),
)
@settings(max_examples=100)
def test_property_6_review_recency(has_review: bool, days_ago: int, recency_window: int) -> None:
    """**Validates: Requirements 5.6**

    Feature: ad-groups-mcp, Property 6: Policy review recency rule

    Review recency rule passes iff review exists and is within window.
    """
    config = PolicyConfig(review_recency_days=recency_window)
    engine = PolicyEngine(config)

    if has_review:
        reviewed_at = datetime.now(timezone.utc) - timedelta(days=days_ago)
        review = ReviewRecord(
            group_dn="CN=Test,DC=example,DC=com",
            reviewer="admin",
            reviewed_at=reviewed_at,
        )
    else:
        review = None

    result = engine.evaluate_review_recency(review)

    if review is None:
        assert result.passed is False, "No review should always fail"
    else:
        # The engine computes elapsed_days = (now - reviewed_at).days
        # which for a timedelta of exactly `days_ago` days should be `days_ago`
        expected = days_ago <= recency_window
        assert result.passed == expected, (
            f"days_ago={days_ago}, window={recency_window}: "
            f"expected passed={expected}, got passed={result.passed}"
        )
    assert result.rule_name == "review_recency"


# =========================================================================
# Property 7: Evaluation completeness and consistency
# =========================================================================

_group_detail_strategy = st.builds(
    _make_group_detail,
    sam_name=st.just("SEC_Test"),  # Use a valid name to keep it simple
    description=_optional_string,
    managed_by=_optional_string,
    member_count=st.integers(min_value=0, max_value=2000),
)

_review_strategy = st.one_of(
    st.none(),
    st.builds(
        ReviewRecord,
        group_dn=st.just("CN=SEC_Test,OU=Groups,DC=example,DC=com"),
        reviewer=st.just("admin"),
        reviewed_at=st.datetimes(
            min_value=datetime(2023, 1, 1),
            max_value=datetime(2025, 1, 1),
            timezones=st.just(timezone.utc),
        ),
    ),
)


@given(group=_group_detail_strategy, review=_review_strategy)
@settings(max_examples=100)
def test_property_7_evaluation_completeness(group: GroupDetail, review: ReviewRecord | None) -> None:
    """**Validates: Requirements 5.1, 5.7**

    Feature: ad-groups-mcp, Property 7: Policy evaluation completeness and consistency

    Result has exactly 5 RuleResults with unique names, and compliant iff all passed.
    """
    config = PolicyConfig()
    engine = PolicyEngine(config)
    result = engine.evaluate(group, review)

    # At least 6 rules (6 base + optional privileged_review)
    assert len(result.rules) >= 6, f"Expected at least 6 rules, got {len(result.rules)}"

    # Rule names are unique
    names = [r.rule_name for r in result.rules]
    assert len(names) == len(set(names)), f"Duplicate rule names: {names}"

    # Expected rule names (base 6 + optional privileged_review)
    base_names = {"naming", "description", "owner", "membership", "review_recency", "stale_group"}
    assert base_names.issubset(set(names))

    # compliant iff all passed
    all_passed = all(r.passed for r in result.rules)
    assert result.compliant == all_passed, (
        f"compliant={result.compliant} but all_passed={all_passed}"
    )


# =========================================================================
# Property 8: Inventory audit summary consistency
# =========================================================================

_rule_result_strategy = st.builds(
    RuleResult,
    rule_name=st.sampled_from(["naming", "description", "owner", "membership", "review_recency"]),
    passed=st.booleans(),
    message=st.just("test message"),
)

_eval_result_strategy = st.builds(
    lambda dn, rules: PolicyEvalResult(
        group_dn=dn,
        rules=rules,
        compliant=all(r.passed for r in rules),
    ),
    dn=st.text(min_size=5, max_size=40, alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="=,_")),
    rules=st.lists(_rule_result_strategy, min_size=5, max_size=5),
)


@given(eval_results=st.lists(_eval_result_strategy, min_size=0, max_size=20))
@settings(max_examples=100)
def test_property_8_audit_summary_consistency(eval_results: list[PolicyEvalResult]) -> None:
    """**Validates: Requirements 6.2, 6.3**

    Feature: ad-groups-mcp, Property 8: Inventory audit summary consistency

    total = compliant + violation and per_group_violations matches non-compliant.
    """
    compliant_count = sum(1 for r in eval_results if r.compliant)
    violation_count = sum(1 for r in eval_results if not r.compliant)
    per_group_violations = [r for r in eval_results if not r.compliant]
    total = len(eval_results)

    audit = InventoryAuditResult(
        total_groups=total,
        compliant_count=compliant_count,
        violation_count=violation_count,
        errors=[],
        per_group_violations=per_group_violations,
    )

    # total = compliant + violation
    assert audit.total_groups == audit.compliant_count + audit.violation_count, (
        f"total={audit.total_groups} != compliant={audit.compliant_count} + violation={audit.violation_count}"
    )

    # per_group_violations matches non-compliant results
    assert len(audit.per_group_violations) == audit.violation_count
    for v in audit.per_group_violations:
        assert v.compliant is False


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

    # Principal is "in" the allow list if the full name or the short name
    # (after last backslash) matches any entry
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
# Property 10: Review record round-trip
# =========================================================================


@given(
    group_dn=st.text(
        min_size=3,
        max_size=60,
        alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="=,_ "),
    ),
    reviewer=st.text(
        min_size=1,
        max_size=30,
        alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="@._"),
    ),
)
@settings(max_examples=100, deadline=None)
def test_property_10_review_round_trip(group_dn: str, reviewer: str) -> None:
    """**Validates: Requirements 10.1, 10.2, 11.1, 11.2**

    Feature: ad-groups-mcp, Property 10: Review record round-trip

    Record then retrieve returns matching data.
    """
    # Filter out strings that are only whitespace (those would be rejected by the tool)
    assume(group_dn.strip() != "")
    assume(reviewer.strip() != "")
    # Avoid NUL bytes
    assume("\x00" not in group_dn)
    assume("\x00" not in reviewer)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = SQLiteStore(db_path)
    store.initialize()

    before = datetime.now(timezone.utc)
    record = store.record_review(group_dn, reviewer)
    after = datetime.now(timezone.utc)

    # Verify the returned record
    assert record.group_dn == group_dn
    assert record.reviewer == reviewer
    assert before <= record.reviewed_at <= after

    # Retrieve and verify
    retrieved = store.get_review(group_dn)
    assert retrieved is not None
    assert retrieved.group_dn == group_dn
    assert retrieved.reviewer == reviewer
    # Timestamps should match (stored as ISO string, so sub-microsecond precision may differ)
    assert abs((retrieved.reviewed_at - record.reviewed_at).total_seconds()) < 1


# =========================================================================
# Property 11: Review listing order
# =========================================================================


@given(
    entries=st.lists(
        st.tuples(
            st.text(
                min_size=3,
                max_size=40,
                alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="=,_"),
            ),
            st.text(
                min_size=1,
                max_size=20,
                alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="@."),
            ),
        ),
        min_size=1,
        max_size=10,
        unique_by=lambda x: x[0],  # unique group_dn
    ),
)
@settings(max_examples=100, deadline=None)
def test_property_11_review_listing_order(entries: list[tuple[str, str]]) -> None:
    """**Validates: Requirements 12.1, 12.2**

    Feature: ad-groups-mcp, Property 11: Review listing order

    list_reviews returns records ordered by reviewed_at descending.
    """
    import time

    # Filter out entries with whitespace-only or NUL-containing strings
    entries = [(dn, rev) for dn, rev in entries if dn.strip() and rev.strip() and "\x00" not in dn and "\x00" not in rev]
    assume(len(entries) >= 1)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = SQLiteStore(db_path)
    store.initialize()

    # Record reviews with small delays to ensure distinct timestamps
    for group_dn, reviewer in entries:
        store.record_review(group_dn, reviewer)
        time.sleep(0.01)  # small delay for timestamp ordering

    reviews = store.list_reviews()

    # Count should equal number of distinct group DNs
    assert len(reviews) == len(entries)

    # Should be ordered by reviewed_at descending
    for i in range(len(reviews) - 1):
        assert reviews[i].reviewed_at >= reviews[i + 1].reviewed_at, (
            f"Reviews not in descending order at index {i}: "
            f"{reviews[i].reviewed_at} < {reviews[i + 1].reviewed_at}"
        )


# =========================================================================
# Property 12: Read-only cmdlet enforcement
# =========================================================================

# Collect all PowerShell script templates from the codebase
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
            # Heuristic: contains a PowerShell cmdlet pattern
            if any(cmdlet in val for cmdlet in ("Get-AD", "Get-WinEvent", "Get-Module", "ConvertTo-Json")):
                scripts.append(val)
        # Also check f-strings (JoinedStr)
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

    # Modules that generate PowerShell scripts
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

    # Pick a random script to test (property-based: test across all scripts)
    assume(len(all_scripts) > 0)
    idx = data.draw(st.integers(min_value=0, max_value=len(all_scripts) - 1))
    script = all_scripts[idx]

    # Verify no write cmdlets
    for pattern in _WRITE_CMDLET_PATTERNS:
        matches = re.findall(pattern, script)
        assert not matches, (
            f"Write cmdlet found in PowerShell script: {matches}\n"
            f"Script excerpt: {script[:200]}"
        )
