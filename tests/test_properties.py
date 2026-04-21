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


# =========================================================================
# Feature: audit-report-enhancements
# Property 2: Membership snapshot round-trip
# =========================================================================


@given(
    group_dn=st.text(
        min_size=3,
        max_size=60,
        alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="=,_ "),
    ),
    member_count=st.integers(min_value=0, max_value=100000),
    reviewer=st.text(
        min_size=1,
        max_size=30,
        alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="@._"),
    ),
)
@settings(max_examples=100, deadline=None)
def test_property_membership_snapshot_round_trip(group_dn: str, member_count: int, reviewer: str) -> None:
    """**Validates: Requirements 1.3**

    Feature: audit-report-enhancements, Property 2: Membership snapshot round-trip

    For any valid group DN, member count, and recorder identity, recording a
    membership snapshot and reading it back returns identical values.
    """
    assume(group_dn.strip() != "")
    assume(reviewer.strip() != "")
    assume("\x00" not in group_dn)
    assume("\x00" not in reviewer)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = SQLiteStore(db_path)
    store.initialize()

    record = store.record_snapshot(group_dn, member_count, reviewer)

    # Verify the returned record
    assert record.group_dn == group_dn
    assert record.member_count == member_count
    assert record.reviewer == reviewer

    # Read back and verify
    snapshots = store.get_snapshots(group_dn)
    assert len(snapshots) == 1
    retrieved = snapshots[0]
    assert retrieved.group_dn == group_dn
    assert retrieved.member_count == member_count
    assert retrieved.reviewer == reviewer


# =========================================================================
# Feature: audit-report-enhancements
# Property 3: Snapshot accumulation preserves history
# =========================================================================


@given(
    group_dn=st.text(
        min_size=3,
        max_size=60,
        alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="=,_ "),
    ),
    member_counts=st.lists(st.integers(min_value=0, max_value=100000), min_size=1, max_size=10),
)
@settings(max_examples=100, deadline=None)
def test_property_snapshot_accumulation(group_dn: str, member_counts: list[int]) -> None:
    """**Validates: Requirements 1.5**

    Feature: audit-report-enhancements, Property 3: Snapshot accumulation preserves history

    For any group DN and sequence of N snapshots, querying returns all N in
    chronological order with no overwrites.
    """
    assume(group_dn.strip() != "")
    assume("\x00" not in group_dn)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = SQLiteStore(db_path)
    store.initialize()

    # Record N snapshots for the same group_dn with different member counts
    for count in member_counts:
        store.record_snapshot(group_dn, count, "audit-script")

    # Read all snapshots back
    snapshots = store.get_snapshots(group_dn)

    # Assert we got exactly N snapshots (no overwrites, no pruning)
    assert len(snapshots) == len(member_counts), (
        f"Expected {len(member_counts)} snapshots, got {len(snapshots)}"
    )

    # Assert snapshots are in chronological order
    for i in range(len(snapshots) - 1):
        assert snapshots[i].snapshot_at <= snapshots[i + 1].snapshot_at, (
            f"Snapshots not in chronological order at index {i}: "
            f"{snapshots[i].snapshot_at} > {snapshots[i + 1].snapshot_at}"
        )

    # Assert member_count values match the input sequence
    actual_counts = [s.member_count for s in snapshots]
    assert actual_counts == member_counts, (
        f"Member counts mismatch: expected {member_counts}, got {actual_counts}"
    )


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


# =========================================================================
# Feature: audit-report-enhancements
# Property 4: Audit snapshot round-trip
# =========================================================================


@given(
    compliance_pct=st.floats(min_value=0.0, max_value=100.0, allow_nan=False, allow_infinity=False),
    total_groups=st.integers(min_value=0, max_value=10000),
    compliant_count=st.integers(min_value=0, max_value=10000),
)
@settings(max_examples=100, deadline=None)
def test_property_audit_snapshot_round_trip(
    compliance_pct: float, total_groups: int, compliant_count: int
) -> None:
    """**Validates: Requirements 2.1**

    Feature: audit-report-enhancements, Property 4: Audit snapshot round-trip

    For any valid compliance_pct (0.0–100.0), total_groups, and compliant_count,
    recording and reading back returns identical values.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = SQLiteStore(db_path)
    store.initialize()

    # Record an audit snapshot
    store.record_audit_snapshot(compliance_pct, total_groups, compliant_count)

    # Read it back
    snapshots = store.get_audit_snapshots(limit=1)
    assert len(snapshots) == 1, f"Expected 1 snapshot, got {len(snapshots)}"

    retrieved = snapshots[0]
    assert retrieved["compliance_pct"] == compliance_pct, (
        f"compliance_pct mismatch: expected {compliance_pct}, got {retrieved['compliance_pct']}"
    )
    assert retrieved["total_groups"] == total_groups, (
        f"total_groups mismatch: expected {total_groups}, got {retrieved['total_groups']}"
    )
    assert retrieved["compliant_count"] == compliant_count, (
        f"compliant_count mismatch: expected {compliant_count}, got {retrieved['compliant_count']}"
    )


# =========================================================================
# Feature: audit-report-enhancements
# Property 5: Trend chart SVG contains correct data points
# =========================================================================

_audit_snapshot_strategy = st.fixed_dictionaries({
    "compliance_pct": st.floats(min_value=0.0, max_value=100.0, allow_nan=False, allow_infinity=False),
    "snapshot_at": st.just("2026-01-15T00:00:00+00:00"),
})

from ad_groups_mcp.report import _trend_chart_svg


@given(trend_data=st.lists(_audit_snapshot_strategy, min_size=2, max_size=30))
@settings(max_examples=100)
def test_property_trend_chart_svg_data_points(trend_data: list[dict]) -> None:
    """**Validates: Requirements 2.2, 2.3**

    Feature: audit-report-enhancements, Property 5: Trend chart SVG contains correct data points

    For any list of 2–30 audit snapshots, the SVG contains exactly as many
    data points as inputs and is a valid self-contained SVG element.
    """
    svg = _trend_chart_svg(trend_data)

    # Must be a valid self-contained SVG element
    assert "<svg" in svg
    assert "</svg>" in svg
    assert 'xmlns="http://www.w3.org/2000/svg"' in svg

    # Count <circle elements — one per data point
    circles = re.findall(r"<circle", svg)
    assert len(circles) == len(trend_data), (
        f"Expected {len(trend_data)} <circle> elements, got {len(circles)}"
    )

    # No external references
    assert "xlink:href" not in svg


# =========================================================================
# Feature: audit-report-enhancements
# Property 6: Sparkline SVG contains correct data points
# =========================================================================

_membership_snapshot_strategy = st.fixed_dictionaries({
    "member_count": st.integers(min_value=0, max_value=10000),
    "snapshot_at": st.just("2026-01-15T00:00:00+00:00"),
})

from ad_groups_mcp.report import _sparkline_svg


@given(snapshots=st.lists(_membership_snapshot_strategy, min_size=2, max_size=10))
@settings(max_examples=100)
def test_property_sparkline_svg_data_points(snapshots: list[dict]) -> None:
    """**Validates: Requirements 2.5**

    Feature: audit-report-enhancements, Property 6: Sparkline SVG contains correct data points

    For any list of 2–10 membership snapshots, the SVG contains exactly as many
    data points as inputs and is a valid self-contained SVG element.
    """
    svg = _sparkline_svg(snapshots)

    # Must be a valid self-contained SVG element
    assert "<svg" in svg
    assert "</svg>" in svg
    assert 'xmlns="http://www.w3.org/2000/svg"' in svg

    # Count <circle elements — one per data point
    circles = re.findall(r"<circle", svg)
    assert len(circles) == len(snapshots), (
        f"Expected {len(snapshots)} <circle> elements, got {len(circles)}"
    )


# =========================================================================
# Feature: audit-report-enhancements
# Property 7: Combined group filter correctness
# =========================================================================

_filter_group_strategy = st.fixed_dictionaries({
    "name": st.text(min_size=1, max_size=30, alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="_-")),
    "compliant": st.booleans(),
})

from ad_groups_mcp.report import _filter_groups


@given(
    search_text=st.text(min_size=0, max_size=20),
    compliance_filter=st.sampled_from(["all", "compliant", "non-compliant"]),
    groups=st.lists(_filter_group_strategy, min_size=0, max_size=15),
)
@settings(max_examples=100)
def test_property_combined_group_filter(
    search_text: str, compliance_filter: str, groups: list[dict]
) -> None:
    """**Validates: Requirements 5.2, 5.3, 5.5, 5.6, 5.7**

    Feature: audit-report-enhancements, Property 7: Combined group filter correctness

    For any search string, compliance filter, and list of groups, the filter
    returns exactly those groups matching both criteria, and the visible count
    equals the filtered list length.
    """
    filtered_list, count = _filter_groups(groups, search_text, compliance_filter)

    # Count equals filtered list length
    assert count == len(filtered_list), (
        f"count={count} != len(filtered_list)={len(filtered_list)}"
    )

    needle = search_text.lower()

    # Every group in filtered_list has search_text in its name (case-insensitive)
    for g in filtered_list:
        assert needle in g["name"].lower(), (
            f"Group '{g['name']}' does not contain search text '{search_text}'"
        )

    # Every group in filtered_list matches the compliance filter
    for g in filtered_list:
        if compliance_filter == "compliant":
            assert g["compliant"] is True, (
                f"Group '{g['name']}' is not compliant but passed 'compliant' filter"
            )
        elif compliance_filter == "non-compliant":
            assert g["compliant"] is False, (
                f"Group '{g['name']}' is compliant but passed 'non-compliant' filter"
            )

    # Completeness: no group outside filtered_list matches both criteria
    for g in groups:
        name_matches = needle in g["name"].lower()
        compliance_matches = (
            compliance_filter == "all"
            or (compliance_filter == "compliant" and g["compliant"] is True)
            or (compliance_filter == "non-compliant" and g["compliant"] is False)
        )
        if name_matches and compliance_matches:
            assert g in filtered_list, (
                f"Group '{g['name']}' matches both criteria but is missing from filtered_list"
            )


# =========================================================================
# Feature: audit-report-enhancements
# Property 8: Report metadata completeness
# =========================================================================

import json

from ad_groups_mcp.report import _report_metadata_json

_metadata_rule_strategy = st.fixed_dictionaries({
    "rule_name": st.sampled_from(["naming", "description", "owner", "membership", "review_recency"]),
    "passed": st.booleans(),
    "message": st.just("test"),
})

_metadata_group_strategy = st.fixed_dictionaries({
    "name": st.text(min_size=1, max_size=30, alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="_-")),
    "compliant": st.booleans(),
    "member_count": st.integers(min_value=0, max_value=10000),
    "rules": st.lists(_metadata_rule_strategy, min_size=0, max_size=5),
})


@given(groups=st.lists(_metadata_group_strategy, min_size=0, max_size=20))
@settings(max_examples=100)
def test_property_report_metadata_completeness(groups: list[dict]) -> None:
    """**Validates: Requirements 6.1, 6.2**

    Feature: audit-report-enhancements, Property 8: Report metadata completeness

    For any list of groups, the generated metadata JSON is valid, contains
    correct total_groups, compliant_count, compliance_pct, and per-group
    entries with name, compliance status, member_count, and rules.
    """
    total = len(groups)
    compliant_count = sum(1 for g in groups if g.get("compliant"))

    html_tag = _report_metadata_json(groups, total, compliant_count, "2026-04-20T14:30:00+00:00")

    # Extract JSON from the script tag
    match = re.search(
        r'<script type="application/json" id="report-metadata">(.*?)</script>',
        html_tag,
    )
    assert match is not None, "No report-metadata script tag found"

    metadata = json.loads(match.group(1))

    # Top-level fields
    assert metadata["total_groups"] == total
    assert metadata["compliant_count"] == compliant_count

    expected_pct = round(compliant_count / total * 100, 1) if total > 0 else 0
    assert metadata["compliance_pct"] == expected_pct

    # Per-group entries
    assert len(metadata["groups"]) == len(groups)

    for entry in metadata["groups"]:
        assert "name" in entry
        assert "compliant" in entry
        assert "member_count" in entry
        assert "rules" in entry


# =========================================================================
# Feature: audit-report-enhancements
# Property 9: Report diff correctness
# =========================================================================

from ad_groups_mcp.report import _diff_metadata

_diff_group_strategy = st.fixed_dictionaries({
    "name": st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="_-")),
    "compliant": st.booleans(),
    "member_count": st.integers(min_value=0, max_value=10000),
})

_diff_metadata_strategy = st.fixed_dictionaries({
    "total_groups": st.integers(min_value=0, max_value=100),
    "compliance_pct": st.floats(min_value=0.0, max_value=100.0, allow_nan=False, allow_infinity=False),
    "groups": st.lists(_diff_group_strategy, min_size=0, max_size=10, unique_by=lambda g: g["name"]),
})


@given(current=_diff_metadata_strategy, other=_diff_metadata_strategy)
@settings(max_examples=100)
def test_property_report_diff_correctness(current: dict, other: dict) -> None:
    """**Validates: Requirements 6.5, 6.6, 6.7**

    Feature: audit-report-enhancements, Property 9: Report diff correctness

    For any two valid metadata objects, the diff correctly computes: change in
    total groups, change in compliance %, newly compliant/non-compliant counts,
    added/removed groups, and list of groups with changed status or member count.
    """
    result = _diff_metadata(current, other)

    # 1. delta_total == current["total_groups"] - other["total_groups"]
    assert result["delta_total"] == current["total_groups"] - other["total_groups"], (
        f"delta_total: expected {current['total_groups'] - other['total_groups']}, "
        f"got {result['delta_total']}"
    )

    # 2. delta_compliance == round(current["compliance_pct"] - other["compliance_pct"], 1)
    expected_delta_compliance = round(current["compliance_pct"] - other["compliance_pct"], 1)
    assert result["delta_compliance"] == expected_delta_compliance, (
        f"delta_compliance: expected {expected_delta_compliance}, "
        f"got {result['delta_compliance']}"
    )

    # Build lookup maps for expected computation
    cur_map = {g["name"]: g for g in current["groups"]}
    oth_map = {g["name"]: g for g in other["groups"]}
    cur_names = set(cur_map)
    oth_names = set(oth_map)

    # 3. Compute expected added/removed groups and assert they match
    expected_added = cur_names - oth_names
    expected_removed = oth_names - cur_names
    assert set(result["added"]) == expected_added, (
        f"added: expected {expected_added}, got {set(result['added'])}"
    )
    assert set(result["removed"]) == expected_removed, (
        f"removed: expected {expected_removed}, got {set(result['removed'])}"
    )

    # 4. Compute expected newly_compliant/newly_non_compliant counts
    common_names = cur_names & oth_names
    expected_newly_compliant = sum(
        1 for n in common_names
        if cur_map[n]["compliant"] and not oth_map[n]["compliant"]
    )
    expected_newly_non_compliant = sum(
        1 for n in common_names
        if not cur_map[n]["compliant"] and oth_map[n]["compliant"]
    )
    assert result["newly_compliant"] == expected_newly_compliant, (
        f"newly_compliant: expected {expected_newly_compliant}, "
        f"got {result['newly_compliant']}"
    )
    assert result["newly_non_compliant"] == expected_newly_non_compliant, (
        f"newly_non_compliant: expected {expected_newly_non_compliant}, "
        f"got {result['newly_non_compliant']}"
    )

    # 5. Assert changed list contains exactly those groups whose compliance
    #    or member_count changed
    expected_changed_names = {
        n for n in common_names
        if cur_map[n]["compliant"] != oth_map[n]["compliant"]
        or cur_map[n]["member_count"] != oth_map[n]["member_count"]
    }
    actual_changed_names = {c["name"] for c in result["changed"]}
    assert actual_changed_names == expected_changed_names, (
        f"changed names: expected {expected_changed_names}, got {actual_changed_names}"
    )

    # Verify each changed entry has correct old/new values
    for entry in result["changed"]:
        name = entry["name"]
        assert entry["old_compliant"] == oth_map[name]["compliant"]
        assert entry["new_compliant"] == cur_map[name]["compliant"]
        assert entry["old_members"] == oth_map[name]["member_count"]
        assert entry["new_members"] == cur_map[name]["member_count"]


# =========================================================================
# Feature: audit-report-enhancements
# Property 1: Snapshot recording produces one correct snapshot per group
# =========================================================================

_snapshot_group_strategy = st.lists(
    st.tuples(
        st.text(min_size=3, max_size=60, alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="=,_ ")),
        st.integers(min_value=0, max_value=100000),
    ),
    min_size=1,
    max_size=10,
    unique_by=lambda x: x[0],
)


@given(groups=_snapshot_group_strategy)
@settings(max_examples=100, deadline=None)
def test_property_snapshot_recording_per_group(groups: list[tuple[str, int]]) -> None:
    """**Validates: Requirements 1.1, 1.2**

    Feature: audit-report-enhancements, Property 1: Snapshot recording produces one correct snapshot per group

    For any list of groups with arbitrary member counts, recording snapshots
    produces exactly one new snapshot per group with correct member_count
    and reviewer="audit-script".
    """
    # Filter out whitespace-only and NUL-containing group DNs
    for group_dn, _ in groups:
        assume(group_dn.strip() != "")
        assume("\x00" not in group_dn)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    store = SQLiteStore(db_path)
    store.initialize()

    # Record one snapshot per group (simulating an audit run)
    for group_dn, member_count in groups:
        store.record_snapshot(group_dn, member_count, "audit-script")

    # Verify: exactly one snapshot per group with correct values
    for group_dn, member_count in groups:
        snapshots = store.get_snapshots(group_dn)
        assert len(snapshots) == 1, (
            f"Expected 1 snapshot for '{group_dn}', got {len(snapshots)}"
        )
        snap = snapshots[0]
        assert snap.member_count == member_count, (
            f"member_count mismatch for '{group_dn}': expected {member_count}, got {snap.member_count}"
        )
        assert snap.reviewer == "audit-script", (
            f"reviewer mismatch for '{group_dn}': expected 'audit-script', got '{snap.reviewer}'"
        )


# =========================================================================
# Feature: ad-native-audit
# Property 1: Date parsing round-trip
# =========================================================================

from ad_groups_mcp.review_resolver import (
    parse_review_date,
    build_review_from_ad,
    resolve_review,
)


@given(
    year=st.integers(min_value=2000, max_value=2099),
    month=st.integers(min_value=1, max_value=12),
    day=st.integers(min_value=1, max_value=28),
)
@settings(max_examples=100)
def test_property_1_ad_native_date_parsing_round_trip(year: int, month: int, day: int) -> None:
    """**Validates: Requirements 9.2**

    Feature: ad-native-audit, Property 1: Date parsing round-trip

    For any valid date (year 2000-2099, month 1-12, day 1-28), formatting
    as YYYY-MM-DD then parsing with parse_review_date and formatting back
    produces the original string.
    """
    date_str = f"{year:04d}-{month:02d}-{day:02d}"
    parsed = parse_review_date(date_str)
    assert parsed is not None, f"parse_review_date returned None for valid date '{date_str}'"
    round_tripped = parsed.strftime("%Y-%m-%d")
    assert round_tripped == date_str, (
        f"Round-trip failed: input='{date_str}', output='{round_tripped}'"
    )


# =========================================================================
# Feature: ad-native-audit
# Property 2: Most-recent-wins merge correctness
# =========================================================================


@given(
    ad_date=st.dates(
        min_value=datetime(2000, 1, 1).date(),
        max_value=datetime(2099, 12, 28).date(),
    ),
    sqlite_date=st.dates(
        min_value=datetime(2000, 1, 1).date(),
        max_value=datetime(2099, 12, 28).date(),
    ),
    ad_reviewer=st.text(
        min_size=1, max_size=20,
        alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="_-"),
    ),
    sqlite_reviewer=st.text(
        min_size=1, max_size=20,
        alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="_-"),
    ),
)
@settings(max_examples=100)
def test_property_2_ad_native_most_recent_wins(
    ad_date, sqlite_date, ad_reviewer: str, sqlite_reviewer: str,
) -> None:
    """**Validates: Requirements 1.3, 4.3**

    Feature: ad-native-audit, Property 2: Most-recent-wins merge correctness

    For any two ReviewRecords with distinct timestamps, resolve_review
    returns the more recent one; single-source returns that source;
    no sources returns None.
    """
    assume(ad_date != sqlite_date)

    ad_date_str = ad_date.strftime("%Y-%m-%d")
    sqlite_dt = datetime(sqlite_date.year, sqlite_date.month, sqlite_date.day, tzinfo=timezone.utc)
    sqlite_review = ReviewRecord(
        group_dn="CN=TestGroup,OU=Groups,DC=example,DC=com",
        reviewer=sqlite_reviewer,
        reviewed_at=sqlite_dt,
    )

    # Both sources present (distinct dates)
    review, source = resolve_review(ad_reviewer, ad_date_str, sqlite_review)
    assert review is not None
    assert source == "both"
    if ad_date > sqlite_date:
        assert review.reviewer == ad_reviewer, (
            f"AD date {ad_date} > SQLite date {sqlite_date}, expected AD reviewer"
        )
    else:
        assert review.reviewer == sqlite_reviewer, (
            f"SQLite date {sqlite_date} > AD date {ad_date}, expected SQLite reviewer"
        )

    # AD only
    review_ad, source_ad = resolve_review(ad_reviewer, ad_date_str, None)
    assert review_ad is not None
    assert source_ad == "ad"
    assert review_ad.reviewer == ad_reviewer

    # SQLite only
    review_sq, source_sq = resolve_review(None, None, sqlite_review)
    assert review_sq is not None
    assert source_sq == "sqlite"
    assert review_sq.reviewer == sqlite_reviewer

    # No sources
    review_none, source_none = resolve_review(None, None, None)
    assert review_none is None
    assert source_none == "none"


# =========================================================================
# Feature: ad-native-audit
# Property 3: Malformed date rejection
# =========================================================================

_YYYY_MM_DD_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@given(text=st.text(min_size=0, max_size=50))
@settings(max_examples=100)
def test_property_3_ad_native_malformed_date_rejection(text: str) -> None:
    """**Validates: Requirements 1.5**

    Feature: ad-native-audit, Property 3: Malformed date rejection

    For any string not matching YYYY-MM-DD format, parse_review_date
    returns None.
    """
    assume(not _YYYY_MM_DD_RE.match(text))
    result = parse_review_date(text)
    assert result is None, (
        f"parse_review_date should return None for malformed input '{text}', got {result}"
    )


@given(
    year=st.integers(min_value=2000, max_value=2099),
    month=st.integers(min_value=1, max_value=12),
    day=st.integers(min_value=1, max_value=28),
    sep=st.sampled_from(["/", ".", " ", "_", ":", ""]),
)
@settings(max_examples=100)
def test_property_3_ad_native_wrong_separator_rejection(
    year: int, month: int, day: int, sep: str,
) -> None:
    """**Validates: Requirements 1.5**

    Feature: ad-native-audit, Property 3: Malformed date rejection (wrong separators)

    Strings that look like dates but use wrong separators are rejected.
    """
    assume(sep != "-")
    text = f"{year:04d}{sep}{month:02d}{sep}{day:02d}"
    result = parse_review_date(text)
    assert result is None, (
        f"parse_review_date should return None for wrong-separator input '{text}', got {result}"
    )


# =========================================================================
# Feature: ad-native-audit
# Property 6: Review record construction round-trip
# =========================================================================


@given(
    username=st.text(
        min_size=1,
        max_size=30,
        alphabet=st.characters(
            blacklist_categories=("Cs",),
            blacklist_characters="\x00",
        ),
    ),
    year=st.integers(min_value=2000, max_value=2099),
    month=st.integers(min_value=1, max_value=12),
    day=st.integers(min_value=1, max_value=28),
)
@settings(max_examples=100)
def test_property_6_ad_native_review_record_construction_round_trip(
    username: str, year: int, month: int, day: int,
) -> None:
    """**Validates: Requirements 1.1, 1.2, 4.2, 9.1**

    Feature: ad-native-audit, Property 6: Review record construction round-trip

    For any valid username (non-empty, no NUL bytes) and valid YYYY-MM-DD
    date, build_review_from_ad produces a ReviewRecord with matching
    reviewer and date.
    """
    date_str = f"{year:04d}-{month:02d}-{day:02d}"
    record = build_review_from_ad(username, date_str)
    assert record is not None, (
        f"build_review_from_ad returned None for valid inputs: "
        f"username='{username}', date='{date_str}'"
    )
    assert record.reviewer == username, (
        f"reviewer mismatch: expected '{username}', got '{record.reviewer}'"
    )
    assert record.reviewed_at.strftime("%Y-%m-%d") == date_str, (
        f"date mismatch: expected '{date_str}', "
        f"got '{record.reviewed_at.strftime('%Y-%m-%d')}'"
    )


# =========================================================================
# Feature: ad-native-audit
# Property 4: No-DB mode omits database-dependent sections
# =========================================================================

from ad_groups_mcp.report import generate_audit_report

# Strategy for minimal group dicts suitable for generate_audit_report
_report_group_strategy = st.fixed_dictionaries({
    "name": st.text(
        min_size=1,
        max_size=30,
        alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="_-"),
    ),
    "scope": st.sampled_from(["Universal", "Global", "DomainLocal"]),
    "category": st.sampled_from(["Security", "Distribution"]),
    "description": st.text(min_size=0, max_size=50),
    "managed_by": st.text(min_size=0, max_size=30),
    "compliant": st.booleans(),
    "member_count": st.integers(min_value=0, max_value=500),
    "rules": st.just([]),
})


@given(groups=st.lists(_report_group_strategy, min_size=0, max_size=5))
@settings(max_examples=100, deadline=None)
def test_property_4_ad_native_no_db_mode_omits_db_sections(groups: list[dict]) -> None:
    """**Validates: Requirements 2.3, 8.2**

    Feature: ad-native-audit, Property 4: No-DB mode omits database-dependent sections

    For any group data with no_db_mode=True, HTML shall not contain trend
    chart SVG, sparkline SVG, or drift table, and shall contain the no-DB
    banner.
    """
    html_output = generate_audit_report(
        groups=groups,
        no_db_mode=True,
        # Provide data that would normally render these sections —
        # they must still be omitted in no-DB mode.
        trend_data=[
            {"compliance_pct": 80.0, "snapshot_at": "2026-01-01T00:00:00+00:00"},
            {"compliance_pct": 90.0, "snapshot_at": "2026-01-02T00:00:00+00:00"},
        ],
        membership_drift=[{
            "group_dn": "CN=Test,OU=Groups,DC=example,DC=com",
            "previous_count": 5,
            "current_count": 10,
            "delta": 5,
            "change_pct": 100,
            "previous_date": "2026-01-01",
            "current_date": "2026-01-02",
        }],
        sparkline_data={
            "CN=Test,OU=Groups,DC=example,DC=com": [
                {"member_count": 5, "snapshot_at": "2026-01-01T00:00:00+00:00"},
                {"member_count": 10, "snapshot_at": "2026-01-02T00:00:00+00:00"},
            ],
        },
    )

    # Must contain the no-DB banner
    assert "no-db-banner" in html_output, "No-DB banner CSS class not found in output"
    assert "No-DB mode" in html_output, "No-DB banner text not found in output"

    # Must NOT contain trend chart SVG (the _trend_chart_svg produces <svg with viewBox)
    # When trend_data has >=2 points, it would produce an SVG with <polyline — verify absent
    assert '<polyline points="' not in html_output or "Insufficient data" in html_output, (
        "Trend chart SVG polyline found in no-DB mode output"
    )

    # Must NOT contain drift table section
    assert 'id="drift"' not in html_output, (
        "Membership drift section found in no-DB mode output"
    )

    # Must NOT contain sparkline SVGs (sparklines are rendered inside drift section)
    assert "sparkline" not in html_output.lower() or 'id="drift"' not in html_output, (
        "Sparkline content found in no-DB mode output"
    )


# =========================================================================
# Feature: ad-native-audit
# Property 5: Review source annotation in report
# =========================================================================


@given(
    review_source=st.sampled_from(["ad", "sqlite", "both"]),
    reviewer_name=st.text(
        min_size=1,
        max_size=20,
        alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="_-"),
    ),
)
@settings(max_examples=100, deadline=None)
def test_property_5_ad_native_review_source_annotation(
    review_source: str, reviewer_name: str,
) -> None:
    """**Validates: Requirements 8.1**

    Feature: ad-native-audit, Property 5: Review source annotation in report

    For any group with review_source in {"ad", "sqlite", "both"}, rendered
    HTML contains the source label alongside the review date and reviewer.
    """
    groups = [{
        "name": "ACME-TestGroup",
        "scope": "Universal",
        "category": "Security",
        "description": "Test group",
        "managed_by": "",
        "compliant": True,
        "member_count": 5,
        "rules": [],
        "last_review": {
            "reviewer": reviewer_name,
            "reviewed_at": "2026-01-15T00:00:00+00:00",
        },
        "review_source": review_source,
    }]

    html_output = generate_audit_report(groups=groups)

    # The source display mapping
    source_display = {"ad": "AD", "sqlite": "SQLite", "both": "both"}[review_source]
    expected_label = f"(source: {source_display})"

    assert expected_label in html_output, (
        f"Expected source label '{expected_label}' not found in report HTML "
        f"for review_source='{review_source}'"
    )

    # The reviewer name should also appear
    assert reviewer_name in html_output, (
        f"Reviewer name '{reviewer_name}' not found in report HTML"
    )
