"""Unit tests for the PolicyEngine class."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ad_groups_mcp.models import (
    GroupDetail,
    PolicyConfig,
    ReviewRecord,
)
from ad_groups_mcp.policy_engine import PolicyEngine


@pytest.fixture
def default_config() -> PolicyConfig:
    return PolicyConfig()


@pytest.fixture
def engine(default_config: PolicyConfig) -> PolicyEngine:
    return PolicyEngine(default_config)


def _make_group(
    sam_name: str = "SEC_TestGroup",
    description: str | None = "A test group",
    managed_by: str | None = "CN=Admin,DC=example,DC=com",
    member_count: int = 10,
    when_changed: datetime | None = None,
) -> GroupDetail:
    if when_changed is None:
        when_changed = datetime(2024, 6, 1, tzinfo=timezone.utc)
    return GroupDetail(
        distinguished_name="CN=SEC_TestGroup,OU=Groups,DC=example,DC=com",
        sam_account_name=sam_name,
        group_scope="Global",
        group_category="Security",
        description=description,
        managed_by=managed_by,
        when_created=datetime(2024, 1, 1, tzinfo=timezone.utc),
        when_changed=when_changed,
        member_count=member_count,
    )


def _make_review(days_ago: int = 30) -> ReviewRecord:
    return ReviewRecord(
        group_dn="CN=SEC_TestGroup,OU=Groups,DC=example,DC=com",
        reviewer="admin@example.com",
        reviewed_at=datetime.now(timezone.utc) - timedelta(days=days_ago),
    )


# --- evaluate_naming ---

class TestEvaluateNaming:
    def test_matching_name_passes(self, engine: PolicyEngine) -> None:
        result = engine.evaluate_naming("SEC_MyGroup")
        assert result.passed is True
        assert result.rule_name == "naming"

    def test_non_matching_name_fails(self, engine: PolicyEngine) -> None:
        result = engine.evaluate_naming("BadName")
        assert result.passed is False
        assert result.rule_name == "naming"
        assert "BadName" in result.message

    def test_dl_prefix_passes(self, engine: PolicyEngine) -> None:
        assert engine.evaluate_naming("DL_Distribution").passed is True

    def test_app_prefix_passes(self, engine: PolicyEngine) -> None:
        assert engine.evaluate_naming("APP_Service").passed is True

    def test_custom_regex(self) -> None:
        config = PolicyConfig(naming_regex=r"^GRP-\d+$")
        eng = PolicyEngine(config)
        assert eng.evaluate_naming("GRP-123").passed is True
        assert eng.evaluate_naming("GRP-abc").passed is False


# --- evaluate_description ---

class TestEvaluateDescription:
    def test_non_empty_passes(self, engine: PolicyEngine) -> None:
        result = engine.evaluate_description("Some description")
        assert result.passed is True
        assert result.rule_name == "description"

    def test_none_fails(self, engine: PolicyEngine) -> None:
        result = engine.evaluate_description(None)
        assert result.passed is False

    def test_empty_string_fails(self, engine: PolicyEngine) -> None:
        result = engine.evaluate_description("")
        assert result.passed is False


# --- evaluate_owner ---

class TestEvaluateOwner:
    def test_non_empty_passes(self, engine: PolicyEngine) -> None:
        result = engine.evaluate_owner("CN=Admin,DC=example,DC=com")
        assert result.passed is True
        assert result.rule_name == "owner"

    def test_none_fails(self, engine: PolicyEngine) -> None:
        result = engine.evaluate_owner(None)
        assert result.passed is False

    def test_empty_string_fails(self, engine: PolicyEngine) -> None:
        result = engine.evaluate_owner("")
        assert result.passed is False


# --- evaluate_membership ---

class TestEvaluateMembership:
    def test_under_threshold_passes(self, engine: PolicyEngine) -> None:
        result = engine.evaluate_membership(100)
        assert result.passed is True
        assert result.rule_name == "membership"

    def test_at_threshold_passes(self, engine: PolicyEngine) -> None:
        result = engine.evaluate_membership(500)
        assert result.passed is True

    def test_over_threshold_fails(self, engine: PolicyEngine) -> None:
        result = engine.evaluate_membership(501)
        assert result.passed is False


# --- evaluate_review_recency ---

class TestEvaluateReviewRecency:
    def test_recent_review_passes(self, engine: PolicyEngine) -> None:
        review = _make_review(days_ago=30)
        result = engine.evaluate_review_recency(review)
        assert result.passed is True
        assert result.rule_name == "review_recency"

    def test_stale_review_fails(self, engine: PolicyEngine) -> None:
        review = _make_review(days_ago=91)
        result = engine.evaluate_review_recency(review)
        assert result.passed is False

    def test_no_review_fails(self, engine: PolicyEngine) -> None:
        result = engine.evaluate_review_recency(None)
        assert result.passed is False
        assert "No governance review" in result.message

    def test_exactly_at_window_passes(self, engine: PolicyEngine) -> None:
        review = _make_review(days_ago=90)
        result = engine.evaluate_review_recency(review)
        assert result.passed is True


# --- evaluate (full) ---

class TestEvaluate:
    def test_fully_compliant_group(self, engine: PolicyEngine) -> None:
        group = _make_group()
        review = _make_review(days_ago=10)
        result = engine.evaluate(group, review)
        assert result.compliant is True
        assert result.group_dn == group.distinguished_name
        assert len(result.rules) == 6
        assert all(r.passed for r in result.rules)

    def test_non_compliant_group_bad_name(self, engine: PolicyEngine) -> None:
        group = _make_group(sam_name="BadName")
        review = _make_review(days_ago=10)
        result = engine.evaluate(group, review)
        assert result.compliant is False
        naming_rule = next(r for r in result.rules if r.rule_name == "naming")
        assert naming_rule.passed is False

    def test_non_compliant_no_review(self, engine: PolicyEngine) -> None:
        group = _make_group()
        result = engine.evaluate(group, None)
        assert result.compliant is False

    def test_multiple_violations(self, engine: PolicyEngine) -> None:
        group = _make_group(
            sam_name="BadName",
            description=None,
            managed_by=None,
            member_count=1000,
            when_changed=datetime(2020, 1, 1, tzinfo=timezone.utc),  # stale
        )
        result = engine.evaluate(group, None)
        assert result.compliant is False
        failed = [r for r in result.rules if not r.passed]
        assert len(failed) == 6  # all rules fail including stale_group

    def test_rule_names_are_unique(self, engine: PolicyEngine) -> None:
        group = _make_group()
        review = _make_review()
        result = engine.evaluate(group, review)
        names = [r.rule_name for r in result.rules]
        assert len(names) == len(set(names))

    def test_expected_rule_names(self, engine: PolicyEngine) -> None:
        group = _make_group()
        review = _make_review()
        result = engine.evaluate(group, review)
        names = {r.rule_name for r in result.rules}
        assert names == {"naming", "description", "owner", "membership", "review_recency", "stale_group"}
