"""YAML-based policy evaluation logic for AD group compliance."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from ad_groups_mcp.models import (
    GroupDetail,
    PolicyConfig,
    PolicyEvalResult,
    ReviewRecord,
    RuleResult,
)


class PolicyEngine:
    """Evaluates AD groups against configurable policy rules."""

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    def evaluate_naming(self, sam_name: str) -> RuleResult:
        """Check SAM account name against the naming regex pattern."""
        passed = bool(re.fullmatch(self.config.naming_regex, sam_name))
        message = (
            "Name matches naming convention"
            if passed
            else f"Name '{sam_name}' does not match pattern '{self.config.naming_regex}'"
        )
        return RuleResult(rule_name="naming", passed=passed, message=message)

    def evaluate_description(self, description: str | None) -> RuleResult:
        """Check that the group has a non-empty description."""
        passed = description is not None and description != ""
        message = (
            "Description is present"
            if passed
            else "Description is missing or empty"
        )
        return RuleResult(rule_name="description", passed=passed, message=message)

    def evaluate_owner(self, managed_by: str | None) -> RuleResult:
        """Check that the group has a non-empty managedBy attribute."""
        passed = managed_by is not None and managed_by != ""
        message = (
            "Owner (managedBy) is assigned"
            if passed
            else "Owner (managedBy) is missing or empty"
        )
        return RuleResult(rule_name="owner", passed=passed, message=message)

    def evaluate_membership(self, member_count: int) -> RuleResult:
        """Check that member count does not exceed the configured threshold."""
        passed = member_count <= self.config.max_members
        message = (
            f"Member count ({member_count}) is within threshold ({self.config.max_members})"
            if passed
            else f"Member count ({member_count}) exceeds threshold ({self.config.max_members})"
        )
        return RuleResult(rule_name="membership", passed=passed, message=message)

    def evaluate_review_recency(self, review: ReviewRecord | None) -> RuleResult:
        """Check that a review exists and is within the recency window."""
        if review is None:
            return RuleResult(
                rule_name="review_recency",
                passed=False,
                message="No governance review recorded",
            )

        now = datetime.now(timezone.utc)
        reviewed_at = review.reviewed_at
        # Ensure timezone-aware comparison
        if reviewed_at.tzinfo is None:
            reviewed_at = reviewed_at.replace(tzinfo=timezone.utc)
        elapsed_days = (now - reviewed_at).days
        passed = elapsed_days <= self.config.review_recency_days
        message = (
            f"Review is recent ({elapsed_days} days ago, within {self.config.review_recency_days}-day window)"
            if passed
            else f"Review is stale ({elapsed_days} days ago, exceeds {self.config.review_recency_days}-day window)"
        )
        return RuleResult(rule_name="review_recency", passed=passed, message=message)

    def evaluate_stale(self, when_changed: datetime) -> RuleResult:
        """Check that the group has been modified within the stale threshold."""
        now = datetime.now(timezone.utc)
        changed = when_changed
        if changed.tzinfo is None:
            changed = changed.replace(tzinfo=timezone.utc)
        elapsed_days = (now - changed).days
        passed = elapsed_days <= self.config.stale_days
        message = (
            f"Group is active (last changed {elapsed_days} days ago, within {self.config.stale_days}-day window)"
            if passed
            else f"Group is stale (last changed {elapsed_days} days ago, exceeds {self.config.stale_days}-day threshold)"
        )
        return RuleResult(rule_name="stale_group", passed=passed, message=message)

    def is_privileged(self, sam_name: str) -> bool:
        """Check if a group name contains any privileged keywords."""
        name_lower = sam_name.lower()
        return any(kw.lower() in name_lower for kw in self.config.privileged_keywords)

    def evaluate_privileged_review(self, sam_name: str, review: ReviewRecord | None) -> RuleResult | None:
        """Check privileged groups have been reviewed within the shorter window.

        Returns None if the group is not privileged (rule doesn't apply).
        """
        if not self.is_privileged(sam_name):
            return None

        if review is None:
            return RuleResult(
                rule_name="privileged_review",
                passed=False,
                message=f"Privileged group has no governance review (required every {self.config.privileged_review_days} days)",
            )

        now = datetime.now(timezone.utc)
        reviewed_at = review.reviewed_at
        if reviewed_at.tzinfo is None:
            reviewed_at = reviewed_at.replace(tzinfo=timezone.utc)
        elapsed_days = (now - reviewed_at).days
        passed = elapsed_days <= self.config.privileged_review_days
        message = (
            f"Privileged review is current ({elapsed_days} days ago, within {self.config.privileged_review_days}-day window)"
            if passed
            else f"Privileged review is overdue ({elapsed_days} days ago, exceeds {self.config.privileged_review_days}-day window)"
        )
        return RuleResult(rule_name="privileged_review", passed=passed, message=message)

    def evaluate(self, group: GroupDetail, review: ReviewRecord | None) -> PolicyEvalResult:
        """Run all policy rules against a group and return the evaluation result."""
        rules = [
            self.evaluate_naming(group.sam_account_name),
            self.evaluate_description(group.description),
            self.evaluate_owner(group.managed_by),
            self.evaluate_membership(group.member_count),
            self.evaluate_review_recency(review),
            self.evaluate_stale(group.when_changed),
        ]
        # Add privileged review rule only if applicable
        priv_rule = self.evaluate_privileged_review(group.sam_account_name, review)
        if priv_rule is not None:
            rules.append(priv_rule)

        compliant = all(r.passed for r in rules)
        return PolicyEvalResult(
            group_dn=group.distinguished_name,
            rules=rules,
            compliant=compliant,
        )
