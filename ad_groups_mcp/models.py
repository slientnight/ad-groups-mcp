"""Pydantic data models for the AD Groups MCP server."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class HealthcheckResult(BaseModel):
    status: str  # "ok" or "error"
    domain_controller: str | None
    domain_name: str | None
    timestamp: datetime
    error_message: str | None = None


class GroupSummary(BaseModel):
    distinguished_name: str
    sam_account_name: str
    group_scope: str  # "DomainLocal" | "Global" | "Universal"
    group_category: str  # "Security" | "Distribution"
    description: str | None
    managed_by: str | None


class ReplicationMetadata(BaseModel):
    last_originating_change_time: datetime | None
    last_originating_change_dc: str | None
    originating_change_principal: str | None


class ReviewRecord(BaseModel):
    group_dn: str
    reviewer: str
    reviewed_at: datetime


class GroupDetail(GroupSummary):
    when_created: datetime
    when_changed: datetime
    member_count: int
    replication_metadata: ReplicationMetadata | None = None
    last_review: ReviewRecord | None = None
    extension_attribute_1: str | None = None  # last reviewed by
    extension_attribute_2: str | None = None  # last reviewed date
    review_source: str | None = None  # "ad", "sqlite", "both", or "none"


class ReviewConfirmation(BaseModel):
    group_dn: str
    reviewer: str
    reviewed_at: datetime
    warnings: list[str] = []  # partial failure warnings


class RuleResult(BaseModel):
    rule_name: str
    passed: bool
    message: str


class PolicyEvalResult(BaseModel):
    group_dn: str
    rules: list[RuleResult]
    compliant: bool  # True if all rules passed


class ACEViolation(BaseModel):
    principal: str
    permission: str  # "GenericAll" | "WriteDacl" | "WriteOwner"
    group_dn: str


class ACLAuditResult(BaseModel):
    group_dn: str
    clean: bool
    violations: list[ACEViolation]


class InventoryAuditResult(BaseModel):
    total_groups: int
    compliant_count: int
    violation_count: int
    errors: list[str]
    per_group_violations: list[PolicyEvalResult]


class SecurityEvent(BaseModel):
    event_id: int
    timestamp: datetime
    account: str  # Who performed the change
    member: str  # Member added/removed
    target_group: str


class PolicyConfig(BaseModel):
    naming_regex: str = r"^(SEC|DL|APP)_.*"
    max_members: int = 500
    review_recency_days: int = 90
    stale_days: int = 730  # 2 years — groups unchanged longer are flagged
    privileged_keywords: list[str] = ["Admin", "Server", "LAPS", "RBAC", "Root"]
    privileged_review_days: int = 90  # quarterly review for privileged groups
    acl_allow_list: list[str] = ["Domain Admins", "Enterprise Admins"]
    search_base: str = ""  # OU to scope queries, e.g. "OU=MyGroups,OU=MyOrg,DC=example,DC=com"
    extended_attribute_mapping: dict[str, str] = {
        "reviewed_by": "extensionAttribute1",
        "reviewed_date": "extensionAttribute2",
    }


class MembershipSnapshot(BaseModel):
    group_dn: str
    member_count: int
    snapshot_at: datetime
    reviewer: str


class AuditSnapshot(BaseModel):
    compliance_pct: float
    total_groups: int
    compliant_count: int
    snapshot_at: datetime


class ReviewCoverage(BaseModel):
    total_groups: int
    reviewed_count: int
    unreviewed_count: int
    coverage_pct: float
    stale_reviews: int  # reviewed but outside window
    unreviewed_groups: list[str]
    stale_review_groups: list[str]


class SearchResult(BaseModel):
    groups: list[GroupSummary]
    message: str | None = None  # e.g. "No matches found"


class ToolError(BaseModel):
    error: bool = True
    code: str  # e.g. "AD_UNREACHABLE", "GROUP_NOT_FOUND", "INVALID_INPUT"
    message: str  # Human-readable description
