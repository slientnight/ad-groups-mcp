"""FastMCP server instance and tool registration for AD Groups MCP.

Exposes read-only tools for AD group management, auditing, and
policy evaluation over the Model Context Protocol.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from ad_groups_mcp.acl_auditor import ACLAuditor
from ad_groups_mcp.models import (
    GroupDetail,
    GroupSummary,
    HealthcheckResult,
    InventoryAuditResult,
    PolicyConfig,
    PolicyEvalResult,
    ReviewConfirmation,
    SearchResult,
    ToolError,
)
from ad_groups_mcp.policy_engine import PolicyEngine
from ad_groups_mcp.sqlite_store import SQLiteStore

logger = logging.getLogger(__name__)

# AD returns GroupScope and GroupCategory as integers in some environments
_GROUP_SCOPE_MAP = {0: "DomainLocal", 1: "Global", 2: "Universal"}
_GROUP_CATEGORY_MAP = {0: "Distribution", 1: "Security"}


def _coerce_group_scope(value) -> str:
    if isinstance(value, int):
        return _GROUP_SCOPE_MAP.get(value, str(value))
    return str(value) if value else ""


def _coerce_group_category(value) -> str:
    if isinstance(value, int):
        return _GROUP_CATEGORY_MAP.get(value, str(value))
    return str(value) if value else ""


def create_server(policy_config: PolicyConfig, store: SQLiteStore) -> FastMCP:
    """Create a FastMCP server with all tools registered.

    Parameters
    ----------
    policy_config:
        Loaded policy configuration for the policy engine.
    store:
        Initialized SQLite store for governance review records.

    Returns
    -------
    FastMCP
        Configured server instance ready to run.
    """
    mcp = FastMCP("ad-groups-mcp")
    engine = PolicyEngine(policy_config)
    acl_auditor = ACLAuditor(allow_list=policy_config.acl_allow_list)

    # ------------------------------------------------------------------
    # Tool 1: healthcheck
    # ------------------------------------------------------------------
    @mcp.tool()
    async def healthcheck() -> HealthcheckResult | ToolError:
        """Verify AD connectivity by running a lightweight domain query."""
        from ad_groups_mcp.ad_query import run_ps_command

        try:
            script = (
                "$dc = Get-ADDomainController -Discover -ErrorAction Stop; "
                "@{ DomainController = $dc.HostName[0]; DomainName = $dc.Domain } "
                "| ConvertTo-Json -Compress"
            )
            result = await run_ps_command(script)
            return HealthcheckResult(
                status="ok",
                domain_controller=result.get("DomainController"),
                domain_name=result.get("DomainName"),
                timestamp=datetime.now(timezone.utc),
            )
        except Exception as exc:
            return HealthcheckResult(
                status="error",
                domain_controller=None,
                domain_name=None,
                timestamp=datetime.now(timezone.utc),
                error_message=str(exc),
            )

    # ------------------------------------------------------------------
    # Tool 2: search_groups
    # ------------------------------------------------------------------
    @mcp.tool()
    async def search_groups(query: str) -> SearchResult | ToolError:
        """Search AD groups by name. Requires a non-empty query string."""
        if not query or not query.strip():
            return ToolError(
                code="INVALID_INPUT",
                message="A non-empty search query is required.",
            )

        from ad_groups_mcp.ad_query import search_ad_groups

        try:
            raw_groups = await search_ad_groups(query)
        except Exception as exc:
            return ToolError(code="AD_UNREACHABLE", message=str(exc))

        if not raw_groups:
            return SearchResult(groups=[], message="No matches found")

        groups = [
            GroupSummary(
                distinguished_name=g.get("DistinguishedName", ""),
                sam_account_name=g.get("SamAccountName", ""),
                group_scope=_coerce_group_scope(g.get("GroupScope", "")),
                group_category=_coerce_group_category(g.get("GroupCategory", "")),
                description=g.get("Description"),
                managed_by=g.get("ManagedBy"),
            )
            for g in raw_groups
        ]
        return SearchResult(groups=groups)

    # ------------------------------------------------------------------
    # Tool 3: get_group
    # ------------------------------------------------------------------
    @mcp.tool()
    async def get_group(identity: str) -> GroupDetail | ToolError:
        """Get full group details enriched with replication metadata and review record.

        Returns three distinct timestamps: whenChanged, replication metadata
        time, and human governance review time.
        """
        from ad_groups_mcp.ad_query import get_ad_group
        from ad_groups_mcp.replication import get_member_replication_metadata

        try:
            raw = await get_ad_group(identity)
        except Exception as exc:
            msg = str(exc)
            code = "GROUP_NOT_FOUND" if "not found" in msg.lower() else "AD_UNREACHABLE"
            return ToolError(code=code, message=msg)

        # Parse member count — Members may be a list or None
        members = raw.get("Members") or raw.get("Member") or []
        if isinstance(members, list):
            member_count = len(members)
        else:
            member_count = 1 if members else 0

        dn = raw.get("DistinguishedName", "")

        # Enrich: replication metadata
        repl_meta = None
        try:
            repl_meta = await get_member_replication_metadata(identity)
        except Exception:
            logger.warning("Failed to retrieve replication metadata for %s", identity)

        # Enrich: review record
        last_review = None
        try:
            last_review = store.get_review(dn)
        except Exception:
            logger.warning("Failed to retrieve review record for %s", dn)

        # Parse timestamps
        when_created = _parse_ad_datetime(raw.get("whenCreated"))
        when_changed = _parse_ad_datetime(raw.get("whenChanged"))

        return GroupDetail(
            distinguished_name=dn,
            sam_account_name=raw.get("SamAccountName", ""),
            group_scope=_coerce_group_scope(raw.get("GroupScope", "")),
            group_category=_coerce_group_category(raw.get("GroupCategory", "")),
            description=raw.get("Description"),
            managed_by=raw.get("ManagedBy"),
            when_created=when_created,
            when_changed=when_changed,
            member_count=member_count,
            replication_metadata=repl_meta,
            last_review=last_review,
        )

    # ------------------------------------------------------------------
    # Tool 4: evaluate_group_policy
    # ------------------------------------------------------------------
    @mcp.tool()
    async def evaluate_group_policy(identity: str) -> PolicyEvalResult | ToolError:
        """Evaluate a single AD group against all policy rules."""
        detail = await get_group(identity)
        if isinstance(detail, ToolError):
            return detail

        review = store.get_review(detail.distinguished_name)
        return engine.evaluate(detail, review)

    # ------------------------------------------------------------------
    # Tool 5: audit_group_inventory
    # ------------------------------------------------------------------
    @mcp.tool()
    async def audit_group_inventory() -> InventoryAuditResult | ToolError:
        """Bulk audit all AD groups against policy with fault isolation."""
        from ad_groups_mcp.ad_query import get_groups_in_ou, get_all_ad_groups

        try:
            if policy_config.search_base:
                raw_groups = await get_groups_in_ou(policy_config.search_base)
            else:
                raw_groups = await get_all_ad_groups()
        except Exception as exc:
            return ToolError(code="AD_UNREACHABLE", message=str(exc))

        per_group_violations: list[PolicyEvalResult] = []
        errors: list[str] = []
        compliant_count = 0

        for raw in raw_groups:
            dn = raw.get("DistinguishedName", "unknown")
            try:
                detail = await get_group(dn)
                if isinstance(detail, ToolError):
                    errors.append(f"{dn}: {detail.message}")
                    continue

                review = store.get_review(detail.distinguished_name)
                eval_result = engine.evaluate(detail, review)

                if eval_result.compliant:
                    compliant_count += 1
                else:
                    per_group_violations.append(eval_result)
            except Exception as exc:
                logger.error("Error evaluating group %s: %s", dn, exc)
                errors.append(f"{dn}: {exc}")

        total = len(raw_groups)
        violation_count = total - compliant_count - len(errors)

        return InventoryAuditResult(
            total_groups=total,
            compliant_count=compliant_count,
            violation_count=len(per_group_violations),
            errors=errors,
            per_group_violations=per_group_violations,
        )

    # ------------------------------------------------------------------
    # Tool 6: get_group_change_events
    # ------------------------------------------------------------------
    @mcp.tool()
    async def get_group_change_events(
        identity: str,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> list | ToolError:
        """Query Windows Security event log for group membership change events."""
        from ad_groups_mcp.event_reader import get_group_change_events as _get_events

        try:
            events = await _get_events(identity, start_time, end_time)
            return [e.model_dump() for e in events]
        except Exception as exc:
            return ToolError(code="EVENT_LOG_UNAVAILABLE", message=str(exc))

    # ------------------------------------------------------------------
    # Tool 7: record_group_review
    # ------------------------------------------------------------------
    @mcp.tool()
    async def record_group_review(
        group_dn: str, reviewer: str
    ) -> ReviewConfirmation | ToolError:
        """Record a human governance review for an AD group."""
        if not group_dn or not group_dn.strip():
            return ToolError(
                code="INVALID_INPUT",
                message="A non-empty group distinguished name is required.",
            )

        try:
            record = store.record_review(group_dn.strip(), reviewer)
            return ReviewConfirmation(
                group_dn=record.group_dn,
                reviewer=record.reviewer,
                reviewed_at=record.reviewed_at,
            )
        except Exception as exc:
            return ToolError(code="STORE_ERROR", message=str(exc))

    # ------------------------------------------------------------------
    # Tool 8: get_group_review
    # ------------------------------------------------------------------
    @mcp.tool()
    async def get_group_review(group_dn: str) -> dict:
        """Retrieve the most recent governance review record for a group."""
        try:
            record = store.get_review(group_dn)
            if record is None:
                return {"message": f"No review has been recorded for '{group_dn}'."}
            return record.model_dump()
        except Exception as exc:
            return ToolError(code="STORE_ERROR", message=str(exc)).model_dump()

    # ------------------------------------------------------------------
    # Tool 9: list_recorded_reviews
    # ------------------------------------------------------------------
    @mcp.tool()
    async def list_recorded_reviews() -> list[dict]:
        """List all recorded governance reviews ordered by timestamp descending."""
        try:
            records = store.list_reviews()
            return [r.model_dump() for r in records]
        except Exception as exc:
            return [ToolError(code="STORE_ERROR", message=str(exc)).model_dump()]

    # ------------------------------------------------------------------
    # Tool 10: list_privileged_groups
    # ------------------------------------------------------------------
    @mcp.tool()
    async def list_privileged_groups() -> list[dict] | ToolError:
        """List all privileged groups (names containing Admin, Server, LAPS, RBAC, Root)."""
        from ad_groups_mcp.ad_query import get_groups_in_ou, get_all_ad_groups

        try:
            if policy_config.search_base:
                raw_groups = await get_groups_in_ou(policy_config.search_base)
            else:
                raw_groups = await get_all_ad_groups()
        except Exception as exc:
            return ToolError(code="AD_UNREACHABLE", message=str(exc))

        privileged = []
        for raw in raw_groups:
            sam = raw.get("SamAccountName", "")
            if not engine.is_privileged(sam):
                continue
            dn = raw.get("DistinguishedName", "")
            review = store.get_review(dn)
            priv_rule = engine.evaluate_privileged_review(sam, review)
            privileged.append({
                "name": sam,
                "distinguished_name": dn,
                "description": raw.get("Description"),
                "review_status": priv_rule.model_dump() if priv_rule else None,
                "last_review": review.model_dump() if review else None,
            })
        return privileged

    # ------------------------------------------------------------------
    # Tool 11: record_membership_snapshot
    # ------------------------------------------------------------------
    @mcp.tool()
    async def record_membership_snapshot(
        group_dn: str, member_count: int, reviewer: str
    ) -> dict | ToolError:
        """Record a membership count snapshot for drift tracking."""
        if not group_dn or not group_dn.strip():
            return ToolError(code="INVALID_INPUT", message="group_dn is required.")
        try:
            snap = store.record_snapshot(group_dn.strip(), member_count, reviewer)
            return snap.model_dump()
        except Exception as exc:
            return ToolError(code="STORE_ERROR", message=str(exc))

    # ------------------------------------------------------------------
    # Tool 12: get_membership_drift
    # ------------------------------------------------------------------
    @mcp.tool()
    async def get_membership_drift(group_dn: str) -> dict | ToolError:
        """Compare membership snapshots to detect drift for a group."""
        if not group_dn or not group_dn.strip():
            return ToolError(code="INVALID_INPUT", message="group_dn is required.")
        try:
            drift = store.get_membership_drift(group_dn.strip())
            if drift is None:
                return {"message": f"Less than 2 snapshots recorded for '{group_dn}'. Need at least 2 for drift comparison."}
            return drift
        except Exception as exc:
            return ToolError(code="STORE_ERROR", message=str(exc))

    # ------------------------------------------------------------------
    # Tool 13: review_coverage
    # ------------------------------------------------------------------
    @mcp.tool()
    async def review_coverage() -> dict | ToolError:
        """Get review coverage dashboard — how many groups have been reviewed vs total."""
        from ad_groups_mcp.ad_query import get_groups_in_ou, get_all_ad_groups

        try:
            if policy_config.search_base:
                raw_groups = await get_groups_in_ou(policy_config.search_base)
            else:
                raw_groups = await get_all_ad_groups()
        except Exception as exc:
            return ToolError(code="AD_UNREACHABLE", message=str(exc))

        total = len(raw_groups)
        reviewed = 0
        stale = 0
        unreviewed_list = []
        stale_list = []
        now = datetime.now(timezone.utc)

        for raw in raw_groups:
            dn = raw.get("DistinguishedName", "")
            review = store.get_review(dn)
            if review is None:
                unreviewed_list.append(dn)
            else:
                reviewed += 1
                reviewed_at = review.reviewed_at
                if reviewed_at.tzinfo is None:
                    reviewed_at = reviewed_at.replace(tzinfo=timezone.utc)
                if (now - reviewed_at).days > policy_config.review_recency_days:
                    stale += 1
                    stale_list.append(dn)

        coverage_pct = round(reviewed / total * 100, 1) if total else 0
        return {
            "total_groups": total,
            "reviewed_count": reviewed,
            "unreviewed_count": total - reviewed,
            "coverage_pct": coverage_pct,
            "stale_reviews": stale,
            "unreviewed_groups": unreviewed_list[:50],  # cap at 50 for readability
            "stale_review_groups": stale_list[:50],
        }

    return mcp


def _parse_ad_datetime(value) -> datetime:
    """Best-effort parse of an AD datetime value, falling back to UTC now.

    Handles:
    - ISO 8601 strings ("2024-01-15T10:30:00+00:00")
    - Microsoft JSON dates ("/Date(1350561951000)/")
    - US locale strings ("10/18/2012 2:45:51 PM")
    - Integer epoch milliseconds from ConvertTo-Json
    - None
    """
    import re

    if value is None:
        return datetime.now(timezone.utc)

    val = str(value).strip()

    # Microsoft JSON date format: /Date(1350561951000)/
    ms_match = re.match(r"^/Date\((\d+)\)/$", val)
    if ms_match:
        epoch_ms = int(ms_match.group(1))
        return datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)

    # Raw integer (epoch milliseconds from ConvertTo-Json)
    if val.isdigit() and len(val) >= 10:
        epoch_ms = int(val)
        # If it looks like seconds (10 digits), convert; otherwise ms (13 digits)
        if epoch_ms > 1e12:
            return datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
        return datetime.fromtimestamp(epoch_ms, tz=timezone.utc)

    # ISO 8601
    try:
        return datetime.fromisoformat(val)
    except (ValueError, TypeError):
        pass

    # US locale: "10/18/2012 2:45:51 PM" or "8/4/2025 1:16:48 PM"
    for fmt in (
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S",
        "%Y%m%d%H%M%S.0Z",       # AD generalized time
        "%m/%d/%Y",
    ):
        try:
            dt = datetime.strptime(val, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    return datetime.now(timezone.utc)
