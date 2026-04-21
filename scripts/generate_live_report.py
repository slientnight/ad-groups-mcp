#!/usr/bin/env python3
"""Generate a live HTML audit report by calling the MCP server tools.

This script uses asyncio to call the same AD query functions the MCP
server uses, then feeds the results into the report generator.

Usage:
    python scripts/generate_live_report.py
    python scripts/generate_live_report.py --no-db
"""
import argparse
import asyncio
import logging
import os
import re as _re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ad_groups_mcp.ad_query import get_ad_group, get_groups_in_ou, search_ad_groups
from ad_groups_mcp.config import load_policy_config
from ad_groups_mcp.models import GroupDetail
from ad_groups_mcp.policy_engine import PolicyEngine
from ad_groups_mcp.report import generate_audit_report
from ad_groups_mcp.review_resolver import resolve_review
from ad_groups_mcp.sqlite_store import SQLiteStore

logger = logging.getLogger(__name__)


def parse_ps_date(val):
    """Parse PowerShell date formats including /Date(...)/ and ISO strings."""
    if isinstance(val, dict) and "value" in val:
        val = val["value"]
    if isinstance(val, str):
        m = _re.match(r"/Date\((\d+)\)/", val)
        if m:
            return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc)
        return datetime.fromisoformat(val.replace("Z", "+00:00"))
    return datetime.now(timezone.utc)


async def main(no_db: bool = False):
    policy = load_policy_config("policy.yaml")
    engine = PolicyEngine(policy)
    search_base = policy.search_base or ""
    ou_name = search_base.split(",")[0].replace("OU=", "") if search_base else "Domain"

    print(f"Searching groups in: {search_base or 'entire domain'}")
    if no_db:
        print("Running in --no-db mode: SQLite operations will be skipped")
    raw_groups = await get_groups_in_ou(search_base) if search_base else await search_ad_groups("*")
    print(f"Found {len(raw_groups)} groups")

    # --- SQLite store: only initialise when not in no-db mode ---
    store = None
    if not no_db:
        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reviews.db")
        store = SQLiteStore(db_path)
        store.initialize()

    # --- Collect per-group data ---
    groups = []
    privileged_groups = []

    for idx, rg in enumerate(raw_groups, 1):
        dn = rg.get("DistinguishedName", "")
        sam = rg.get("SamAccountName", dn.split(",")[0].replace("CN=", ""))
        print(f"  [{idx}/{len(raw_groups)}] {sam}")

        try:
            detail_raw = await get_ad_group(sam)
        except Exception as e:
            print(f"    WARN: Could not get details for {sam}: {e}")
            detail_raw = rg

        when_changed = parse_ps_date(detail_raw.get("whenChanged", ""))
        desc = detail_raw.get("Description") or ""
        managed = detail_raw.get("ManagedBy") or ""
        scope = detail_raw.get("GroupScope", "")
        category = detail_raw.get("GroupCategory", "")

        # Member count
        members = detail_raw.get("Members") or detail_raw.get("Member") or []
        if isinstance(members, list):
            member_count = len(members)
        elif isinstance(members, str):
            member_count = 1
        elif isinstance(members, dict) and "Count" in members:
            member_count = members["Count"]
        else:
            member_count = 0

        # Map PowerShell int enums
        scope_map = {0: "DomainLocal", 1: "Global", 2: "Universal"}
        cat_map = {0: "Distribution", 1: "Security"}
        if isinstance(scope, int):
            scope = scope_map.get(scope, str(scope))
        if isinstance(category, int):
            category = cat_map.get(category, str(category))

        group_detail = GroupDetail(
            distinguished_name=dn,
            sam_account_name=sam,
            group_scope=str(scope),
            group_category=str(category),
            description=desc if desc else None,
            managed_by=managed if managed else None,
            when_created=datetime.now(timezone.utc),
            when_changed=when_changed,
            member_count=member_count,
        )

        # --- Review resolution: merge AD attrs + SQLite via resolve_review ---
        ext_attr1 = detail_raw.get("extensionAttribute1") or None
        ext_attr2 = detail_raw.get("extensionAttribute2") or None

        sqlite_review = store.get_review(dn) if store is not None else None
        review, review_source = resolve_review(ext_attr1, ext_attr2, sqlite_review)

        evaluation = engine.evaluate(group_detail, review)
        rules = [{"rule_name": r.rule_name, "passed": r.passed, "message": r.message}
                 for r in evaluation.rules]

        # Stale detection
        now = datetime.now(timezone.utc)
        elapsed_days = (now - when_changed).days if when_changed.tzinfo else (now - when_changed.replace(tzinfo=timezone.utc)).days
        is_stale = elapsed_days > policy.stale_days

        # Privileged detection
        is_priv = engine.is_privileged(sam)

        group_dict = {
            "name": sam,
            "distinguished_name": dn,
            "scope": str(scope),
            "category": str(category),
            "description": desc,
            "managed_by": managed,
            "member_count": member_count,
            "when_changed": when_changed.isoformat(),
            "naming_prefix_ok": not any(r["rule_name"] == "naming" and not r["passed"] for r in rules),
            "naming_format_ok": not any(r["rule_name"] == "naming" and not r["passed"] for r in rules),
            "has_notes_initials": bool(desc and any(c.isdigit() for c in desc)),
            "compliant": evaluation.compliant,
            "rules": rules,
            "is_stale": is_stale,
            "stale_days": elapsed_days,
            "is_privileged": is_priv,
            "review_source": review_source,
            "last_review": {
                "reviewer": review.reviewer,
                "reviewed_at": review.reviewed_at.isoformat(),
            } if review else None,
        }

        # Extract extended attributes from AD
        ext_attrs = {}
        for attr_idx in range(1, 8):
            key = f"extensionAttribute{attr_idx}"
            val = detail_raw.get(key) or ""
            if val:
                ext_attrs[key] = val
        if ext_attrs:
            group_dict["extended_attributes"] = ext_attrs

        groups.append(group_dict)

        # Build privileged group entry
        if is_priv:
            priv_rule = next((r for r in rules if r["rule_name"] == "privileged_review"), None)
            privileged_groups.append({
                "name": sam,
                "distinguished_name": dn,
                "description": desc or None,
                "review_status": priv_rule or {"rule_name": "privileged_review", "passed": False, "message": "No review"},
                "last_review": group_dict["last_review"],
            })

        # Record membership snapshot for drift tracking (only when DB is available)
        if store is not None:
            store.record_snapshot(dn, member_count, "audit-script")

    # --- Review coverage ---
    reviewed_count = sum(1 for g in groups if g["last_review"] is not None)
    review_coverage = {
        "total_groups": len(groups),
        "reviewed_count": reviewed_count,
        "unreviewed_count": len(groups) - reviewed_count,
        "coverage_pct": round(reviewed_count / len(groups) * 100, 1) if groups else 0,
        "stale_reviews": 0,  # could compute based on review_recency_days
    }

    # --- Audit snapshot, trend data, sparklines, drift (DB-only) ---
    trend_data = None
    sparkline_data = None
    drift_data = []

    if store is not None:
        try:
            compliant_count = sum(1 for g in groups if g.get("compliant"))
            compliance_pct = round(compliant_count / len(groups) * 100, 1) if groups else 0
            store.record_audit_snapshot(compliance_pct, len(groups), compliant_count)

            trend_data = store.get_audit_snapshots(limit=30)

            sparkline_data = {}
            for g in groups:
                snaps = store.get_snapshots(g["distinguished_name"])
                if len(snaps) >= 2:
                    sparkline_data[g["distinguished_name"]] = [
                        {"member_count": s.member_count, "snapshot_at": s.snapshot_at.isoformat()}
                        for s in snaps[-10:]
                    ]
            if not sparkline_data:
                sparkline_data = None
        except Exception:
            logger.warning("Failed to record audit snapshot or fetch trend data", exc_info=True)
            trend_data = None
            sparkline_data = None

        # --- Membership drift ---
        for g in groups:
            drift = store.get_membership_drift(g["distinguished_name"])
            if drift:
                drift_data.append(drift)

    print(f"\nGenerating report for {len(groups)} groups...")
    print(f"  Review coverage: {review_coverage['reviewed_count']}/{review_coverage['total_groups']} ({review_coverage['coverage_pct']}%)")
    print(f"  Privileged groups: {len(privileged_groups)}")
    print(f"  Stale groups: {sum(1 for g in groups if g['is_stale'])}")
    print(f"  Drift records: {len(drift_data)}")

    report_html = generate_audit_report(
        groups=groups,
        title="AD Groups SOP Compliance Audit",
        ou_name=ou_name,
        review_coverage=review_coverage,
        privileged_groups=privileged_groups,
        membership_drift=drift_data if drift_data else None,
        trend_data=trend_data,
        sparkline_data=sparkline_data,
        no_db_mode=(store is None),
    )

    output_path = "cec_audit_report.html"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_html)
    print(f"Report written to {output_path}")


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate a live HTML audit report from AD group data.",
    )
    parser.add_argument(
        "--no-db",
        action="store_true",
        help="Skip SQLite database operations; generate report from AD data only",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(main(no_db=args.no_db))
