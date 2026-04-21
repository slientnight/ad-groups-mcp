"""HTML audit report generator for AD Groups MCP.

Produces a standalone HTML report with SOP compliance summary
and drill-down details per group, styled with a dark theme.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone


def generate_audit_report(
    groups: list[dict],
    policy_rules: list[str] | None = None,
    title: str = "AD Groups SOP Compliance Audit",
    ou_name: str = "Corp-Groups OU",
    review_coverage: dict | None = None,
    privileged_groups: list[dict] | None = None,
    membership_drift: list[dict] | None = None,
    trend_data: list[dict] | None = None,
    sparkline_data: dict[str, list[dict]] | None = None,
    no_db_mode: bool = False,
) -> str:
    """Generate a standalone HTML audit report.

    Parameters
    ----------
    groups:
        List of group dicts, each with keys: name, scope, category,
        description, managed_by, rules (list of {rule_name, passed, message}),
        compliant (bool).  Optional extra keys: member_count, when_changed,
        is_stale, is_privileged, last_review.
    policy_rules:
        Names of SOP rules to summarize. Defaults to standard set.
    title:
        Report title.
    ou_name:
        OU display name for the header.
    review_coverage:
        Dict with total_groups, reviewed_count, unreviewed_count, coverage_pct,
        stale_reviews.
    privileged_groups:
        List of dicts with name, distinguished_name, description,
        review_status, last_review.
    membership_drift:
        List of dicts with group_dn, previous_count, current_count, delta,
        change_pct, previous_date, current_date.
    trend_data:
        List of audit snapshot dicts for the compliance trend chart.
    sparkline_data:
        Mapping of group DN to list of membership snapshot dicts for
        sparkline rendering in the drift section.

    Returns
    -------
    str
        Complete HTML document as a string.
    """
    if policy_rules is None:
        policy_rules = [
            "scope_universal",
            "type_security",
            "naming_prefix",
            "naming_format",
            "description",
            "notes_initials",
        ]

    total = len(groups)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    now_iso = datetime.now(timezone.utc).isoformat()
    compliant_count = sum(1 for g in groups if g.get("compliant"))

    # Compute summary stats
    summary = _compute_summary(groups, total)

    # Identify stale groups
    stale_groups = [g for g in groups if g.get("is_stale")]

    # Build HTML
    parts = [
        _html_head(title),
        _report_header(title, ou_name, total, now),
    ]

    # No-DB mode banner
    if no_db_mode:
        parts.append(_no_db_banner())

    parts += [
        # Header controls: theme toggle, PDF export, compare button
        '<div style="display:flex;gap:0.75rem;flex-wrap:wrap;margin-bottom:1rem">',
        _theme_toggle_section(),
        _pdf_export_button(),
        _comparison_section(),
        '</div>',
        _nav_section(review_coverage, privileged_groups, stale_groups,
                     None if no_db_mode else membership_drift, groups),
        _stat_cards(total, compliant_count, review_coverage, privileged_groups, stale_groups),
    ]

    # Trend chart — skip in no-DB mode
    if not no_db_mode:
        parts.append(_trend_chart_svg(trend_data or []))

    parts += [
        _summary_table(summary),
        _review_coverage_section(review_coverage),
        _privileged_groups_section(privileged_groups),
        _stale_groups_section(stale_groups),
    ]

    # Membership drift + sparklines — skip in no-DB mode
    if not no_db_mode:
        parts.append(_membership_drift_section(membership_drift, sparkline_data))

    parts += [
        _scope_violations_section(groups),
        _description_missing_section(groups),
        _compliant_groups_section(groups),
        _filter_section(),
        _drilldown_section(groups),
        _report_metadata_json(groups, total, compliant_count, now_iso),
        _html_footer(),
    ]
    return "\n".join(parts)


def _compute_summary(groups: list[dict], total: int) -> list[dict]:
    scope_ok = sum(1 for g in groups if g.get("scope", "").lower() == "universal")
    type_ok = sum(1 for g in groups if g.get("category", "").lower() == "security")
    prefix_ok = sum(1 for g in groups if g.get("naming_prefix_ok", True))
    format_ok = sum(1 for g in groups if g.get("naming_format_ok", True))
    desc_ok = sum(1 for g in groups if g.get("description"))
    notes_ok = sum(1 for g in groups if g.get("has_notes_initials", False))

    def pct(n: int) -> str:
        return f"{round(n / total * 100)}%" if total else "0%"

    return [
        {"rule": "Scope = Universal", "ok": scope_ok, "fail": total - scope_ok, "rate": pct(scope_ok)},
        {"rule": "Type = Security", "ok": type_ok, "fail": total - type_ok, "rate": pct(type_ok)},
        {"rule": "Naming (correct prefix)", "ok": prefix_ok, "fail": total - prefix_ok, "rate": pct(prefix_ok)},
        {"rule": "Naming follows <code>Prefix-System/Function_Role/Access</code> format", "ok": format_ok, "fail": total - format_ok, "rate": pct(format_ok)},
        {"rule": "Description field populated", "ok": desc_ok, "fail": total - desc_ok, "rate": pct(desc_ok)},
        {"rule": "Notes with author initials &amp; date", "ok": notes_ok, "fail": total - notes_ok, "rate": pct(notes_ok)},
    ]


def _html_head(title: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root {{
  --bg: #1a1a2e;
  --surface: #16213e;
  --surface2: #0f3460;
  --text: #e0e0e0;
  --text-muted: #8892a4;
  --accent: #4fc3f7;
  --green: #66bb6a;
  --red: #ef5350;
  --yellow: #ffa726;
  --border: #2a2a4a;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  padding: 2rem;
}}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ font-size: 1.5rem; font-weight: 600; margin-bottom: 0.25rem; }}
h2 {{ font-size: 1.15rem; font-weight: 600; margin: 2rem 0 1rem; color: var(--accent); }}
h3 {{ font-size: 1rem; font-weight: 500; margin: 1.5rem 0 0.75rem; }}
.subtitle {{ color: var(--text-muted); font-size: 0.9rem; margin-bottom: 2rem; }}
table {{ width: 100%; border-collapse: collapse; margin-bottom: 1.5rem; }}
th {{
  text-align: left; padding: 0.75rem 1rem; font-weight: 600; font-size: 0.85rem;
  color: var(--text-muted); border-bottom: 2px solid var(--border);
  text-transform: uppercase; letter-spacing: 0.05em;
}}
td {{
  padding: 0.65rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.9rem;
}}
tr:hover {{ background: rgba(79, 195, 247, 0.05); }}
.rule-name {{ font-weight: 600; }}
code {{
  background: var(--surface2); padding: 0.15rem 0.4rem; border-radius: 3px;
  font-size: 0.82rem; font-family: 'Cascadia Code', 'Fira Code', monospace;
}}
.badge {{
  display: inline-block; padding: 0.15rem 0.6rem; border-radius: 10px;
  font-size: 0.78rem; font-weight: 600;
}}
.badge-pass {{ background: rgba(102, 187, 106, 0.15); color: var(--green); }}
.badge-fail {{ background: rgba(239, 83, 80, 0.15); color: var(--red); }}
.badge-warn {{ background: rgba(255, 167, 38, 0.15); color: var(--yellow); }}
.rate-good {{ color: var(--green); font-weight: 600; }}
.rate-warn {{ color: var(--yellow); font-weight: 600; }}
.rate-bad {{ color: var(--red); font-weight: 600; }}
details {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 6px; margin-bottom: 0.5rem;
}}
details[open] {{ border-color: var(--accent); }}
summary {{
  padding: 0.75rem 1rem; cursor: pointer; font-size: 0.9rem;
  display: flex; align-items: center; gap: 0.75rem;
}}
summary:hover {{ background: rgba(79, 195, 247, 0.05); }}
summary::marker {{ color: var(--accent); }}
.detail-body {{ padding: 0 1rem 1rem; }}
.detail-body table {{ margin-bottom: 0.5rem; }}
.detail-meta {{ color: var(--text-muted); font-size: 0.82rem; }}
.stat-row {{ display: flex; gap: 2rem; margin-bottom: 1.5rem; flex-wrap: wrap; }}
.stat-card {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; padding: 1.25rem 1.5rem; min-width: 160px; flex: 1;
}}
.stat-value {{ font-size: 2rem; font-weight: 700; }}
.stat-label {{ color: var(--text-muted); font-size: 0.82rem; margin-top: 0.25rem; }}
.group-name {{ font-weight: 600; flex: 1; }}
.group-status {{ font-size: 0.82rem; }}
.section-list {{ list-style: none; padding: 0; }}
.section-list li {{
  padding: 0.4rem 0; border-bottom: 1px solid var(--border);
  font-size: 0.88rem; display: flex; justify-content: space-between;
}}
.section-list li:last-child {{ border-bottom: none; }}
.nav-bar {{
  background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
  padding: 0.75rem 1rem; margin-bottom: 1.5rem; display: flex; flex-wrap: wrap; gap: 0.5rem;
}}
.nav-bar a {{
  color: var(--accent); text-decoration: none; font-size: 0.82rem; padding: 0.3rem 0.7rem;
  border-radius: 4px; background: var(--surface2); transition: background 0.2s;
}}
.nav-bar a:hover {{ background: rgba(79, 195, 247, 0.15); }}
footer {{
  margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
  color: var(--text-muted); font-size: 0.8rem; text-align: center;
}}
{_theme_css()}
{_print_css()}
</style>
</head>
<body>
<div class="container">"""


def _report_header(title: str, ou_name: str, total: int, timestamp: str) -> str:
    return f"""
<h1>{html.escape(title)}</h1>
<p class="subtitle">{html.escape(ou_name)} &mdash; {total} groups &mdash; Generated {timestamp}</p>
"""


def _no_db_banner() -> str:
    """Return a warning banner indicating the report was generated in No-DB mode."""
    return (
        '<div class="no-db-banner" style="background:rgba(255,167,38,0.15);'
        "border:1px solid var(--yellow);border-radius:8px;padding:1rem;"
        'margin-bottom:1.5rem;color:var(--yellow);font-weight:600;font-size:0.9rem">'
        "Report generated in No-DB mode \u2014 trend charts, sparklines, "
        "and drift data are unavailable."
        "</div>"
    )


def _nav_section(review_coverage, privileged_groups, stale_groups, membership_drift, groups) -> str:
    """Build a clickable navigation bar linking to each report section."""
    links = ['<a href="#compliance">Overall Compliance</a>']
    if review_coverage:
        links.append('<a href="#review-coverage">Review Coverage</a>')
    if privileged_groups:
        links.append('<a href="#privileged">Privileged Groups</a>')
    if stale_groups:
        links.append('<a href="#stale">Stale Groups</a>')
    if membership_drift:
        links.append('<a href="#drift">Membership Drift</a>')
    scope_bad = [g for g in groups if g.get("scope", "").lower() != "universal"]
    if scope_bad:
        links.append('<a href="#scope-violations">Scope Violations</a>')
    desc_missing = [g for g in groups if not g.get("description")]
    if desc_missing:
        links.append('<a href="#missing-desc">Missing Descriptions</a>')
    links.append('<a href="#group-details">Group Details</a>')
    return f'<nav class="nav-bar">{"".join(links)}</nav>'


def _stat_cards(total: int, compliant: int, review_coverage: dict | None,
                privileged_groups: list[dict] | None, stale_groups: list[dict]) -> str:
    non_compliant = total - compliant
    compliance_pct = round(compliant / total * 100) if total else 0

    reviewed = 0
    review_pct = 0.0
    if review_coverage:
        reviewed = review_coverage.get("reviewed_count", 0)
        review_pct = review_coverage.get("coverage_pct", 0.0)

    priv_count = len(privileged_groups) if privileged_groups else 0
    priv_reviewed = 0
    if privileged_groups:
        priv_reviewed = sum(1 for p in privileged_groups
                           if p.get("review_status", {}).get("passed", False))

    stale_count = len(stale_groups)

    compliance_class = "rate-good" if compliance_pct >= 80 else ("rate-warn" if compliance_pct >= 50 else "rate-bad")
    review_class = "rate-good" if review_pct >= 80 else ("rate-warn" if review_pct >= 50 else "rate-bad")
    stale_class = "rate-good" if stale_count == 0 else ("rate-warn" if stale_count <= 5 else "rate-bad")

    return f"""<div class="stat-row">
  <div class="stat-card">
    <div class="stat-value {compliance_class}">{compliant}/{total}</div>
    <div class="stat-label">Policy Compliant</div>
  </div>
  <div class="stat-card">
    <div class="stat-value {review_class}">{reviewed}/{total}</div>
    <div class="stat-label">Reviews Completed ({round(review_pct)}%)</div>
  </div>
  <div class="stat-card">
    <div class="stat-value" style="color: var(--accent)">{priv_count}</div>
    <div class="stat-label">Privileged Groups ({priv_reviewed} reviewed)</div>
  </div>
  <div class="stat-card">
    <div class="stat-value {stale_class}">{stale_count}</div>
    <div class="stat-label">Stale Groups (&gt;2yr)</div>
  </div>
</div>"""


def _rate_class(rate_str: str) -> str:
    try:
        val = int(rate_str.replace("%", "").replace("~", ""))
    except ValueError:
        return "rate-warn"
    if val >= 90:
        return "rate-good"
    if val >= 60:
        return "rate-warn"
    return "rate-bad"


def _summary_table(summary: list[dict]) -> str:
    rows = ""
    for s in summary:
        rc = _rate_class(s["rate"])
        rows += f"""<tr>
  <td class="rule-name">{s['rule']}</td>
  <td style="text-align:center">{s['ok']}</td>
  <td style="text-align:center">{s['fail']}</td>
  <td style="text-align:center" class="{rc}">{s['rate']}</td>
</tr>\n"""

    return f"""<h2 id="compliance">Overall Compliance</h2>
<table>
<thead><tr>
  <th>SOP Rule</th>
  <th style="text-align:center">Compliant</th>
  <th style="text-align:center">Non-Compliant</th>
  <th style="text-align:center">Rate</th>
</tr></thead>
<tbody>
{rows}</tbody>
</table>"""


def _review_coverage_section(review_coverage: dict | None) -> str:
    if not review_coverage:
        return ""
    total = review_coverage.get("total_groups", 0)
    reviewed = review_coverage.get("reviewed_count", 0)
    unreviewed = review_coverage.get("unreviewed_count", 0)
    pct = review_coverage.get("coverage_pct", 0.0)
    stale = review_coverage.get("stale_reviews", 0)

    bar_color = "var(--green)" if pct >= 80 else ("var(--yellow)" if pct >= 50 else "var(--red)")

    return f"""<h2 id="review-coverage">Review Coverage</h2>
<div style="margin-bottom:1rem">
  <div style="display:flex;justify-content:space-between;font-size:0.85rem;margin-bottom:0.3rem">
    <span>{reviewed} of {total} groups reviewed</span>
    <span style="font-weight:600">{round(pct)}%</span>
  </div>
  <div style="background:var(--border);border-radius:6px;height:20px;overflow:hidden">
    <div style="background:{bar_color};height:100%;width:{pct}%;border-radius:6px;transition:width 0.3s"></div>
  </div>
  <div style="display:flex;gap:2rem;margin-top:0.5rem;font-size:0.82rem;color:var(--text-muted)">
    <span>Unreviewed: <strong style="color:var(--red)">{unreviewed}</strong></span>
    <span>Stale reviews: <strong style="color:var(--yellow)">{stale}</strong></span>
  </div>
</div>"""


def _privileged_groups_section(privileged_groups: list[dict] | None) -> str:
    if not privileged_groups:
        return ""
    rows = ""
    for pg in privileged_groups:
        name = html.escape(pg.get("name", ""))
        desc = html.escape(pg.get("description") or "") or "<em>None</em>"
        rs = pg.get("review_status", {})
        passed = rs.get("passed", False)
        msg = html.escape(rs.get("message", ""))
        badge = (
            '<span class="badge badge-pass">CURRENT</span>'
            if passed
            else '<span class="badge badge-fail">OVERDUE</span>'
        )
        lr = pg.get("last_review")
        review_info = "Never reviewed"
        if lr:
            reviewed_at = str(lr.get("reviewed_at", "?"))[:10]
            review_info = html.escape(f"{lr.get('reviewer', '?')} on {reviewed_at}")
        rows += f"""<tr>
  <td><code>{name}</code></td>
  <td class="detail-meta">{desc}</td>
  <td style="text-align:center">{badge}</td>
  <td class="detail-meta">{review_info}</td>
</tr>\n"""

    return f"""<h2 id="privileged">Privileged Groups ({len(privileged_groups)} groups requiring quarterly review)</h2>
<table>
<thead><tr>
  <th>Group</th><th>Description</th>
  <th style="text-align:center">Review Status</th><th>Last Review</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>"""


def _stale_groups_section(stale_groups: list[dict]) -> str:
    if not stale_groups:
        return ""
    rows = ""
    for g in stale_groups:
        name = html.escape(g.get("name", ""))
        days = g.get("stale_days", "?")
        mc = g.get("member_count", "?")
        desc = html.escape(g.get("description") or "") or "<em>None</em>"
        rows += f"""<tr>
  <td><code>{name}</code></td>
  <td style="text-align:center" class="rate-bad">{days} days</td>
  <td style="text-align:center">{mc}</td>
  <td class="detail-meta">{desc}</td>
</tr>\n"""

    return f"""<h2 id="stale">Stale Groups ({len(stale_groups)} unchanged &gt;2 years)</h2>
<table>
<thead><tr>
  <th>Group</th><th style="text-align:center">Last Changed</th>
  <th style="text-align:center">Members</th><th>Description</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>"""


def _membership_drift_section(membership_drift: list[dict] | None, sparkline_data: dict[str, list[dict]] | None = None) -> str:
    if not membership_drift:
        return ""
    rows = ""
    for d in membership_drift:
        dn = d.get("group_dn", "")
        name = html.escape(dn.split(",")[0].replace("CN=", "") if "," in dn else dn)
        prev = d.get("previous_count", 0)
        curr = d.get("current_count", 0)
        delta = d.get("delta", 0)
        pct = d.get("change_pct", 0)
        prev_date = html.escape(d.get("previous_date", "?")[:10])
        curr_date = html.escape(d.get("current_date", "?")[:10])

        if delta > 0:
            delta_str = f'<span style="color:var(--yellow)">+{delta} (+{pct}%)</span>'
        elif delta < 0:
            delta_str = f'<span style="color:var(--red)">{delta} ({pct}%)</span>'
        else:
            delta_str = '<span style="color:var(--green)">0 (no change)</span>'

        # Render sparkline if data is available for this group
        sparkline_html = ""
        if sparkline_data and dn in sparkline_data:
            sparkline_html = " " + _sparkline_svg(sparkline_data[dn])

        rows += f"""<tr>
  <td><code>{name}</code>{sparkline_html}</td>
  <td style="text-align:center">{prev} <span class="detail-meta">({prev_date})</span></td>
  <td style="text-align:center">{curr} <span class="detail-meta">({curr_date})</span></td>
  <td style="text-align:center">{delta_str}</td>
</tr>\n"""

    return f"""<h2 id="drift">Membership Drift ({len(membership_drift)} groups with snapshots)</h2>
<table>
<thead><tr>
  <th>Group</th><th style="text-align:center">Previous</th>
  <th style="text-align:center">Current</th><th style="text-align:center">Change</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>"""


def _scope_violations_section(groups: list[dict]) -> str:
    bad = [g for g in groups if g.get("scope", "").lower() != "universal"]
    if not bad:
        return ""
    rows = ""
    for g in bad:
        rows += f"""<li>
  <span><code>{html.escape(g['name'])}</code></span>
  <span class="badge badge-fail">{html.escape(g.get('scope', 'Unknown'))}</span>
</li>\n"""
    return f"""<h2 id="scope-violations">Groups with Wrong Scope (should be Universal)</h2>
<ul class="section-list">{rows}</ul>"""


def _description_missing_section(groups: list[dict]) -> str:
    missing = [g for g in groups if not g.get("description")]
    if not missing:
        return ""
    rows = ""
    for g in missing:
        rows += f"<li><code>{html.escape(g['name'])}</code></li>\n"
    return f"""<h2 id="missing-desc">Groups Missing Description ({len(missing)} of {len(groups)})</h2>
<ul class="section-list">{rows}</ul>"""


def _compliant_groups_section(groups: list[dict]) -> str:
    good = [g for g in groups if g.get("description") and g.get("scope", "").lower() == "universal"]
    if not good:
        return ""
    rows = ""
    for g in good:
        desc = html.escape(g.get("description", ""))
        rows += f"""<tr>
  <td><code>{html.escape(g['name'])}</code></td>
  <td>{desc}</td>
</tr>\n"""
    return f"""<h2>Groups with Good Descriptions</h2>
<table>
<thead><tr><th>Group</th><th>Description</th></tr></thead>
<tbody>{rows}</tbody>
</table>"""


def _drilldown_section(groups: list[dict]) -> str:
    items = ""
    for g in groups:
        name = html.escape(g.get("name", ""))
        scope = html.escape(g.get("scope", ""))
        category = html.escape(g.get("category", ""))
        desc = html.escape(g.get("description", "")) or "<em>None</em>"
        managed = html.escape(g.get("managed_by", "")) or "<em>None</em>"
        compliant = g.get("compliant", False)
        member_count = g.get("member_count", "?")
        stale_days = g.get("stale_days", "")
        is_stale = g.get("is_stale", False)
        is_priv = g.get("is_privileged", False)

        status_badge = (
            '<span class="badge badge-pass">COMPLIANT</span>'
            if compliant
            else '<span class="badge badge-fail">NON-COMPLIANT</span>'
        )

        # Classification badges
        class_badges = ""
        if is_priv:
            class_badges += ' <span class="badge badge-warn">PRIVILEGED</span>'
        if is_stale:
            class_badges += ' <span class="badge badge-fail">STALE</span>'

        # Build rules table if present
        rules_html = ""
        rules = g.get("rules", [])
        if rules:
            rule_rows = ""
            for r in rules:
                rname = html.escape(r.get("rule_name", ""))
                passed = r.get("passed", False)
                msg = html.escape(r.get("message", ""))
                badge = (
                    '<span class="badge badge-pass">PASS</span>'
                    if passed
                    else '<span class="badge badge-fail">FAIL</span>'
                )
                rule_rows += f"""<tr>
  <td>{rname}</td>
  <td style="text-align:center">{badge}</td>
  <td class="detail-meta">{msg}</td>
</tr>\n"""
            rules_html = f"""<table>
<thead><tr><th>Rule</th><th style="text-align:center">Status</th><th>Message</th></tr></thead>
<tbody>{rule_rows}</tbody>
</table>"""

        # Extended attributes section
        ext_attrs = g.get("extended_attributes", {})
        ext_html = ""
        if ext_attrs:
            ext_rows = ""
            attr_map = [
                ("extensionAttribute1", "Last reviewed by"),
                ("extensionAttribute2", "Last reviewed date"),
                ("extensionAttribute5", "Ticket / justification"),
                ("extensionAttribute6", "Classification"),
                ("extensionAttribute7", "Sunset date"),
            ]
            for attr_key, label in attr_map:
                val = ext_attrs.get(attr_key, "")
                if val:
                    ext_rows += f"<tr><td class='detail-meta'>{label}</td><td>{html.escape(str(val))}</td></tr>\n"
            if ext_rows:
                ext_html = f"""<h3 style="font-size:0.82rem;color:var(--accent);margin:0.75rem 0 0.25rem">Extended Attributes</h3>
<table><tbody>{ext_rows}</tbody></table>"""

        # Last review info
        lr = g.get("last_review")
        review_html = ""
        if lr:
            reviewer = html.escape(str(lr.get("reviewer", "?")))
            reviewed_at = html.escape(str(lr.get("reviewed_at", "?"))[:10])
            # Show review source annotation if available
            review_source = g.get("review_source")
            source_label = ""
            if review_source and review_source.lower() not in ("none", ""):
                source_display = {"ad": "AD", "sqlite": "SQLite", "both": "both"}.get(
                    review_source.lower(), html.escape(review_source)
                )
                source_label = f' <span class="detail-meta">(source: {source_display})</span>'
            review_html = f'<p class="detail-meta" style="margin-top:0.5rem">Last review: <strong>{reviewer}</strong> on {reviewed_at}{source_label}</p>'

        stale_info = f" &nbsp;|&nbsp; Last changed: {stale_days} days ago" if stale_days != "" else ""

        items += f"""<details data-group-name="{html.escape(name.lower())}" data-compliant="{'true' if compliant else 'false'}">
<summary>
  <span class="group-name"><code>{name}</code></span>
  <span class="group-status">{status_badge}{class_badges}</span>
</summary>
<div class="detail-body">
  <p class="detail-meta">Scope: <strong>{scope}</strong> &nbsp;|&nbsp; Type: <strong>{category}</strong> &nbsp;|&nbsp; Members: <strong>{member_count}</strong>{stale_info}</p>
  <p class="detail-meta">Owner: {managed}</p>
  <p class="detail-meta" style="margin-bottom:0.75rem">Description: {desc}</p>
  {review_html}
  {rules_html}
  {ext_html}
</div>
</details>\n"""

    return f"""<h2 id="group-details">Group Details (click to expand)</h2>
{items}"""


def _html_footer() -> str:
    return """</div>
<footer>
  Generated by <strong>ad-groups-mcp</strong> &mdash; Read-only AD Group Audit Tool
</footer>
</body>
</html>"""


def _trend_chart_svg(trend_data: list[dict]) -> str:
    """Generate an inline SVG line chart showing compliance_pct over time.

    Parameters
    ----------
    trend_data:
        List of dicts with keys ``compliance_pct`` (float) and
        ``snapshot_at`` (str, ISO timestamp).  Up to 30 data points.

    Returns
    -------
    str
        Self-contained SVG markup, or a fallback message when fewer
        than 2 data points are available.
    """
    if len(trend_data) < 2:
        return (
            '<p style="color:var(--text-muted);font-style:italic;margin:1rem 0">'
            "Insufficient data for trend chart — run more audits to see trends"
            "</p>"
        )

    # Chart dimensions (viewBox-based)
    width = 600
    height = 200
    pad_left = 50
    pad_right = 20
    pad_top = 20
    pad_bottom = 40

    plot_w = width - pad_left - pad_right
    plot_h = height - pad_top - pad_bottom

    n = len(trend_data)

    # Build coordinate lists
    points = []
    circles = []
    labels = []
    for i, d in enumerate(trend_data):
        pct = max(0.0, min(100.0, float(d.get("compliance_pct", 0))))
        x = pad_left + (i / (n - 1)) * plot_w
        y = pad_top + plot_h - (pct / 100.0) * plot_h
        points.append(f"{x:.1f},{y:.1f}")
        circles.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" '
            f'fill="var(--accent)" stroke="var(--bg)" stroke-width="1"/>'
        )
        # X-axis labels: show first, last, and a few in between
        snap_at = str(d.get("snapshot_at", ""))[:10]
        if i == 0 or i == n - 1 or (n > 5 and i == n // 2):
            labels.append(
                f'<text x="{x:.1f}" y="{height - 5}" '
                f'text-anchor="middle" fill="var(--text-muted)" '
                f'font-size="9">{html.escape(snap_at)}</text>'
            )

    polyline_pts = " ".join(points)

    # Y-axis labels (0%, 25%, 50%, 75%, 100%)
    y_labels = []
    y_gridlines = []
    for pct_val in (0, 25, 50, 75, 100):
        y_pos = pad_top + plot_h - (pct_val / 100.0) * plot_h
        y_labels.append(
            f'<text x="{pad_left - 8}" y="{y_pos + 3:.1f}" '
            f'text-anchor="end" fill="var(--text-muted)" '
            f'font-size="9">{pct_val}%</text>'
        )
        y_gridlines.append(
            f'<line x1="{pad_left}" y1="{y_pos:.1f}" '
            f'x2="{width - pad_right}" y2="{y_pos:.1f}" '
            f'stroke="var(--border)" stroke-width="0.5" stroke-dasharray="4,3"/>'
        )

    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" style="max-width:100%;margin:1rem 0">',
        # Gridlines
        "\n".join(y_gridlines),
        # Axes
        f'<line x1="{pad_left}" y1="{pad_top}" '
        f'x2="{pad_left}" y2="{pad_top + plot_h}" '
        f'stroke="var(--text-muted)" stroke-width="1"/>',
        f'<line x1="{pad_left}" y1="{pad_top + plot_h}" '
        f'x2="{width - pad_right}" y2="{pad_top + plot_h}" '
        f'stroke="var(--text-muted)" stroke-width="1"/>',
        # Y-axis labels
        "\n".join(y_labels),
        # Polyline
        f'<polyline points="{polyline_pts}" '
        f'fill="none" stroke="var(--accent)" stroke-width="2" '
        f'stroke-linejoin="round" stroke-linecap="round"/>',
        # Data point circles
        "\n".join(circles),
        # X-axis labels
        "\n".join(labels),
        "</svg>",
    ]
    return "\n".join(svg_parts)


def _sparkline_svg(snapshots: list[dict]) -> str:
    """Generate a small inline SVG sparkline from membership snapshot data.

    Parameters
    ----------
    snapshots:
        List of dicts with keys ``member_count`` (int) and
        ``snapshot_at`` (str, ISO timestamp).  Up to 10 data points.

    Returns
    -------
    str
        Self-contained SVG markup, or empty string when fewer than
        2 snapshots are available.
    """
    if len(snapshots) < 2:
        return ""

    width = 100
    height = 30
    pad = 2

    plot_w = width - 2 * pad
    plot_h = height - 2 * pad

    counts = [int(s.get("member_count", 0)) for s in snapshots]
    min_val = min(counts)
    max_val = max(counts)
    val_range = max_val - min_val if max_val != min_val else 1

    n = len(counts)
    points = []
    circles = []
    for i, c in enumerate(counts):
        x = pad + (i / (n - 1)) * plot_w
        y = pad + plot_h - ((c - min_val) / val_range) * plot_h
        points.append(f"{x:.1f},{y:.1f}")
        circles.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="1.5" '
            f'fill="var(--accent)"/>'
        )

    polyline_pts = " ".join(points)

    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" style="vertical-align:middle">',
        f'<polyline points="{polyline_pts}" '
        f'fill="none" stroke="var(--accent)" stroke-width="1.5" '
        f'stroke-linejoin="round" stroke-linecap="round"/>',
        "\n".join(circles),
        "</svg>",
    ]
    return "\n".join(svg_parts)


def _print_css() -> str:
    """Return a ``@media print`` CSS block for PDF-friendly output.

    Hides interactive controls, forces white background with black text,
    expands all ``<details>`` elements, and inserts page breaks before
    major report sections.
    """
    return """@media print {
  .nav-bar,
  .theme-toggle,
  .filter-section,
  .pdf-export-btn,
  .compare-btn {
    display: none !important;
  }

  body {
    background: #fff !important;
    color: #000 !important;
    padding: 0 !important;
  }

  * {
    background: #fff !important;
    color: #000 !important;
    border-color: #ccc !important;
  }

  .stat-card {
    border: 1px solid #ccc !important;
  }

  .badge-pass {
    background: #e8f5e9 !important;
    color: #2e7d32 !important;
  }

  .badge-fail {
    background: #ffebee !important;
    color: #c62828 !important;
  }

  .badge-warn {
    background: #fff3e0 !important;
    color: #e65100 !important;
  }

  details {
    display: block !important;
    border: 1px solid #ccc !important;
  }

  details > summary {
    pointer-events: none;
  }

  details > .detail-body {
    display: block !important;
  }

  #compliance {
    page-break-before: always;
  }

  #review-coverage {
    page-break-before: always;
  }

  #privileged {
    page-break-before: always;
  }

  #group-details {
    page-break-before: always;
  }

  a {
    text-decoration: none !important;
  }
}"""


def _pdf_export_button() -> str:
    """Return an "Export to PDF" button that invokes ``window.print()``.

    The button is styled using CSS custom properties so it matches
    whichever theme is active.  It is hidden in print output via the
    ``@media print`` rule from :func:`_print_css`.
    """
    return (
        '<button class="pdf-export-btn" onclick="window.print()" '
        'style="background:var(--surface2);color:var(--accent);'
        "border:1px solid var(--border);border-radius:6px;"
        "padding:0.4rem 1rem;cursor:pointer;font-size:0.85rem;"
        'font-weight:600">'
        "&#128438;&#65039; Export to PDF</button>"
    )


def _theme_css() -> str:
    """Return CSS with light theme overrides using ``[data-theme="light"]``.

    Overrides all CSS custom properties (--bg, --surface, --surface2,
    --text, --text-muted, --accent, --border) so the report can switch
    between dark and light palettes via a ``data-theme`` attribute on
    the ``<html>`` element.
    """
    return """[data-theme="light"] {
  --bg: #f5f5f5;
  --surface: #ffffff;
  --surface2: #e8e8e8;
  --text: #1a1a1a;
  --text-muted: #666666;
  --accent: #1976d2;
  --border: #d0d0d0;
}"""


def _theme_toggle_section() -> str:
    """Return a theme toggle button with inline JS for dark/light switching.

    The button toggles the ``data-theme`` attribute on
    ``document.documentElement`` between absent (dark, the default) and
    ``"light"``.  The preference is persisted to ``localStorage`` under
    the key ``"audit-report-theme"`` and restored on page load.

    ``localStorage`` access is wrapped in try/catch for compatibility
    with private browsing modes where storage may be unavailable.
    """
    return """<button class="theme-toggle" onclick="toggleTheme()" style="background:var(--surface2);color:var(--accent);border:1px solid var(--border);border-radius:6px;padding:0.4rem 1rem;cursor:pointer;font-size:0.85rem;font-weight:600">&#127763; Toggle Theme</button>
<script>
(function() {
  function applyTheme(theme) {
    if (theme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
  }
  function getStoredTheme() {
    try { return localStorage.getItem('audit-report-theme'); } catch(e) { return null; }
  }
  function storeTheme(theme) {
    try { localStorage.setItem('audit-report-theme', theme); } catch(e) {}
  }
  var saved = getStoredTheme();
  if (saved) { applyTheme(saved); }
  window.toggleTheme = function() {
    var current = document.documentElement.getAttribute('data-theme');
    var next = current === 'light' ? 'dark' : 'light';
    applyTheme(next);
    storeTheme(next);
  };
})();
</script>"""


def _filter_section() -> str:
    """Return a group filter/search section with inline JS.

    Renders a text input for searching groups by name, three compliance
    filter buttons ("All", "Compliant", "Non-Compliant"), and a count
    display showing visible vs total groups.  The inline ``<script>``
    filters ``<details>`` elements inside ``#group-details`` by their
    ``data-group-name`` (case-insensitive substring) and
    ``data-compliant`` attributes.
    """
    return (
        '<div class="filter-section" style="background:var(--surface);'
        "border:1px solid var(--border);border-radius:8px;padding:1rem;"
        'margin-bottom:1rem;display:flex;flex-wrap:wrap;gap:0.75rem;align-items:center">\n'
        '  <input id="group-filter-input" type="text" '
        'placeholder="Search groups\u2026" style="flex:1;min-width:200px;'
        "padding:0.4rem 0.75rem;border:1px solid var(--border);"
        "border-radius:6px;background:var(--surface2);color:var(--text);"
        'font-size:0.85rem;outline:none">\n'
        '  <div style="display:flex;gap:0.25rem">\n'
        '    <button class="filter-btn" data-filter="all" '
        "style=\"background:var(--accent);color:var(--bg);"
        "border:1px solid var(--border);border-radius:6px;"
        "padding:0.4rem 0.85rem;cursor:pointer;font-size:0.82rem;"
        'font-weight:600">All</button>\n'
        '    <button class="filter-btn" data-filter="compliant" '
        "style=\"background:var(--surface2);color:var(--text);"
        "border:1px solid var(--border);border-radius:6px;"
        "padding:0.4rem 0.85rem;cursor:pointer;font-size:0.82rem;"
        'font-weight:600">Compliant</button>\n'
        '    <button class="filter-btn" data-filter="non-compliant" '
        "style=\"background:var(--surface2);color:var(--text);"
        "border:1px solid var(--border);border-radius:6px;"
        "padding:0.4rem 0.85rem;cursor:pointer;font-size:0.82rem;"
        'font-weight:600">Non-Compliant</button>\n'
        "  </div>\n"
        '  <span id="filter-count" style="color:var(--text-muted);'
        'font-size:0.82rem"></span>\n'
        "</div>\n"
        "<script>\n"
        "(function() {\n"
        "  var input = document.getElementById('group-filter-input');\n"
        "  var countEl = document.getElementById('filter-count');\n"
        "  var activeFilter = 'all';\n"
        "\n"
        "  function getGroupDetails() {\n"
        "    var section = document.getElementById('group-details');\n"
        "    if (!section) return [];\n"
        "    var parent = section.parentElement || section.parentNode;\n"
        "    var all = [];\n"
        "    var sibling = section.nextElementSibling;\n"
        "    while (sibling) {\n"
        "      if (sibling.tagName === 'DETAILS' && sibling.hasAttribute('data-group-name')) {\n"
        "        all.push(sibling);\n"
        "      } else if (sibling.tagName !== 'DETAILS') {\n"
        "        break;\n"
        "      }\n"
        "      sibling = sibling.nextElementSibling;\n"
        "    }\n"
        "    return all;\n"
        "  }\n"
        "\n"
        "  function applyFilters() {\n"
        "    var searchText = (input.value || '').toLowerCase();\n"
        "    var details = getGroupDetails();\n"
        "    var total = details.length;\n"
        "    var visible = 0;\n"
        "    for (var i = 0; i < details.length; i++) {\n"
        "      var el = details[i];\n"
        "      var name = el.getAttribute('data-group-name') || '';\n"
        "      var compliant = el.getAttribute('data-compliant');\n"
        "      var matchesText = name.indexOf(searchText) !== -1;\n"
        "      var matchesCompliance = activeFilter === 'all' ||\n"
        "        (activeFilter === 'compliant' && compliant === 'true') ||\n"
        "        (activeFilter === 'non-compliant' && compliant === 'false');\n"
        "      if (matchesText && matchesCompliance) {\n"
        "        el.style.display = '';\n"
        "        visible++;\n"
        "      } else {\n"
        "        el.style.display = 'none';\n"
        "      }\n"
        "    }\n"
        "    countEl.textContent = 'Showing ' + visible + ' of ' + total + ' groups';\n"
        "  }\n"
        "\n"
        "  function setActiveButton(selected) {\n"
        "    var btns = document.querySelectorAll('.filter-btn');\n"
        "    for (var i = 0; i < btns.length; i++) {\n"
        "      var btn = btns[i];\n"
        "      if (btn.getAttribute('data-filter') === selected) {\n"
        "        btn.style.background = 'var(--accent)';\n"
        "        btn.style.color = 'var(--bg)';\n"
        "      } else {\n"
        "        btn.style.background = 'var(--surface2)';\n"
        "        btn.style.color = 'var(--text)';\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "\n"
        "  input.addEventListener('input', applyFilters);\n"
        "\n"
        "  var btns = document.querySelectorAll('.filter-btn');\n"
        "  for (var i = 0; i < btns.length; i++) {\n"
        "    btns[i].addEventListener('click', function() {\n"
        "      activeFilter = this.getAttribute('data-filter');\n"
        "      setActiveButton(activeFilter);\n"
        "      applyFilters();\n"
        "    });\n"
        "  }\n"
        "\n"
        "  applyFilters();\n"
        "})();\n"
        "</script>"
    )


def _filter_groups(
    groups: list[dict], search_text: str, compliance_filter: str
) -> tuple[list[dict], int]:
    """Filter groups by name substring and compliance status.

    This is a pure Python mirror of the client-side JS filter logic,
    extracted for property-based testing.

    Parameters
    ----------
    groups:
        List of dicts with at least ``name`` (str) and ``compliant`` (bool).
    search_text:
        Case-insensitive substring to match against group names.
    compliance_filter:
        One of ``"all"``, ``"compliant"``, or ``"non-compliant"``.

    Returns
    -------
    tuple[list[dict], int]
        (filtered_list, count) where count == len(filtered_list).
    """
    needle = search_text.lower()
    filtered = [
        g
        for g in groups
        if needle in g["name"].lower()
        and (
            compliance_filter == "all"
            or (compliance_filter == "compliant" and g["compliant"] is True)
            or (compliance_filter == "non-compliant" and g["compliant"] is False)
        )
    ]
    return filtered, len(filtered)


def _report_metadata_json(
    groups: list[dict], total: int, compliant_count: int, now: str
) -> str:
    """Build a JSON metadata block embedded in the HTML report.

    Parameters
    ----------
    groups:
        List of group dicts (same structure as passed to
        ``generate_audit_report``).  Each dict should have at least
        ``name``, ``compliant``, ``member_count``, and ``rules``.
    total:
        Total number of groups.
    compliant_count:
        Number of compliant groups.
    now:
        ISO timestamp string for the ``generated_at`` field.

    Returns
    -------
    str
        An HTML ``<script type="application/json" id="report-metadata">``
        tag containing the serialised metadata.
    """
    compliance_pct = round(compliant_count / total * 100, 1) if total > 0 else 0

    per_group = []
    for g in groups:
        per_group.append({
            "name": g.get("name", ""),
            "compliant": bool(g.get("compliant", False)),
            "member_count": g.get("member_count", 0),
            "rules": [
                {"rule_name": r.get("rule_name", ""), "passed": bool(r.get("passed", False))}
                for r in g.get("rules", [])
            ],
        })

    metadata = {
        "generated_at": now,
        "total_groups": total,
        "compliant_count": compliant_count,
        "compliance_pct": compliance_pct,
        "groups": per_group,
    }

    return (
        '<script type="application/json" id="report-metadata">'
        + json.dumps(metadata)
        + "</script>"
    )


def _comparison_section() -> str:
    """Return a "Compare Reports" button, hidden comparison panel, and inline JS.

    The button triggers a hidden file input.  When a second HTML report
    is selected the inline JavaScript reads it with ``FileReader``,
    extracts the ``<script id="report-metadata">`` JSON via regex, diffs
    the two metadata objects, and renders a comparison summary plus a
    per-group diff table.

    If the loaded file has no valid metadata tag an error message is
    shown instead.
    """
    return (
        # -- Button ----------------------------------------------------------
        '<button class="compare-btn" id="compare-btn" '
        'style="background:var(--surface2);color:var(--accent);'
        "border:1px solid var(--border);border-radius:6px;"
        "padding:0.4rem 1rem;cursor:pointer;font-size:0.85rem;"
        'font-weight:600" onclick="document.getElementById(\'compare-file-input\').click()">'
        "&#128260; Compare Reports</button>\n"
        # -- Hidden file input ------------------------------------------------
        '<input type="file" id="compare-file-input" accept=".html,.htm" '
        'style="display:none">\n'
        # -- Comparison results container (hidden until populated) ------------
        '<div id="comparison-results" style="display:none;margin-top:1.5rem;'
        "background:var(--surface);border:1px solid var(--border);"
        'border-radius:8px;padding:1.25rem"></div>\n'
        # -- Inline script ----------------------------------------------------
        "<script>\n"
        "(function() {\n"
        "  var fileInput = document.getElementById('compare-file-input');\n"
        "  var resultsDiv = document.getElementById('comparison-results');\n"
        "\n"
        "  function getCurrentMetadata() {\n"
        "    var el = document.getElementById('report-metadata');\n"
        "    if (!el) return null;\n"
        "    try { return JSON.parse(el.textContent); } catch(e) { return null; }\n"
        "  }\n"
        "\n"
        "  function extractMetadata(htmlText) {\n"
        "    var re = /<script[^>]*id=\"report-metadata\"[^>]*>([\\s\\S]*?)<\\/script>/;\n"
        "    var m = re.exec(htmlText);\n"
        "    if (!m) return null;\n"
        "    try { return JSON.parse(m[1]); } catch(e) { return null; }\n"
        "  }\n"
        "\n"
        "  function buildGroupMap(groups) {\n"
        "    var map = {};\n"
        "    for (var i = 0; i < groups.length; i++) {\n"
        "      map[groups[i].name] = groups[i];\n"
        "    }\n"
        "    return map;\n"
        "  }\n"
        "\n"
        "  function diffMetadata(current, other) {\n"
        "    var d = {};\n"
        "    d.delta_total = current.total_groups - other.total_groups;\n"
        "    d.delta_compliance = Math.round((current.compliance_pct - other.compliance_pct) * 10) / 10;\n"
        "    var curMap = buildGroupMap(current.groups || []);\n"
        "    var othMap = buildGroupMap(other.groups || []);\n"
        "    var allNames = {};\n"
        "    var k;\n"
        "    for (k in curMap) { allNames[k] = true; }\n"
        "    for (k in othMap) { allNames[k] = true; }\n"
        "    d.newly_compliant = 0;\n"
        "    d.newly_non_compliant = 0;\n"
        "    d.added = [];\n"
        "    d.removed = [];\n"
        "    d.changed = [];\n"
        "    for (k in allNames) {\n"
        "      var inCur = curMap.hasOwnProperty(k);\n"
        "      var inOth = othMap.hasOwnProperty(k);\n"
        "      if (inCur && !inOth) {\n"
        "        d.added.push(k);\n"
        "      } else if (!inCur && inOth) {\n"
        "        d.removed.push(k);\n"
        "      } else {\n"
        "        var cg = curMap[k];\n"
        "        var og = othMap[k];\n"
        "        if (cg.compliant && !og.compliant) d.newly_compliant++;\n"
        "        if (!cg.compliant && og.compliant) d.newly_non_compliant++;\n"
        "        if (cg.compliant !== og.compliant || cg.member_count !== og.member_count) {\n"
        "          d.changed.push({\n"
        "            name: k,\n"
        "            old_compliant: og.compliant,\n"
        "            new_compliant: cg.compliant,\n"
        "            old_members: og.member_count,\n"
        "            new_members: cg.member_count\n"
        "          });\n"
        "        }\n"
        "      }\n"
        "    }\n"
        "    return d;\n"
        "  }\n"
        "\n"
        "  function sign(n) { return n > 0 ? '+' + n : '' + n; }\n"
        "\n"
        "  function renderDiff(diff) {\n"
        "    var h = '<h2 style=\"margin-top:0;color:var(--accent)\">Comparison Summary</h2>';\n"
        "    h += '<div style=\"display:flex;flex-wrap:wrap;gap:1.5rem;margin-bottom:1rem\">';\n"
        "    h += '<div><strong>Total Groups:</strong> ' + sign(diff.delta_total) + '</div>';\n"
        "    h += '<div><strong>Compliance %:</strong> ' + sign(diff.delta_compliance) + '%</div>';\n"
        "    h += '<div><strong>Newly Compliant:</strong> ' + diff.newly_compliant + '</div>';\n"
        "    h += '<div><strong>Newly Non-Compliant:</strong> ' + diff.newly_non_compliant + '</div>';\n"
        "    h += '<div><strong>Added Groups:</strong> ' + diff.added.length + '</div>';\n"
        "    h += '<div><strong>Removed Groups:</strong> ' + diff.removed.length + '</div>';\n"
        "    h += '</div>';\n"
        "\n"
        "    // Added groups\n"
        "    if (diff.added.length) {\n"
        "      h += '<h3 style=\"color:var(--green);margin:0.75rem 0 0.25rem\">Added Groups</h3><ul>';\n"
        "      for (var i = 0; i < diff.added.length; i++) h += '<li>' + diff.added[i] + '</li>';\n"
        "      h += '</ul>';\n"
        "    }\n"
        "    // Removed groups\n"
        "    if (diff.removed.length) {\n"
        "      h += '<h3 style=\"color:var(--red);margin:0.75rem 0 0.25rem\">Removed Groups</h3><ul>';\n"
        "      for (var i = 0; i < diff.removed.length; i++) h += '<li>' + diff.removed[i] + '</li>';\n"
        "      h += '</ul>';\n"
        "    }\n"
        "    // Per-group diff table\n"
        "    if (diff.changed.length) {\n"
        "      h += '<h3 style=\"color:var(--accent);margin:0.75rem 0 0.25rem\">Changed Groups</h3>';\n"
        "      h += '<table style=\"width:100%;border-collapse:collapse\">';\n"
        "      h += '<thead><tr>';\n"
        "      h += '<th style=\"text-align:left;padding:0.5rem;border-bottom:2px solid var(--border)\">Group</th>';\n"
        "      h += '<th style=\"text-align:center;padding:0.5rem;border-bottom:2px solid var(--border)\">Compliance</th>';\n"
        "      h += '<th style=\"text-align:center;padding:0.5rem;border-bottom:2px solid var(--border)\">Members</th>';\n"
        "      h += '</tr></thead><tbody>';\n"
        "      for (var i = 0; i < diff.changed.length; i++) {\n"
        "        var c = diff.changed[i];\n"
        "        var compStr = '';\n"
        "        if (c.old_compliant !== c.new_compliant) {\n"
        "          compStr = (c.old_compliant ? 'Compliant' : 'Non-Compliant') + ' \\u2192 ' + (c.new_compliant ? 'Compliant' : 'Non-Compliant');\n"
        "        } else {\n"
        "          compStr = c.new_compliant ? 'Compliant' : 'Non-Compliant';\n"
        "        }\n"
        "        var memStr = '';\n"
        "        if (c.old_members !== c.new_members) {\n"
        "          memStr = c.old_members + ' \\u2192 ' + c.new_members;\n"
        "        } else {\n"
        "          memStr = '' + c.new_members;\n"
        "        }\n"
        "        h += '<tr>';\n"
        "        h += '<td style=\"padding:0.4rem 0.5rem;border-bottom:1px solid var(--border)\">' + c.name + '</td>';\n"
        "        h += '<td style=\"text-align:center;padding:0.4rem 0.5rem;border-bottom:1px solid var(--border)\">' + compStr + '</td>';\n"
        "        h += '<td style=\"text-align:center;padding:0.4rem 0.5rem;border-bottom:1px solid var(--border)\">' + memStr + '</td>';\n"
        "        h += '</tr>';\n"
        "      }\n"
        "      h += '</tbody></table>';\n"
        "    }\n"
        "\n"
        "    if (!diff.added.length && !diff.removed.length && !diff.changed.length) {\n"
        "      h += '<p style=\"color:var(--text-muted);font-style:italic\">No differences found between the two reports.</p>';\n"
        "    }\n"
        "    return h;\n"
        "  }\n"
        "\n"
        "  fileInput.addEventListener('change', function() {\n"
        "    var file = fileInput.files[0];\n"
        "    if (!file) return;\n"
        "    var reader = new FileReader();\n"
        "    reader.onload = function(e) {\n"
        "      var text = e.target.result;\n"
        "      var otherMeta = extractMetadata(text);\n"
        "      if (!otherMeta) {\n"
        "        resultsDiv.style.display = 'block';\n"
        "        resultsDiv.innerHTML = '<p style=\"color:var(--red);font-weight:600\">' +\n"
        "          'Selected file is not a valid audit report or was generated before comparison support was added.' +\n"
        "          '</p>';\n"
        "        return;\n"
        "      }\n"
        "      var currentMeta = getCurrentMetadata();\n"
        "      if (!currentMeta) {\n"
        "        resultsDiv.style.display = 'block';\n"
        "        resultsDiv.innerHTML = '<p style=\"color:var(--red)\">Current report metadata not found.</p>';\n"
        "        return;\n"
        "      }\n"
        "      var diff = diffMetadata(currentMeta, otherMeta);\n"
        "      resultsDiv.style.display = 'block';\n"
        "      resultsDiv.innerHTML = renderDiff(diff);\n"
        "    };\n"
        "    reader.readAsText(file);\n"
        "    fileInput.value = '';\n"
        "  });\n"
        "})();\n"
        "</script>"
    )


def _diff_metadata(current: dict, other: dict) -> dict:
    """Compute the diff between two report metadata objects.

    This is a pure Python mirror of the client-side JS ``diffMetadata``
    function in :func:`_comparison_section`, extracted for property-based
    testing.

    Parameters
    ----------
    current:
        Metadata dict with keys ``total_groups`` (int),
        ``compliance_pct`` (float), and ``groups`` (list of dicts each
        with ``name``, ``compliant``, ``member_count``).
    other:
        Same structure as *current*.

    Returns
    -------
    dict
        Keys:

        - ``delta_total``: current.total_groups − other.total_groups
        - ``delta_compliance``: rounded to 1 decimal place
        - ``newly_compliant``: count of groups non-compliant in *other*
          but compliant in *current*
        - ``newly_non_compliant``: count of groups compliant in *other*
          but non-compliant in *current*
        - ``added``: list of group names in *current* but not *other*
        - ``removed``: list of group names in *other* but not *current*
        - ``changed``: list of dicts for groups whose compliance status
          or member_count changed, each with ``name``,
          ``old_compliant``, ``new_compliant``, ``old_members``,
          ``new_members``
    """
    delta_total = current["total_groups"] - other["total_groups"]
    delta_compliance = round(current["compliance_pct"] - other["compliance_pct"], 1)

    cur_map = {g["name"]: g for g in (current.get("groups") or [])}
    oth_map = {g["name"]: g for g in (other.get("groups") or [])}

    all_names = set(cur_map) | set(oth_map)

    newly_compliant = 0
    newly_non_compliant = 0
    added: list[str] = []
    removed: list[str] = []
    changed: list[dict] = []

    for name in all_names:
        in_cur = name in cur_map
        in_oth = name in oth_map

        if in_cur and not in_oth:
            added.append(name)
        elif not in_cur and in_oth:
            removed.append(name)
        else:
            cg = cur_map[name]
            og = oth_map[name]
            if cg["compliant"] and not og["compliant"]:
                newly_compliant += 1
            if not cg["compliant"] and og["compliant"]:
                newly_non_compliant += 1
            if cg["compliant"] != og["compliant"] or cg["member_count"] != og["member_count"]:
                changed.append({
                    "name": name,
                    "old_compliant": og["compliant"],
                    "new_compliant": cg["compliant"],
                    "old_members": og["member_count"],
                    "new_members": cg["member_count"],
                })

    return {
        "delta_total": delta_total,
        "delta_compliance": delta_compliance,
        "newly_compliant": newly_compliant,
        "newly_non_compliant": newly_non_compliant,
        "added": added,
        "removed": removed,
        "changed": changed,
    }


# ---------------------------------------------------------------------------
# Convenience: generate a demo report with anonymized sample data
# ---------------------------------------------------------------------------

def generate_demo_report() -> str:
    """Generate a demo report with anonymized sample data."""
    groups = [
        {
            "name": "ACME-Endpoint-Admins",
            "scope": "Universal",
            "category": "Security",
            "description": "Members of this group have admin access to the endpoint management console.",
            "managed_by": "CN=jsmith,OU=Users,DC=corp,DC=example,DC=com",
            "member_count": 5,
            "naming_prefix_ok": True,
            "naming_format_ok": True,
            "has_notes_initials": True,
            "compliant": True,
            "is_stale": False,
            "stale_days": 30,
            "is_privileged": True,
            "last_review": {"reviewer": "jsmith", "reviewed_at": "2026-03-20T10:00:00+00:00"},
            "review_source": "ad",
            "extended_attributes": {
                "extensionAttribute1": "jsmith",
                "extensionAttribute2": "2026-03-20",
            },
            "rules": [
                {"rule_name": "naming", "passed": True, "message": "Name matches naming convention"},
                {"rule_name": "description", "passed": True, "message": "Description is present"},
                {"rule_name": "owner", "passed": True, "message": "Owner (managedBy) is assigned"},
                {"rule_name": "membership", "passed": True, "message": "Member count (5) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": True, "message": "Review is recent (30 days ago, within 365-day window)"},
                {"rule_name": "stale_group", "passed": True, "message": "Group is active (last changed 30 days ago)"},
                {"rule_name": "privileged_review", "passed": True, "message": "Privileged review is current (30 days ago, within 90-day window)"},
            ],
        },
        {
            "name": "ACME-ITS-Server-Admin",
            "scope": "Universal",
            "category": "Security",
            "description": "Admin access for server management. JS 12/11/25",
            "managed_by": "",
            "member_count": 3,
            "naming_prefix_ok": True,
            "naming_format_ok": True,
            "has_notes_initials": True,
            "compliant": False,
            "is_stale": False,
            "stale_days": 39,
            "is_privileged": True,
            "last_review": None,
            "review_source": "none",
            "rules": [
                {"rule_name": "naming", "passed": True, "message": "Name matches naming convention"},
                {"rule_name": "description", "passed": True, "message": "Description is present"},
                {"rule_name": "owner", "passed": False, "message": "Owner (managedBy) is missing or empty"},
                {"rule_name": "membership", "passed": True, "message": "Member count (3) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": False, "message": "No governance review recorded"},
                {"rule_name": "stale_group", "passed": True, "message": "Group is active (last changed 39 days ago)"},
                {"rule_name": "privileged_review", "passed": False, "message": "Privileged group has no governance review (required every 90 days)"},
            ],
        },
        {
            "name": "ACME-VPN-Users",
            "scope": "Universal",
            "category": "Security",
            "description": "",
            "managed_by": "",
            "member_count": 42,
            "naming_prefix_ok": True,
            "naming_format_ok": True,
            "has_notes_initials": False,
            "compliant": False,
            "is_stale": False,
            "stale_days": 120,
            "is_privileged": False,
            "last_review": None,
            "review_source": "none",
            "rules": [
                {"rule_name": "naming", "passed": True, "message": "Name matches naming convention"},
                {"rule_name": "description", "passed": False, "message": "Description is missing or empty"},
                {"rule_name": "owner", "passed": False, "message": "Owner (managedBy) is missing or empty"},
                {"rule_name": "membership", "passed": True, "message": "Member count (42) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": False, "message": "No governance review recorded"},
                {"rule_name": "stale_group", "passed": True, "message": "Group is active (last changed 120 days ago)"},
            ],
        },
        {
            "name": "ACME-Grad-Students",
            "scope": "Global",
            "category": "Security",
            "description": "",
            "managed_by": "",
            "member_count": 87,
            "naming_prefix_ok": True,
            "naming_format_ok": True,
            "has_notes_initials": False,
            "compliant": False,
            "is_stale": False,
            "stale_days": 219,
            "is_privileged": False,
            "last_review": None,
            "review_source": "none",
            "rules": [
                {"rule_name": "naming", "passed": True, "message": "Name matches naming convention"},
                {"rule_name": "description", "passed": False, "message": "Description is missing or empty"},
                {"rule_name": "owner", "passed": False, "message": "Owner (managedBy) is missing or empty"},
                {"rule_name": "membership", "passed": True, "message": "Member count (87) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": False, "message": "No governance review recorded"},
                {"rule_name": "stale_group", "passed": True, "message": "Group is active (last changed 219 days ago)"},
            ],
        },
        {
            "name": "ACME-ADMIN",
            "scope": "Universal",
            "category": "Security",
            "description": "",
            "managed_by": "",
            "member_count": 4,
            "naming_prefix_ok": True,
            "naming_format_ok": False,
            "has_notes_initials": False,
            "compliant": False,
            "is_stale": True,
            "stale_days": 870,
            "is_privileged": True,
            "last_review": None,
            "rules": [
                {"rule_name": "naming", "passed": False, "message": "Name 'ACME-ADMIN' does not follow Prefix-System-Role format"},
                {"rule_name": "description", "passed": False, "message": "Description is missing or empty"},
                {"rule_name": "owner", "passed": False, "message": "Owner (managedBy) is missing or empty"},
                {"rule_name": "membership", "passed": True, "message": "Member count (4) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": False, "message": "No governance review recorded"},
                {"rule_name": "stale_group", "passed": False, "message": "Group is stale (last changed 870 days ago, exceeds 730-day threshold)"},
                {"rule_name": "privileged_review", "passed": False, "message": "Privileged group has no governance review (required every 90 days)"},
            ],
        },
        {
            "name": "ACME-MDM-Admin",
            "scope": "Universal",
            "category": "Security",
            "description": "Members of this group have admin access to the MDM platform.",
            "managed_by": "",
            "member_count": 6,
            "naming_prefix_ok": True,
            "naming_format_ok": True,
            "has_notes_initials": False,
            "compliant": False,
            "is_stale": False,
            "stale_days": 239,
            "is_privileged": True,
            "last_review": None,
            "rules": [
                {"rule_name": "naming", "passed": True, "message": "Name matches naming convention"},
                {"rule_name": "description", "passed": True, "message": "Description is present"},
                {"rule_name": "owner", "passed": False, "message": "Owner (managedBy) is missing or empty"},
                {"rule_name": "membership", "passed": True, "message": "Member count (6) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": False, "message": "No governance review recorded"},
                {"rule_name": "stale_group", "passed": True, "message": "Group is active (last changed 239 days ago)"},
                {"rule_name": "privileged_review", "passed": False, "message": "Privileged group has no governance review (required every 90 days)"},
            ],
        },
        {
            "name": "ACME-Lab-Computers",
            "scope": "Global",
            "category": "Security",
            "description": "Legacy computer lab group. Retire when feasible.",
            "managed_by": "",
            "member_count": 120,
            "naming_prefix_ok": True,
            "naming_format_ok": False,
            "has_notes_initials": False,
            "compliant": False,
            "is_stale": True,
            "stale_days": 800,
            "is_privileged": False,
            "last_review": None,
            "rules": [
                {"rule_name": "naming", "passed": False, "message": "Name 'ACME-Lab-Computers' does not follow Prefix-System-Role format"},
                {"rule_name": "description", "passed": True, "message": "Description is present"},
                {"rule_name": "owner", "passed": False, "message": "Owner (managedBy) is missing or empty"},
                {"rule_name": "membership", "passed": True, "message": "Member count (120) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": False, "message": "No governance review recorded"},
                {"rule_name": "stale_group", "passed": False, "message": "Group is stale (last changed 800 days ago, exceeds 730-day threshold)"},
            ],
        },
        {
            "name": "ACME-SECOPS-MDE-RBAC",
            "scope": "Universal",
            "category": "Security",
            "description": "Members of this group have access to security operations tools.",
            "managed_by": "CN=secops-lead,OU=Users,DC=corp,DC=example,DC=com",
            "member_count": 6,
            "naming_prefix_ok": True,
            "naming_format_ok": True,
            "has_notes_initials": True,
            "compliant": True,
            "is_stale": False,
            "stale_days": 15,
            "is_privileged": True,
            "last_review": {"reviewer": "secops-lead", "reviewed_at": "2026-04-05T10:00:00+00:00"},
            "rules": [
                {"rule_name": "naming", "passed": True, "message": "Name matches naming convention"},
                {"rule_name": "description", "passed": True, "message": "Description is present"},
                {"rule_name": "owner", "passed": True, "message": "Owner (managedBy) is assigned"},
                {"rule_name": "membership", "passed": True, "message": "Member count (6) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": True, "message": "Review is recent (15 days ago, within 365-day window)"},
                {"rule_name": "stale_group", "passed": True, "message": "Group is active (last changed 15 days ago)"},
                {"rule_name": "privileged_review", "passed": True, "message": "Privileged review is current (15 days ago, within 90-day window)"},
            ],
        },
        {
            "name": "ACME-Password-Solution-Access",
            "scope": "Universal",
            "category": "Security",
            "description": "",
            "managed_by": "",
            "member_count": 1,
            "naming_prefix_ok": True,
            "naming_format_ok": True,
            "has_notes_initials": False,
            "compliant": False,
            "is_stale": True,
            "stale_days": 900,
            "is_privileged": False,
            "last_review": None,
            "rules": [
                {"rule_name": "naming", "passed": True, "message": "Name matches naming convention"},
                {"rule_name": "description", "passed": False, "message": "Description is missing or empty"},
                {"rule_name": "owner", "passed": False, "message": "Owner (managedBy) is missing or empty"},
                {"rule_name": "membership", "passed": True, "message": "Member count (1) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": False, "message": "No governance review recorded"},
                {"rule_name": "stale_group", "passed": False, "message": "Group is stale (last changed 900 days ago, exceeds 730-day threshold)"},
            ],
        },
        {
            "name": "ACME-Audit-Testing-Admin",
            "scope": "Universal",
            "category": "Security",
            "description": "Admin access for audit and compliance testing tools.",
            "managed_by": "CN=jsmith,OU=Users,DC=corp,DC=example,DC=com",
            "member_count": 2,
            "naming_prefix_ok": True,
            "naming_format_ok": True,
            "has_notes_initials": True,
            "compliant": True,
            "is_stale": False,
            "stale_days": 0,
            "is_privileged": True,
            "last_review": {"reviewer": "jsmith", "reviewed_at": "2026-04-20T14:30:00+00:00"},
            "extended_attributes": {
                "extensionAttribute1": "jsmith",
                "extensionAttribute2": "2026-04-20",
            },
            "rules": [
                {"rule_name": "naming", "passed": True, "message": "Name matches naming convention"},
                {"rule_name": "description", "passed": True, "message": "Description is present"},
                {"rule_name": "owner", "passed": True, "message": "Owner (managedBy) is assigned"},
                {"rule_name": "membership", "passed": True, "message": "Member count (2) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": True, "message": "Review is recent (0 days ago, within 365-day window)"},
                {"rule_name": "stale_group", "passed": True, "message": "Group is active (last changed 0 days ago)"},
                {"rule_name": "privileged_review", "passed": True, "message": "Privileged review is current (0 days ago, within 90-day window)"},
            ],
        },
    ]

    # Build privileged groups list
    privileged_groups = []
    for g in groups:
        if g.get("is_privileged"):
            priv_rule = next((r for r in g["rules"] if r["rule_name"] == "privileged_review"), None)
            privileged_groups.append({
                "name": g["name"],
                "distinguished_name": f"CN={g['name']},OU=Corp-Groups,DC=corp,DC=example,DC=com",
                "description": g.get("description") or None,
                "review_status": priv_rule or {"rule_name": "privileged_review", "passed": False, "message": "No review"},
                "last_review": g.get("last_review"),
            })

    # Review coverage
    reviewed_count = sum(1 for g in groups if g.get("last_review"))
    review_coverage = {
        "total_groups": len(groups),
        "reviewed_count": reviewed_count,
        "unreviewed_count": len(groups) - reviewed_count,
        "coverage_pct": round(reviewed_count / len(groups) * 100, 1),
        "stale_reviews": 0,
    }

    # Membership drift
    membership_drift = [
        {
            "group_dn": "CN=ACME-Audit-Testing-Admin,OU=Corp-Groups,DC=corp,DC=example,DC=com",
            "previous_count": 0,
            "previous_date": "2026-04-20T14:30:00+00:00",
            "current_count": 2,
            "current_date": "2026-04-20T14:36:00+00:00",
            "delta": 2,
            "change_pct": 0,
        },
        {
            "group_dn": "CN=ACME-VPN-Users,OU=Corp-Groups,DC=corp,DC=example,DC=com",
            "previous_count": 38,
            "previous_date": "2026-01-15T10:00:00+00:00",
            "current_count": 42,
            "current_date": "2026-04-20T10:00:00+00:00",
            "delta": 4,
            "change_pct": 10.5,
        },
    ]

    return generate_audit_report(
        groups=groups,
        title="AD Groups SOP Compliance Audit",
        ou_name="Corp-Groups OU",
        review_coverage=review_coverage,
        privileged_groups=privileged_groups,
        membership_drift=membership_drift,
    )


if __name__ == "__main__":
    report = generate_demo_report()
    with open("audit_report_demo.html", "w", encoding="utf-8") as f:
        f.write(report)
    print("Demo report written to audit_report_demo.html")
