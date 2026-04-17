"""HTML audit report generator for AD Groups MCP.

Produces a standalone HTML report with SOP compliance summary
and drill-down details per group, styled with a dark theme.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone


def generate_audit_report(
    groups: list[dict],
    policy_rules: list[str] | None = None,
    title: str = "AD Groups SOP Compliance Audit",
    ou_name: str = "Corp-Groups OU",
) -> str:
    """Generate a standalone HTML audit report.

    Parameters
    ----------
    groups:
        List of group dicts, each with keys: name, scope, category,
        description, managed_by, rules (list of {rule_name, passed, message}),
        compliant (bool).
    policy_rules:
        Names of SOP rules to summarize. Defaults to standard set.
    title:
        Report title.
    ou_name:
        OU display name for the header.

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

    # Compute summary stats
    summary = _compute_summary(groups, total)

    # Build HTML
    parts = [
        _html_head(title),
        _report_header(title, ou_name, total, now),
        _summary_table(summary),
        _scope_violations_section(groups),
        _description_missing_section(groups),
        _compliant_groups_section(groups),
        _drilldown_section(groups),
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
footer {{
  margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
  color: var(--text-muted); font-size: 0.8rem; text-align: center;
}}
</style>
</head>
<body>
<div class="container">"""


def _report_header(title: str, ou_name: str, total: int, timestamp: str) -> str:
    compliant_example = 8  # placeholder; real impl would compute
    return f"""
<h1>{html.escape(title)}</h1>
<p class="subtitle">{html.escape(ou_name)} &mdash; {total} groups &mdash; Generated {timestamp}</p>
"""


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

    return f"""<h2>Overall Compliance</h2>
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
    return f"""<h2>Groups with Wrong Scope (should be Universal)</h2>
<ul class="section-list">{rows}</ul>"""


def _description_missing_section(groups: list[dict]) -> str:
    missing = [g for g in groups if not g.get("description")]
    if not missing:
        return ""
    rows = ""
    for g in missing:
        rows += f"<li><code>{html.escape(g['name'])}</code></li>\n"
    return f"""<h2>Groups Missing Description ({len(missing)} of {len(groups)})</h2>
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

        status_badge = (
            '<span class="badge badge-pass">COMPLIANT</span>'
            if compliant
            else '<span class="badge badge-fail">NON-COMPLIANT</span>'
        )

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

        items += f"""<details>
<summary>
  <span class="group-name"><code>{name}</code></span>
  <span class="group-status">{status_badge}</span>
</summary>
<div class="detail-body">
  <p class="detail-meta">Scope: <strong>{scope}</strong> &nbsp;|&nbsp; Type: <strong>{category}</strong> &nbsp;|&nbsp; Owner: {managed}</p>
  <p class="detail-meta" style="margin-bottom:0.75rem">Description: {desc}</p>
  {rules_html}
</div>
</details>\n"""

    return f"""<h2>Group Details (click to expand)</h2>
{items}"""


def _html_footer() -> str:
    return """</div>
<footer>
  Generated by <strong>ad-groups-mcp</strong> &mdash; Read-only AD Group Audit Tool
</footer>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Convenience: generate a demo report with anonymized sample data
# ---------------------------------------------------------------------------

def generate_demo_report() -> str:
    """Generate a demo report with anonymized sample data."""
    groups = [
        {
            "name": "ACME-BigFix_Admins",
            "scope": "Universal",
            "category": "Security",
            "description": "Members of this group have access to BigFix console and web for endpoint management.",
            "managed_by": "CN=jsmith,OU=Users,DC=corp,DC=example,DC=com",
            "naming_prefix_ok": True,
            "naming_format_ok": True,
            "has_notes_initials": True,
            "compliant": True,
            "rules": [
                {"rule_name": "naming", "passed": True, "message": "Name matches naming convention"},
                {"rule_name": "description", "passed": True, "message": "Description is present"},
                {"rule_name": "owner", "passed": True, "message": "Owner (managedBy) is assigned"},
                {"rule_name": "membership", "passed": True, "message": "Member count (5) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": True, "message": "Review is recent (30 days ago, within 365-day window)"},
            ],
        },
        {
            "name": "ACME-ITS-Server_Admin",
            "scope": "Universal",
            "category": "Security",
            "description": "Admin account used for server admins. JS 12/11/25",
            "managed_by": "",
            "naming_prefix_ok": True,
            "naming_format_ok": True,
            "has_notes_initials": True,
            "compliant": False,
            "rules": [
                {"rule_name": "naming", "passed": True, "message": "Name matches naming convention"},
                {"rule_name": "description", "passed": True, "message": "Description is present"},
                {"rule_name": "owner", "passed": False, "message": "Owner (managedBy) is missing or empty"},
                {"rule_name": "membership", "passed": True, "message": "Member count (3) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": False, "message": "No governance review recorded"},
            ],
        },
        {
            "name": "ACME-VPN_Users",
            "scope": "Universal",
            "category": "Security",
            "description": "",
            "managed_by": "",
            "naming_prefix_ok": True,
            "naming_format_ok": True,
            "has_notes_initials": False,
            "compliant": False,
            "rules": [
                {"rule_name": "naming", "passed": True, "message": "Name matches naming convention"},
                {"rule_name": "description", "passed": False, "message": "Description is missing or empty"},
                {"rule_name": "owner", "passed": False, "message": "Owner (managedBy) is missing or empty"},
                {"rule_name": "membership", "passed": True, "message": "Member count (42) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": False, "message": "No governance review recorded"},
            ],
        },
        {
            "name": "ACME-CSE_Grads",
            "scope": "Global",
            "category": "Security",
            "description": "",
            "managed_by": "",
            "naming_prefix_ok": True,
            "naming_format_ok": True,
            "has_notes_initials": False,
            "compliant": False,
            "rules": [
                {"rule_name": "naming", "passed": True, "message": "Name matches naming convention"},
                {"rule_name": "description", "passed": False, "message": "Description is missing or empty"},
                {"rule_name": "owner", "passed": False, "message": "Owner (managedBy) is missing or empty"},
                {"rule_name": "membership", "passed": True, "message": "Member count (87) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": False, "message": "No governance review recorded"},
            ],
        },
        {
            "name": "ACME-ADMIN",
            "scope": "Universal",
            "category": "Security",
            "description": "",
            "managed_by": "",
            "naming_prefix_ok": True,
            "naming_format_ok": False,
            "has_notes_initials": False,
            "compliant": False,
            "rules": [
                {"rule_name": "naming", "passed": False, "message": "Name 'ACME-ADMIN' does not follow Prefix-System_Role format"},
                {"rule_name": "description", "passed": False, "message": "Description is missing or empty"},
                {"rule_name": "owner", "passed": False, "message": "Owner (managedBy) is missing or empty"},
                {"rule_name": "membership", "passed": True, "message": "Member count (4) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": False, "message": "No governance review recorded"},
            ],
        },
        {
            "name": "ACME-INTUNE_Admin",
            "scope": "Universal",
            "category": "Security",
            "description": "Members of this group will have access to machines & info in Intune (Admin Role)",
            "managed_by": "",
            "naming_prefix_ok": True,
            "naming_format_ok": True,
            "has_notes_initials": False,
            "compliant": False,
            "rules": [
                {"rule_name": "naming", "passed": True, "message": "Name matches naming convention"},
                {"rule_name": "description", "passed": True, "message": "Description is present"},
                {"rule_name": "owner", "passed": False, "message": "Owner (managedBy) is missing or empty"},
                {"rule_name": "membership", "passed": True, "message": "Member count (3) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": False, "message": "No governance review recorded"},
            ],
        },
        {
            "name": "ACME-LabComputers",
            "scope": "Global",
            "category": "Security",
            "description": "Legacy Computer Lab group. Retire when feasible.",
            "managed_by": "",
            "naming_prefix_ok": True,
            "naming_format_ok": False,
            "has_notes_initials": False,
            "compliant": False,
            "rules": [
                {"rule_name": "naming", "passed": False, "message": "Name 'ACME-LabComputers' does not follow Prefix-System_Role format"},
                {"rule_name": "description", "passed": True, "message": "Description is present"},
                {"rule_name": "owner", "passed": False, "message": "Owner (managedBy) is missing or empty"},
                {"rule_name": "membership", "passed": True, "message": "Member count (120) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": False, "message": "No governance review recorded"},
            ],
        },
        {
            "name": "ACME-SECOPS-365-MDE_RBAC",
            "scope": "Universal",
            "category": "Security",
            "description": "Members of this group will have access to machines & info in M365 Defender for Endpoint",
            "managed_by": "CN=secops-lead,OU=Users,DC=corp,DC=example,DC=com",
            "naming_prefix_ok": True,
            "naming_format_ok": True,
            "has_notes_initials": True,
            "compliant": True,
            "rules": [
                {"rule_name": "naming", "passed": True, "message": "Name matches naming convention"},
                {"rule_name": "description", "passed": True, "message": "Description is present"},
                {"rule_name": "owner", "passed": True, "message": "Owner (managedBy) is assigned"},
                {"rule_name": "membership", "passed": True, "message": "Member count (6) is within threshold (500)"},
                {"rule_name": "review_recency", "passed": True, "message": "Review is recent (15 days ago, within 365-day window)"},
            ],
        },
    ]

    return generate_audit_report(
        groups=groups,
        title="AD Groups SOP Compliance Audit",
        ou_name="Corp-Groups OU",
    )


if __name__ == "__main__":
    report = generate_demo_report()
    with open("audit_report_demo.html", "w", encoding="utf-8") as f:
        f.write(report)
    print("Demo report written to audit_report_demo.html")
