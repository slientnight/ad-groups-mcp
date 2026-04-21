# AD Groups MCP Server

A read-only Active Directory group management MCP (Model Context Protocol) server built with [FastMCP](https://gofastmcp.com/). Provides tools for AD group search, policy evaluation, ACL auditing, and governance review tracking.

## Requirements

- Python 3.11+
- Windows host with the Active Directory PowerShell module (RSAT)
- Domain-joined machine with read access to AD

## Install

```bash
pip install -e ".[dev]"
```

## Run

```bash
# stdio (default)
python -m ad_groups_mcp

# SSE
python -m ad_groups_mcp --transport sse

# Streamable HTTP
python -m ad_groups_mcp --transport streamable-http

# Custom policy and DB path
python -m ad_groups_mcp --policy-file custom_policy.yaml --db-path /path/to/reviews.db
```

## MCP Client Configuration

### Kiro / Claude Code (JSON)
```json
{
  "mcpServers": {
    "ad-groups-mcp": {
      "command": "python",
      "args": ["-m", "ad_groups_mcp"],
      "cwd": "/path/to/ad-groups-mcp"
    }
  }
}
```

### OpenAI Codex (TOML)
```toml
[mcp_servers.ad-groups-mcp]
command = "python"
args = ["-m", "ad_groups_mcp"]
cwd = "/path/to/ad-groups-mcp"
```

## Tools

| Tool | Description |
|---|---|
| `healthcheck` | Verify AD connectivity |
| `search_groups` | Search AD groups by name |
| `get_group` | Get full group details with 3 timestamps, AD-native review data (extensionAttribute1/2) with review source tracking |
| `evaluate_group_policy` | Evaluate a group against policy rules (includes stale detection + privileged review) |
| `audit_group_inventory` | Bulk audit all groups in the configured OU |
| `get_group_change_events` | Query security event log for membership changes |
| `record_group_review` | Record a governance review (dual-write to AD + SQLite) |
| `get_group_review` | Get latest review for a group |
| `list_recorded_reviews` | List all recorded reviews |
| `list_privileged_groups` | List groups matching Admin/Server/LAPS/RBAC/Root with review status |
| `record_membership_snapshot` | Snapshot member count for drift tracking |
| `get_membership_drift` | Compare snapshots to detect membership drift |
| `review_coverage` | Dashboard showing reviewed vs unreviewed groups |
| `check_365_sync` | Check which groups are synced to Microsoft 365 / Entra ID |

## Policy Configuration

Copy the example and customize for your environment:

```bash
cp policy.yaml.example policy.yaml
```

Edit `policy.yaml` to customize rules:

```yaml
naming_regex: "^[A-Z]{4,8}[-_].+"
# Format: {OrgPrefix}-{System/Dept}-{Role}
# New groups SHOULD use dashes: Prefix-System-Role
max_members: 500
review_recency_days: 365
stale_days: 730
privileged_keywords:
  - "Admin"
  - "Server"
  - "LAPS"
  - "RBAC"
  - "Root"
privileged_review_days: 90
acl_allow_list:
  - "Domain Admins"
  - "Enterprise Admins"
# Scope queries to a specific OU (leave empty for entire domain)
search_base: "OU=MyGroups,OU=MyOrg,DC=example,DC=com"

# Optional: Map logical review fields to AD extended attribute names.
# Defaults shown below — only needed if your environment uses different attribute slots.
# extended_attribute_mapping:
#   reviewed_by: extensionAttribute1
#   reviewed_date: extensionAttribute2
```

## AD-Native Audit Mode

The server reads governance review data from two sources:

1. **AD Extended Attributes** (primary): `extensionAttribute1` (reviewer) and `extensionAttribute2` (review date in `YYYY-MM-DD`)
2. **SQLite Database** (enrichment): Local `reviews.db` for membership snapshots, trend charts, and drift tracking

When both sources have review data for a group, the **most recent review wins**. On same-date ties, AD takes priority.

### DB-Free Reporting

Generate compliance reports without any SQLite dependency:

```bash
python scripts/generate_live_report.py --no-db
```

This mode evaluates all core compliance rules (naming, description, owner, membership, review recency, stale detection, privileged review) using only AD data. Trend charts, sparklines, and drift tracking are omitted.

### Dual-Write

When recording a review via `record_group_review`, the tool writes to both AD (`extensionAttribute1`/`extensionAttribute2`) and SQLite. Partial failures produce warnings rather than errors.

## Tests

```bash
# All tests
pytest tests/ -v

# Unit tests only
pytest tests/ -v --ignore=tests/test_properties.py

# Property-based tests only
pytest tests/test_properties.py -v
```

## Example Output

### Get Group Details

```json
{
  "distinguished_name": "CN=ACME-Endpoint-Admins,OU=Corp-Groups,OU=ACME,DC=corp,DC=example,DC=com",
  "sam_account_name": "ACME-Endpoint-Admins",
  "group_scope": "Universal",
  "group_category": "Security",
  "description": "Members of this group have access to endpoint management console and web.",
  "managed_by": "CN=jsmith,OU=Users,DC=corp,DC=example,DC=com",
  "when_created": "2024-09-12T14:30:00+00:00",
  "when_changed": "2025-11-03T09:15:22+00:00",
  "member_count": 5,
  "replication_metadata": {
    "last_originating_change_time": "2025-11-03T09:15:22+00:00",
    "last_originating_change_dc": "CN=DC01,CN=Servers,DC=corp,DC=example,DC=com",
    "originating_change_principal": "CORP\\jsmith"
  },
  "last_review": {
    "group_dn": "CN=ACME-Endpoint-Admins,OU=Corp-Groups,OU=ACME,DC=corp,DC=example,DC=com",
    "reviewer": "admin@example.com",
    "reviewed_at": "2025-10-01T10:00:00+00:00"
  },
  "extension_attribute_1": "admin@example.com",
  "extension_attribute_2": "2025-10-01",
  "review_source": "ad"
}
```

### Policy Evaluation

```json
{
  "group_dn": "CN=ACME-TestGroup,OU=Corp-Groups,OU=ACME,DC=corp,DC=example,DC=com",
  "rules": [
    { "rule_name": "naming",          "passed": false, "message": "Name 'ACME-TestGroup' does not match pattern '^(SEC|DL|APP)_.*'" },
    { "rule_name": "description",     "passed": false, "message": "Description is missing or empty" },
    { "rule_name": "owner",           "passed": false, "message": "Owner (managedBy) is missing or empty" },
    { "rule_name": "membership",      "passed": true,  "message": "Member count (12) is within threshold (500)" },
    { "rule_name": "review_recency",  "passed": false, "message": "No governance review recorded" }
  ],
  "compliant": false
}
```

### Bulk Inventory Audit

```json
{
  "total_groups": 57,
  "compliant_count": 8,
  "violation_count": 46,
  "errors": [
    "CN=ACME-Legacy_Group,OU=Corp-Groups,DC=corp,DC=example,DC=com: PowerShell error (exit 1): Object not found"
  ],
  "per_group_violations": [
    {
      "group_dn": "CN=ACME-VPN_Users,OU=Corp-Groups,DC=corp,DC=example,DC=com",
      "rules": [
        { "rule_name": "description",    "passed": false, "message": "Description is missing or empty" },
        { "rule_name": "owner",          "passed": false, "message": "Owner (managedBy) is missing or empty" },
        { "rule_name": "review_recency", "passed": false, "message": "No governance review recorded" }
      ],
      "compliant": false
    }
  ]
}
```

### Record Governance Review

```json
{
  "group_dn": "CN=ACME-Endpoint-Admins,OU=Corp-Groups,OU=ACME,DC=corp,DC=example,DC=com",
  "reviewer": "admin@example.com",
  "reviewed_at": "2026-04-17T15:30:00+00:00",
  "warnings": []
}
```

## HTML Audit Report

Generate a standalone HTML compliance report with drill-down details per group:

```bash
# Generate a demo report with anonymized sample data
python -m ad_groups_mcp.report
```

View the [live demo report](https://slientnight.github.io/ad-groups-mcp/demo_report.html) to see all audit capabilities including:

- Overview dashboard with compliance stats
- Review coverage progress tracking
- Privileged group focus list with quarterly review status
- Stale group detection (groups unchanged >2 years)
- Membership drift tracking between audit cycles
- Per-group policy evaluation with expandable rule details
- Full tool reference (14 MCP tools)

To generate a live report from real AD data:

```bash
# Full report with SQLite (default — includes trend charts, sparklines, drift)
python scripts/generate_live_report.py

# DB-free report (uses only AD extended attributes for review data)
python scripts/generate_live_report.py --no-db
```

To generate a report from real audit data:

```python
from ad_groups_mcp.report import generate_audit_report

report_html = generate_audit_report(
    groups=your_group_data,
    title="Q2 2026 SOP Compliance Audit",
    ou_name="Corp-Groups OU",
    no_db_mode=False,  # Set True to omit trend/drift sections
)
with open("audit_q2_2026.html", "w") as f:
    f.write(report_html)
```

## SOP-Compliant Group Creation

Use the YAML template to generate PowerShell scripts for creating AD groups that comply with your SOP:

1. Copy `templates/new-group.yaml`
2. Fill in the fields (prefix, system, role, owner, etc.)
3. Paste the filled YAML into the AI chat
4. Receive a complete PowerShell script with `New-ADGroup`, description, notes, and all extended attributes set

The group name is auto-built from `{prefix}-{system}-{role}`. If the description is left blank, it is auto-generated from the filled fields.

```yaml
# templates/new-group.yaml
prefix: "ACME"
system: "VPN"
role: "Users"
description: ""           # auto-generates: "Members of this group have Users access to VPN"
owner_dn: "CN=jsmith,OU=Users,DC=example,DC=com"
target_ou: "OU=MyGroups,OU=MyOrg,DC=example,DC=com"
created_by: "jsmith"
created_date: "2026-04-20"
initials: "JS"
classification: "standard"
ticket: "ITS-1234"
sunset_date: "2027-04-20"
```

The generated PowerShell sets all required attributes including:
- `Description` and `Info` (Notes) for human-readable documentation
- `extensionAttribute1-7` for machine-readable audit metadata (creator, reviewer, ticket, classification, sunset date)
- `ManagedBy` for ownership tracking

After running the PowerShell, use the MCP tools `record_group_review` and `record_membership_snapshot` to baseline the group in the audit system.

## Architecture

- **ad_query.py** — PowerShell subprocess wrappers (read-only `Get-*` cmdlets only), includes OU-scoped queries
- **policy_engine.py** — YAML-based policy evaluation with stale detection and privileged group rules
- **sqlite_store.py** — Local SQLite for governance reviews and membership snapshots (only write path)
- **acl_auditor.py** — nTSecurityDescriptor parsing and allow-list evaluation
- **event_reader.py** — Windows Security event log queries
- **replication.py** — AD replication metadata for membership changes
- **server.py** — FastMCP tool registration (14 tools)
- **report.py** — HTML audit report generator
- **review_resolver.py** — Pure-function module for merging review data from AD extended attributes and SQLite ("most recent wins" logic)
