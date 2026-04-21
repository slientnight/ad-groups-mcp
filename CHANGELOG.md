# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-21

### Changed
- Split repository: standalone audit CLI moved to [ad-group-audit](https://github.com/example-org/ad-group-audit)
- MCP repo now focused exclusively on the MCP server layer
- Shared modules (models, policy_engine, ad_query, report, review_resolver, sqlite_store) marked as copies with sync headers
- Trimmed test suite to MCP-specific tests (server, tools, ACL, events, replication, properties 1-2/9/12)
- Removed `scripts/generate_live_report.py` (replaced by `audit.py` in audit repo)
- Removed GitHub Pages demo report
- Updated README to document repo relationship and shared module sync process

### Added
- 14 MCP tools (5 new since 0.1.0): list_privileged_groups, record_membership_snapshot, get_membership_drift, review_coverage, check_365_sync
- AD-native audit mode using extensionAttribute1/2 for review tracking
- Dual-write governance reviews (AD + SQLite)
- Privileged group detection and quarterly review enforcement
- Stale group detection (configurable via stale_days)
- Membership drift tracking between audit cycles
- Microsoft 365 / Entra ID sync detection
- HTML audit report generator with compliance dashboard
- SOP-compliant group creation via YAML templates
- Review resolver with "most recent wins" merge logic (AD vs SQLite)

## [0.1.0] - 2026-04-17

### Added
- Initial release of AD Groups MCP server
- 9 MCP tools: healthcheck, search_groups, get_group, evaluate_group_policy, audit_group_inventory, get_group_change_events, record_group_review, get_group_review, list_recorded_reviews
- YAML-based policy engine with naming, description, owner, membership, and review recency rules
- ACL auditor for GenericAll, WriteDacl, WriteOwner detection against allow-list
- SQLite governance review store with upsert and listing
- Security event log reader for membership change events (4728, 4729, 4732, 4733, 4756, 4757)
- Replication metadata reader for member attribute changes
- Support for stdio, SSE, and streamable-http transports
- 109 example-based unit tests
- 15 Hypothesis property-based tests covering 12 correctness properties
- Read-only AD access enforced by design (only Get-* cmdlets)
