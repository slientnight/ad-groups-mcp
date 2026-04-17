# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
