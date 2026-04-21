"""SQLite database layer for governance review records."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from ad_groups_mcp.models import AuditSnapshot, MembershipSnapshot, ReviewRecord

EXPECTED_COLUMNS = {"id", "group_dn", "reviewer", "reviewed_at"}

CREATE_TABLE_SQL = """\
CREATE TABLE IF NOT EXISTS group_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_dn TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    reviewed_at TEXT NOT NULL,
    UNIQUE(group_dn)
);
"""

CREATE_SNAPSHOTS_SQL = """\
CREATE TABLE IF NOT EXISTS membership_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_dn TEXT NOT NULL,
    member_count INTEGER NOT NULL,
    snapshot_at TEXT NOT NULL,
    reviewer TEXT NOT NULL
);
"""

CREATE_AUDIT_SNAPSHOTS_SQL = """\
CREATE TABLE IF NOT EXISTS audit_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    compliance_pct REAL NOT NULL,
    total_groups INTEGER NOT NULL,
    compliant_count INTEGER NOT NULL,
    snapshot_at TEXT NOT NULL
);
"""


class SQLiteStore:
    """Manages a local SQLite database for persisting governance review records."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None

    def initialize(self) -> None:
        """Create the database, enable WAL mode, create schema, and verify integrity."""
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute(CREATE_TABLE_SQL)
        self._conn.execute(CREATE_SNAPSHOTS_SQL)
        self._conn.execute(CREATE_AUDIT_SNAPSHOTS_SQL)
        self._conn.commit()
        self._verify_schema()

    def _verify_schema(self) -> None:
        """Check that the group_reviews table exists with the expected columns."""
        assert self._conn is not None
        cursor = self._conn.execute("PRAGMA table_info(group_reviews);")
        rows = cursor.fetchall()
        if not rows:
            raise RuntimeError(
                "SQLite schema verification failed: group_reviews table is missing"
            )
        actual_columns = {row["name"] for row in rows}
        if actual_columns != EXPECTED_COLUMNS:
            raise RuntimeError(
                f"SQLite schema verification failed: expected columns {EXPECTED_COLUMNS}, "
                f"got {actual_columns}"
            )

    def record_review(self, group_dn: str, reviewer: str) -> ReviewRecord:
        """Record a governance review via INSERT OR REPLACE (upsert on group_dn)."""
        assert self._conn is not None
        now = datetime.now(timezone.utc)
        reviewed_at_iso = now.isoformat()
        self._conn.execute(
            "INSERT OR REPLACE INTO group_reviews (group_dn, reviewer, reviewed_at) "
            "VALUES (?, ?, ?);",
            (group_dn, reviewer, reviewed_at_iso),
        )
        self._conn.commit()
        return ReviewRecord(group_dn=group_dn, reviewer=reviewer, reviewed_at=now)

    def get_review(self, group_dn: str) -> ReviewRecord | None:
        """Return the most recent ReviewRecord for a group, or None."""
        assert self._conn is not None
        cursor = self._conn.execute(
            "SELECT group_dn, reviewer, reviewed_at FROM group_reviews "
            "WHERE group_dn = ? ORDER BY reviewed_at DESC LIMIT 1;",
            (group_dn,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return ReviewRecord(
            group_dn=row["group_dn"],
            reviewer=row["reviewer"],
            reviewed_at=datetime.fromisoformat(row["reviewed_at"]),
        )

    def list_reviews(self) -> list[ReviewRecord]:
        """Return all ReviewRecords ordered by reviewed_at descending."""
        assert self._conn is not None
        cursor = self._conn.execute(
            "SELECT group_dn, reviewer, reviewed_at FROM group_reviews "
            "ORDER BY reviewed_at DESC;"
        )
        return [
            ReviewRecord(
                group_dn=row["group_dn"],
                reviewer=row["reviewer"],
                reviewed_at=datetime.fromisoformat(row["reviewed_at"]),
            )
            for row in cursor.fetchall()
        ]

    # ------------------------------------------------------------------
    # Membership snapshots
    # ------------------------------------------------------------------

    def record_snapshot(self, group_dn: str, member_count: int, reviewer: str) -> MembershipSnapshot:
        """Record a membership count snapshot for drift tracking."""
        assert self._conn is not None
        now = datetime.now(timezone.utc)
        self._conn.execute(
            "INSERT INTO membership_snapshots (group_dn, member_count, snapshot_at, reviewer) "
            "VALUES (?, ?, ?, ?);",
            (group_dn, member_count, now.isoformat(), reviewer),
        )
        self._conn.commit()
        return MembershipSnapshot(
            group_dn=group_dn, member_count=member_count, snapshot_at=now, reviewer=reviewer,
        )

    def get_snapshots(self, group_dn: str) -> list[MembershipSnapshot]:
        """Return all membership snapshots for a group, oldest first."""
        assert self._conn is not None
        cursor = self._conn.execute(
            "SELECT group_dn, member_count, snapshot_at, reviewer "
            "FROM membership_snapshots WHERE group_dn = ? ORDER BY snapshot_at ASC;",
            (group_dn,),
        )
        return [
            MembershipSnapshot(
                group_dn=row["group_dn"],
                member_count=row["member_count"],
                snapshot_at=datetime.fromisoformat(row["snapshot_at"]),
                reviewer=row["reviewer"],
            )
            for row in cursor.fetchall()
        ]

    def get_membership_drift(self, group_dn: str) -> dict | None:
        """Compare latest two snapshots and return drift info, or None if < 2 snapshots."""
        snapshots = self.get_snapshots(group_dn)
        if len(snapshots) < 2:
            return None
        prev = snapshots[-2]
        curr = snapshots[-1]
        delta = curr.member_count - prev.member_count
        pct = (delta / prev.member_count * 100) if prev.member_count > 0 else 0
        return {
            "group_dn": group_dn,
            "previous_count": prev.member_count,
            "previous_date": prev.snapshot_at.isoformat(),
            "current_count": curr.member_count,
            "current_date": curr.snapshot_at.isoformat(),
            "delta": delta,
            "change_pct": round(pct, 1),
        }

    # ------------------------------------------------------------------
    # Audit snapshots
    # ------------------------------------------------------------------

    def record_audit_snapshot(
        self, compliance_pct: float, total_groups: int, compliant_count: int
    ) -> dict:
        """Record aggregate audit metrics for trend tracking."""
        assert self._conn is not None
        now = datetime.now(timezone.utc)
        self._conn.execute(
            "INSERT INTO audit_snapshots (compliance_pct, total_groups, compliant_count, snapshot_at) "
            "VALUES (?, ?, ?, ?);",
            (compliance_pct, total_groups, compliant_count, now.isoformat()),
        )
        self._conn.commit()
        return {
            "compliance_pct": compliance_pct,
            "total_groups": total_groups,
            "compliant_count": compliant_count,
            "snapshot_at": now.isoformat(),
        }

    def get_audit_snapshots(self, limit: int = 30) -> list[dict]:
        """Return the most recent `limit` audit snapshots, oldest first."""
        assert self._conn is not None
        cursor = self._conn.execute(
            "SELECT compliance_pct, total_groups, compliant_count, snapshot_at "
            "FROM audit_snapshots ORDER BY id DESC LIMIT ?;",
            (limit,),
        )
        rows = [
            {
                "compliance_pct": row["compliance_pct"],
                "total_groups": row["total_groups"],
                "compliant_count": row["compliant_count"],
                "snapshot_at": row["snapshot_at"],
            }
            for row in cursor.fetchall()
        ]
        rows.reverse()  # oldest first
        return rows
