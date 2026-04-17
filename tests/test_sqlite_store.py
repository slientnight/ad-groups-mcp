"""Unit tests for the SQLite store."""

from __future__ import annotations

import os
import sqlite3
import tempfile

import pytest

from ad_groups_mcp.models import ReviewRecord
from ad_groups_mcp.sqlite_store import SQLiteStore


@pytest.fixture
def tmp_db(tmp_path):
    """Return a path to a temporary SQLite database file."""
    return str(tmp_path / "test_reviews.db")


@pytest.fixture
def store(tmp_db):
    """Return an initialized SQLiteStore."""
    s = SQLiteStore(tmp_db)
    s.initialize()
    return s


class TestInitialize:
    def test_creates_new_database(self, tmp_db):
        """New DB file is created and schema is set up."""
        assert not os.path.exists(tmp_db)
        store = SQLiteStore(tmp_db)
        store.initialize()
        assert os.path.exists(tmp_db)

    def test_wal_mode_enabled(self, tmp_db):
        """WAL journal mode is active after initialization."""
        store = SQLiteStore(tmp_db)
        store.initialize()
        conn = sqlite3.connect(tmp_db)
        mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        conn.close()
        assert mode == "wal"

    def test_existing_valid_db_opens_successfully(self, tmp_db):
        """An existing DB with correct schema can be re-opened."""
        store1 = SQLiteStore(tmp_db)
        store1.initialize()
        store2 = SQLiteStore(tmp_db)
        store2.initialize()  # should not raise

    def test_corrupted_schema_raises(self, tmp_db):
        """A DB with wrong columns raises RuntimeError."""
        conn = sqlite3.connect(tmp_db)
        conn.execute(
            "CREATE TABLE group_reviews (id INTEGER PRIMARY KEY, bad_col TEXT);"
        )
        conn.commit()
        conn.close()
        store = SQLiteStore(tmp_db)
        with pytest.raises(RuntimeError, match="schema verification failed"):
            store.initialize()


class TestRecordReview:
    def test_inserts_new_review(self, store):
        """Recording a review for a new group_dn creates a record."""
        result = store.record_review("CN=TestGroup,DC=example,DC=com", "alice")
        assert isinstance(result, ReviewRecord)
        assert result.group_dn == "CN=TestGroup,DC=example,DC=com"
        assert result.reviewer == "alice"
        assert result.reviewed_at is not None

    def test_upsert_replaces_existing(self, store):
        """Recording a review for the same group_dn replaces the old record."""
        store.record_review("CN=G1,DC=example,DC=com", "alice")
        updated = store.record_review("CN=G1,DC=example,DC=com", "bob")
        assert updated.reviewer == "bob"
        fetched = store.get_review("CN=G1,DC=example,DC=com")
        assert fetched is not None
        assert fetched.reviewer == "bob"


class TestGetReview:
    def test_returns_none_when_missing(self, store):
        """get_review returns None for a group with no review."""
        assert store.get_review("CN=NoSuch,DC=example,DC=com") is None

    def test_returns_matching_record(self, store):
        """get_review returns the correct record."""
        store.record_review("CN=G1,DC=example,DC=com", "alice")
        result = store.get_review("CN=G1,DC=example,DC=com")
        assert result is not None
        assert result.group_dn == "CN=G1,DC=example,DC=com"
        assert result.reviewer == "alice"


class TestListReviews:
    def test_empty_list(self, store):
        """list_reviews returns empty list when no reviews exist."""
        assert store.list_reviews() == []

    def test_returns_all_reviews_ordered(self, store):
        """list_reviews returns all records ordered by reviewed_at desc."""
        import time

        store.record_review("CN=G1,DC=example,DC=com", "alice")
        time.sleep(0.05)
        store.record_review("CN=G2,DC=example,DC=com", "bob")
        reviews = store.list_reviews()
        assert len(reviews) == 2
        # Most recent first
        assert reviews[0].group_dn == "CN=G2,DC=example,DC=com"
        assert reviews[1].group_dn == "CN=G1,DC=example,DC=com"
