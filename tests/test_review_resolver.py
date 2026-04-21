"""Unit tests for ad_groups_mcp.review_resolver — pure function module."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ad_groups_mcp.models import ReviewRecord
from ad_groups_mcp.review_resolver import (
    build_review_from_ad,
    parse_review_date,
    resolve_review,
)


# ---------------------------------------------------------------------------
# parse_review_date
# ---------------------------------------------------------------------------

class TestParseReviewDate:
    def test_valid_date(self):
        result = parse_review_date("2025-01-15")
        assert result == datetime(2025, 1, 15, tzinfo=timezone.utc)

    def test_returns_timezone_aware(self):
        result = parse_review_date("2024-06-01")
        assert result is not None
        assert result.tzinfo is not None

    def test_none_input(self):
        assert parse_review_date(None) is None

    def test_empty_string(self):
        assert parse_review_date("") is None

    def test_malformed_date(self):
        assert parse_review_date("not-a-date") is None

    def test_wrong_format_slash(self):
        assert parse_review_date("2025/01/15") is None

    def test_wrong_format_day_month(self):
        assert parse_review_date("15-01-2025") is None

    def test_partial_date(self):
        assert parse_review_date("2025-01") is None

    def test_invalid_month(self):
        assert parse_review_date("2025-13-01") is None

    def test_invalid_day(self):
        assert parse_review_date("2025-02-30") is None


# ---------------------------------------------------------------------------
# build_review_from_ad
# ---------------------------------------------------------------------------

class TestBuildReviewFromAd:
    def test_valid_inputs(self):
        record = build_review_from_ad("jsmith", "2025-07-01")
        assert record is not None
        assert record.reviewer == "jsmith"
        assert record.reviewed_at == datetime(2025, 7, 1, tzinfo=timezone.utc)
        assert record.group_dn == ""

    def test_missing_date_returns_none(self):
        assert build_review_from_ad("jsmith", None) is None

    def test_empty_date_returns_none(self):
        assert build_review_from_ad("jsmith", "") is None

    def test_malformed_date_returns_none(self):
        assert build_review_from_ad("jsmith", "bad") is None

    def test_missing_reviewer_uses_empty_string(self):
        record = build_review_from_ad(None, "2025-07-01")
        assert record is not None
        assert record.reviewer == ""

    def test_empty_reviewer_uses_empty_string(self):
        record = build_review_from_ad("", "2025-07-01")
        assert record is not None
        assert record.reviewer == ""


# ---------------------------------------------------------------------------
# resolve_review
# ---------------------------------------------------------------------------

class TestResolveReview:
    """Tests for the merge logic in resolve_review."""

    def _make_sqlite_review(self, date_str: str, reviewer: str = "dbuser") -> ReviewRecord:
        return ReviewRecord(
            group_dn="CN=TestGroup,OU=MyGroups,DC=example,DC=com",
            reviewer=reviewer,
            reviewed_at=datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc),
        )

    # -- neither source --
    def test_no_sources_returns_none(self):
        review, source = resolve_review(None, None, None)
        assert review is None
        assert source == "none"

    # -- AD only --
    def test_ad_only(self):
        review, source = resolve_review("jsmith", "2025-06-01", None)
        assert review is not None
        assert review.reviewer == "jsmith"
        assert source == "ad"

    def test_ad_only_malformed_date(self):
        review, source = resolve_review("jsmith", "bad-date", None)
        assert review is None
        assert source == "none"

    # -- SQLite only --
    def test_sqlite_only(self):
        sqlite_rec = self._make_sqlite_review("2025-05-01")
        review, source = resolve_review(None, None, sqlite_rec)
        assert review is sqlite_rec
        assert source == "sqlite"

    # -- both sources, AD more recent --
    def test_both_ad_wins(self):
        sqlite_rec = self._make_sqlite_review("2025-01-01")
        review, source = resolve_review("jsmith", "2025-06-01", sqlite_rec)
        assert review is not None
        assert review.reviewer == "jsmith"
        assert source == "both"

    # -- both sources, SQLite more recent --
    def test_both_sqlite_wins(self):
        sqlite_rec = self._make_sqlite_review("2025-12-01")
        review, source = resolve_review("jsmith", "2025-01-01", sqlite_rec)
        assert review is sqlite_rec
        assert source == "both"

    # -- both sources, same date → AD wins --
    def test_same_date_ad_wins(self):
        sqlite_rec = self._make_sqlite_review("2025-06-01", reviewer="dbuser")
        review, source = resolve_review("jsmith", "2025-06-01", sqlite_rec)
        assert review is not None
        assert review.reviewer == "jsmith"
        assert source == "both"

    # -- AD date malformed, falls back to SQLite --
    def test_ad_malformed_falls_back_to_sqlite(self):
        sqlite_rec = self._make_sqlite_review("2025-03-15")
        review, source = resolve_review("jsmith", "not-valid", sqlite_rec)
        assert review is sqlite_rec
        assert source == "sqlite"
