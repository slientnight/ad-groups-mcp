# NOTE: This module is a copy of the canonical version in the ad-group-audit repo.
# When modifying shared logic, update the ad-group-audit version first, then copy here.
# See README.md for the sync process.

"""Pure-function module for resolving governance review data.

Merges review records from AD extended attributes and SQLite using
"most recent wins" logic.  No side effects, no AD queries, no SQLite access.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ad_groups_mcp.models import ReviewRecord


def parse_review_date(date_str: str | None) -> datetime | None:
    """Parse a ``YYYY-MM-DD`` string into a timezone-aware UTC datetime.

    Returns ``None`` when *date_str* is ``None``, empty, or does not
    strictly match the ``YYYY-MM-DD`` format.
    """
    if not date_str:
        return None
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        return dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def build_review_from_ad(
    ext_attr1: str | None,
    ext_attr2: str | None,
) -> ReviewRecord | None:
    """Construct a :class:`ReviewRecord` from AD extended attributes.

    *ext_attr1* is the reviewer username (``extensionAttribute1``).
    *ext_attr2* is the review date in ``YYYY-MM-DD`` format
    (``extensionAttribute2``).

    Returns ``None`` when *ext_attr2* is missing or unparseable.
    ``group_dn`` is set to ``""`` because the DN is not available from
    AD attributes alone.
    """
    reviewed_at = parse_review_date(ext_attr2)
    if reviewed_at is None:
        return None
    return ReviewRecord(
        group_dn="",
        reviewer=ext_attr1 or "",
        reviewed_at=reviewed_at,
    )


def resolve_review(
    ad_ext_attr1: str | None,
    ad_ext_attr2: str | None,
    sqlite_review: ReviewRecord | None,
) -> tuple[ReviewRecord | None, str]:
    """Merge AD and SQLite review data using *most recent wins* logic.

    Returns
    -------
    tuple[ReviewRecord | None, str]
        ``(review, source)`` where *source* is one of
        ``"ad"``, ``"sqlite"``, ``"both"``, or ``"none"``.

    When both sources provide a review with the same date, AD wins
    (it is the primary source of truth).
    """
    ad_review = build_review_from_ad(ad_ext_attr1, ad_ext_attr2)

    if ad_review is not None and sqlite_review is not None:
        # Both exist — most recent wins, AD wins on tie
        if ad_review.reviewed_at >= sqlite_review.reviewed_at:
            return ad_review, "both"
        return sqlite_review, "both"

    if ad_review is not None:
        return ad_review, "ad"

    if sqlite_review is not None:
        return sqlite_review, "sqlite"

    return None, "none"
