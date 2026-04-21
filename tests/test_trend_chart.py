"""Unit tests for _trend_chart_svg in report.py."""

from __future__ import annotations

import re

from ad_groups_mcp.report import _trend_chart_svg


def _make_trend_data(n: int) -> list[dict]:
    """Create n trend data points with varying compliance_pct."""
    return [
        {
            "compliance_pct": round(50.0 + i * (50.0 / max(n - 1, 1)), 1),
            "snapshot_at": f"2026-01-{i + 1:02d}T00:00:00+00:00",
        }
        for i in range(n)
    ]


class TestTrendChartFallback:
    """When fewer than 2 data points, return fallback message."""

    def test_empty_list(self) -> None:
        result = _trend_chart_svg([])
        assert "Insufficient data for trend chart" in result
        assert "run more audits to see trends" in result

    def test_single_point(self) -> None:
        result = _trend_chart_svg(_make_trend_data(1))
        assert "Insufficient data for trend chart" in result

    def test_no_svg_in_fallback(self) -> None:
        result = _trend_chart_svg([])
        assert "<svg" not in result


class TestTrendChartSVG:
    """When 2+ data points, return a valid self-contained SVG."""

    def test_two_points_produces_svg(self) -> None:
        result = _trend_chart_svg(_make_trend_data(2))
        assert "<svg" in result
        assert "</svg>" in result

    def test_svg_has_xmlns(self) -> None:
        result = _trend_chart_svg(_make_trend_data(5))
        assert 'xmlns="http://www.w3.org/2000/svg"' in result

    def test_no_external_references(self) -> None:
        result = _trend_chart_svg(_make_trend_data(10))
        assert "xlink:href" not in result
        assert "http://" not in result.replace("http://www.w3.org/2000/svg", "")

    def test_circle_count_matches_data_points(self) -> None:
        for n in (2, 5, 10, 30):
            data = _make_trend_data(n)
            result = _trend_chart_svg(data)
            circles = re.findall(r"<circle\b", result)
            assert len(circles) == n, f"Expected {n} circles, got {len(circles)}"

    def test_has_polyline(self) -> None:
        result = _trend_chart_svg(_make_trend_data(5))
        assert "<polyline" in result

    def test_has_axes(self) -> None:
        result = _trend_chart_svg(_make_trend_data(5))
        # Should have axis lines
        assert result.count("<line") >= 2

    def test_has_y_axis_labels(self) -> None:
        result = _trend_chart_svg(_make_trend_data(5))
        assert "0%" in result
        assert "100%" in result

    def test_viewbox_dimensions(self) -> None:
        result = _trend_chart_svg(_make_trend_data(3))
        assert 'viewBox="0 0 600 200"' in result

    def test_uses_css_custom_properties(self) -> None:
        result = _trend_chart_svg(_make_trend_data(5))
        assert "var(--accent)" in result
        assert "var(--text-muted)" in result

    def test_max_30_points(self) -> None:
        data = _make_trend_data(30)
        result = _trend_chart_svg(data)
        circles = re.findall(r"<circle\b", result)
        assert len(circles) == 30
