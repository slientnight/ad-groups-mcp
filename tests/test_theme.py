"""Unit tests for _theme_css and _theme_toggle_section in report.py."""

from __future__ import annotations

from ad_groups_mcp.report import _theme_css, _theme_toggle_section


class TestThemeCSS:
    """Verify _theme_css() returns correct light theme overrides."""

    def test_returns_data_theme_light_selector(self) -> None:
        css = _theme_css()
        assert '[data-theme="light"]' in css

    def test_overrides_bg(self) -> None:
        css = _theme_css()
        assert "--bg:" in css

    def test_overrides_surface(self) -> None:
        css = _theme_css()
        assert "--surface:" in css

    def test_overrides_surface2(self) -> None:
        css = _theme_css()
        assert "--surface2:" in css

    def test_overrides_text(self) -> None:
        css = _theme_css()
        assert "--text:" in css

    def test_overrides_text_muted(self) -> None:
        css = _theme_css()
        assert "--text-muted:" in css

    def test_overrides_accent(self) -> None:
        css = _theme_css()
        assert "--accent:" in css

    def test_overrides_border(self) -> None:
        css = _theme_css()
        assert "--border:" in css

    def test_light_bg_is_light_color(self) -> None:
        css = _theme_css()
        assert "#f5f5f5" in css

    def test_light_text_is_dark_color(self) -> None:
        css = _theme_css()
        assert "#1a1a1a" in css


class TestThemeToggleSection:
    """Verify _theme_toggle_section() returns correct HTML + JS."""

    def test_contains_button(self) -> None:
        html = _theme_toggle_section()
        assert "<button" in html
        assert "theme-toggle" in html

    def test_contains_script_tag(self) -> None:
        html = _theme_toggle_section()
        assert "<script>" in html
        assert "</script>" in html

    def test_toggles_data_theme_attribute(self) -> None:
        html = _theme_toggle_section()
        assert "data-theme" in html
        assert "setAttribute" in html
        assert "removeAttribute" in html

    def test_persists_to_localstorage(self) -> None:
        html = _theme_toggle_section()
        assert "localStorage" in html
        assert "audit-report-theme" in html

    def test_reads_preference_on_load(self) -> None:
        html = _theme_toggle_section()
        assert "getItem" in html

    def test_saves_preference(self) -> None:
        html = _theme_toggle_section()
        assert "setItem" in html

    def test_localstorage_try_catch(self) -> None:
        html = _theme_toggle_section()
        assert "try" in html
        assert "catch" in html

    def test_defaults_to_dark(self) -> None:
        """Dark is default — no data-theme attribute means dark."""
        html = _theme_toggle_section()
        # The JS only sets data-theme if saved preference exists
        assert "var saved = getStoredTheme();" in html
        assert "if (saved)" in html

    def test_toggle_function_exposed(self) -> None:
        html = _theme_toggle_section()
        assert "toggleTheme" in html
