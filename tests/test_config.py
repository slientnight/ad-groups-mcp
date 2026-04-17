"""Tests for config module: transport selection and policy file loading.

Validates Requirements 1.1–1.3 (transport selection) and 14.1–14.7 (policy file loading).
"""

from __future__ import annotations

import pytest

from ad_groups_mcp.config import parse_args, load_policy_config
from ad_groups_mcp.models import PolicyConfig


# ---------------------------------------------------------------------------
# 9.2 — Transport selection defaults (Requirements 1.1–1.3)
# ---------------------------------------------------------------------------

class TestTransportSelection:
    def test_default_transport_is_stdio(self):
        """Req 1.1: No transport arg defaults to stdio."""
        args = parse_args([])
        assert args.transport == "stdio"

    def test_explicit_stdio(self):
        args = parse_args(["--transport", "stdio"])
        assert args.transport == "stdio"

    def test_explicit_sse(self):
        """Req 1.3: --transport sse selects SSE."""
        args = parse_args(["--transport", "sse"])
        assert args.transport == "sse"

    def test_explicit_streamable_http(self):
        """Req 1.2: --transport streamable-http selects Streamable HTTP."""
        args = parse_args(["--transport", "streamable-http"])
        assert args.transport == "streamable-http"

    def test_invalid_transport_raises(self):
        """Invalid transport value causes argparse error."""
        with pytest.raises(SystemExit):
            parse_args(["--transport", "grpc"])

    def test_default_policy_file(self):
        args = parse_args([])
        assert args.policy_file == "policy.yaml"

    def test_default_db_path(self):
        args = parse_args([])
        assert args.db_path == "reviews.db"

    def test_custom_policy_file(self):
        args = parse_args(["--policy-file", "/tmp/custom.yaml"])
        assert args.policy_file == "/tmp/custom.yaml"

    def test_custom_db_path(self):
        args = parse_args(["--db-path", "/tmp/custom.db"])
        assert args.db_path == "/tmp/custom.db"


# ---------------------------------------------------------------------------
# 9.6 — Policy file loading (Requirements 14.1–14.7)
# ---------------------------------------------------------------------------

class TestPolicyFileLoading:
    def test_valid_yaml_loads_config(self, tmp_path):
        """Req 14.1–14.5: Valid YAML with all fields loads correctly."""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            "naming_regex: '^GRP_.*'\n"
            "max_members: 100\n"
            "review_recency_days: 30\n"
            "acl_allow_list:\n"
            "  - Domain Admins\n"
            "  - Custom Admins\n"
        )
        config = load_policy_config(str(policy_file))
        assert isinstance(config, PolicyConfig)
        assert config.naming_regex == "^GRP_.*"
        assert config.max_members == 100
        assert config.review_recency_days == 30
        assert config.acl_allow_list == ["Domain Admins", "Custom Admins"]

    def test_missing_file_returns_defaults(self, tmp_path):
        """Req 14.6: Missing file falls back to built-in defaults."""
        config = load_policy_config(str(tmp_path / "nonexistent.yaml"))
        assert isinstance(config, PolicyConfig)
        assert config.naming_regex == r"^(SEC|DL|APP)_.*"
        assert config.max_members == 500
        assert config.review_recency_days == 90

    def test_empty_file_returns_defaults(self, tmp_path):
        """Empty YAML file treated as defaults."""
        policy_file = tmp_path / "empty.yaml"
        policy_file.write_text("")
        config = load_policy_config(str(policy_file))
        assert isinstance(config, PolicyConfig)
        assert config.max_members == 500

    def test_malformed_yaml_exits(self, tmp_path):
        """Req 14.7: Malformed YAML causes sys.exit(1)."""
        policy_file = tmp_path / "bad.yaml"
        policy_file.write_text("naming_regex: [\ninvalid yaml")
        with pytest.raises(SystemExit) as exc_info:
            load_policy_config(str(policy_file))
        assert exc_info.value.code == 1

    def test_non_mapping_yaml_exits(self, tmp_path):
        """YAML that parses to a non-dict (e.g. a list) causes sys.exit(1)."""
        policy_file = tmp_path / "list.yaml"
        policy_file.write_text("- item1\n- item2\n")
        with pytest.raises(SystemExit) as exc_info:
            load_policy_config(str(policy_file))
        assert exc_info.value.code == 1

    def test_partial_config_uses_defaults_for_missing(self, tmp_path):
        """Partial YAML uses defaults for unspecified fields."""
        policy_file = tmp_path / "partial.yaml"
        policy_file.write_text("max_members: 200\n")
        config = load_policy_config(str(policy_file))
        assert config.max_members == 200
        assert config.naming_regex == r"^(SEC|DL|APP)_.*"  # default
        assert config.review_recency_days == 90  # default
