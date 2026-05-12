"""Tests for policy_engine.py — verdict, fallback, OPA parse."""

import pytest
from skill_scanner.policy_engine import PolicyEngine


class TestPolicyEngine:
    def test_builtin_allow(self):
        """No critical findings should result in allow."""
        engine = PolicyEngine()
        result = engine.evaluate([], "moderate")
        assert result["verdict"] is True

    def test_builtin_block_critical(self):
        """Critical findings should result in block."""
        engine = PolicyEngine()
        findings = [
            {"id": "T001", "severity": "critical", "rule": "test.rule",
             "action": "block", "title": "test", "file": "SKILL.md"},
        ]
        result = engine.evaluate(findings, "moderate")
        assert result["verdict"] is False
        assert len(result["blocked_rules"]) >= 1

    def test_builtin_block_many_warnings(self):
        """Excessive warnings should block under strict policy."""
        engine = PolicyEngine()
        findings = [
            {"id": f"W{i:03d}", "severity": "warning", "rule": "test.warn",
             "action": "warn", "title": "warn", "file": "SKILL.md"}
            for i in range(10)
        ]
        result = engine.evaluate(findings, "strict")
        assert result["verdict"] is False

    def test_permissive_allow_warnings(self):
        """Permissive policy should allow warnings."""
        engine = PolicyEngine()
        findings = [
            {"id": "W001", "severity": "warning", "rule": "test.warn",
             "action": "warn", "title": "warn", "file": "SKILL.md"}
        ]
        result = engine.evaluate(findings, "permissive")
        assert result["verdict"] is True

    def test_opa_fallback_not_silent(self):
        """OPA fallback should block, not silently allow."""
        engine = PolicyEngine()
        # Force OPA fallback by passing an engine that doesn't exist
        # _parse_opa_output with bad input
        result = engine._parse_opa_output("invalid json", [])
        assert result["verdict"] is False
        assert "opa.evaluation_failed" in result.get("blocked_rules", [])

    def test_policy_names(self):
        """Known policy names should load without error."""
        engine = PolicyEngine()
        for name in ["moderate", "strict", "permissive"]:
            result = engine.evaluate([], name)
            assert "verdict" in result
            assert "engine" in result
            assert result["engine"] == "builtin"

    def test_unknown_policy_fallback(self):
        """Unknown policy name should fall back to moderate."""
        engine = PolicyEngine()
        result = engine.evaluate([], "nonexistent_policy")
        assert "verdict" in result
        assert result["engine"] == "builtin"
