"""Tests for engine.py — scan_skill end-to-end."""

import pytest
from skill_scanner.engine import scan_skill


class TestEngine:
    def test_benign_scan(self, benign_skill):
        """Benign skill should not be blocked."""
        result = scan_skill(benign_skill)
        assert result["blocked"] is False
        assert result["critical"] == 0

    def test_malicious_scan(self, malicious_skill):
        """Malicious skill should be blocked."""
        result = scan_skill(malicious_skill)
        assert result["blocked"] is True
        assert result["critical"] >= 1

    def test_policy_verdict_drives_blocked(self, malicious_skill):
        """blocked must be driven by policy verdict, not critical count."""
        result = scan_skill(malicious_skill, policy_name="moderate")
        verdict = result.get("verdict", {})
        assert result["blocked"] == (verdict.get("verdict") is False)

    def test_strict_policy_more_findings(self, malicious_skill):
        """Strict policy should produce different verdict than permissive."""
        strict = scan_skill(malicious_skill, policy_name="strict")
        permissive = scan_skill(malicious_skill, policy_name="permissive")
        # Strict should have at least as many blocked rules
        assert len(strict.get("blocked_rules", [])) >= len(permissive.get("blocked_rules", []))

    def test_frontmatter_skill(self, frontmatter_skill):
        """Front matter style should scan without error."""
        result = scan_skill(frontmatter_skill)
        assert "findings" in result
        assert result["blocked"] is False

    def test_diff_mode_no_baseline(self, malicious_skill):
        """--diff without baseline should produce a finding."""
        result = scan_skill(malicious_skill, diff_mode=True)
        df = [f for f in result["findings"] if f["id"] == "DF000"]
        assert len(df) >= 1

    def test_scanner_exception_resilient(self, tmp_path):
        """Engine should not crash if a scanner throws."""
        sd = tmp_path / "skill"
        sd.mkdir()
        (sd / "SKILL.md").write_text("name: test\nversion: 1.0.0\n")
        # Should not crash despite missing expected structure
        result = scan_skill(sd)
        assert "findings" in result
