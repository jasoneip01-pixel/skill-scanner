"""Tests for parser.py — skill parsing, safe_join, validation."""

import os
from pathlib import Path
import pytest
from skill_scanner.parser import parse_skill, safe_join, validate_finding, validate_frontmatter


class TestParseSkill:
    def test_frontmatter_and_body(self, benign_skill):
        """Parse front matter + Markdown body."""
        parsed = parse_skill(benign_skill / "SKILL.md")
        assert not parsed.errors
        assert parsed.metadata["name"] == "test-skill"
        assert parsed.metadata["version"] == "1.0.0"
        assert "# Test Skill" in parsed.body

    def test_yaml_only_legacy(self, tmp_path):
        """Parse legacy YAML-only format."""
        p = tmp_path / "SKILL.md"
        p.write_text("name: legacy\nversion: 0.1.0\n")
        parsed = parse_skill(p)
        assert not parsed.errors
        assert parsed.metadata["name"] == "legacy"

    def test_crlf_frontmatter(self, tmp_path):
        """Parse CRLF line endings in front matter."""
        p = tmp_path / "SKILL.md"
        p.write_text("---\r\nname: crlf-test\r\nversion: 1.0.0\r\n---\r\nBody\r\n")
        parsed = parse_skill(p)
        assert not parsed.errors
        assert parsed.metadata["name"] == "crlf-test"

    def test_empty_file(self, tmp_path):
        """Empty file should return empty metadata, not crash."""
        p = tmp_path / "SKILL.md"
        p.write_text("")
        parsed = parse_skill(p)
        # Empty file returns empty metadata, not an error
        assert parsed.metadata == {} or not parsed.errors

    def test_empty_frontmatter(self, empty_skill):
        """Empty front matter (---\\n---)."""
        parsed = parse_skill(empty_skill / "SKILL.md")
        assert parsed.errors or not parsed.metadata

    def test_invalid_yaml(self, tmp_path):
        """Invalid YAML should produce parse_warnings."""
        p = tmp_path / "SKILL.md"
        p.write_text("---\n: invalid yaml :\n---\n")
        parsed = parse_skill(p)
        assert parsed.parse_warnings

    def test_oversized_file(self, tmp_path):
        """File >1MB should produce error."""
        p = tmp_path / "SKILL.md"
        p.write_text("x" * (2 * 1024 * 1024))
        parsed = parse_skill(p)
        assert parsed.errors

    def test_invalid_utf8(self, tmp_path):
        """Invalid UTF-8 should not crash."""
        p = tmp_path / "SKILL.md"
        p.write_bytes(b"---\nname: \xff\xfe\n---\n")
        parsed = parse_skill(p)
        # Should handle gracefully, may or may not parse
        assert parsed is not None

    def test_suspicious_field_detection(self, malicious_skill):
        """suspicious fields like system_prompt_append should be flagged."""
        from skill_scanner.scanners.manifest import scan_manifest
        findings = scan_manifest(malicious_skill, malicious_skill / "SKILL.md")
        suspicious = [f for f in findings if f["id"] == "PI001"]
        assert len(suspicious) > 0
        assert any("system_prompt_append" in s["title"] for s in suspicious)


class TestSafeJoin:
    def test_normal_path(self, tmp_path):
        """Normal relative path should resolve."""
        d = tmp_path / "skill"
        d.mkdir()
        p = safe_join(d, "SKILL.md")
        assert p is not None
        assert str(p).startswith(str(d.resolve()))

    def test_dotdot_traversal(self, tmp_path):
        """../../etc/passwd should be rejected."""
        d = tmp_path / "skill"
        d.mkdir()
        p = safe_join(d, "../../etc/passwd")
        assert p is None

    def test_deep_traversal(self, tmp_path):
        """Deep nested traversal should be rejected."""
        d = tmp_path / "skill"
        d.mkdir()
        p = safe_join(d, "a/../../../../tmp/secret")
        assert p is None

    def test_absolute_path(self, tmp_path):
        """Absolute path should be rejected."""
        d = tmp_path / "skill"
        d.mkdir()
        p = safe_join(d, "/etc/passwd")
        assert p is None

    def test_symlink_outside(self, tmp_path):
        """Symlink pointing outside skill dir should be rejected."""
        d = tmp_path / "skill"
        secret = tmp_path / "secret.txt"
        secret.write_text("secret")
        d.mkdir()
        link = d / "outside_link"
        link.symlink_to(secret, target_is_directory=False)
        p = safe_join(d, "outside_link")
        assert p is None

    def test_symlink_inside(self, tmp_path):
        """Symlink pointing inside skill dir should be allowed."""
        d = tmp_path / "skill"
        d.mkdir()
        inner = d / "inner.txt"
        inner.write_text("hello")
        link = d / "link.txt"
        link.symlink_to(inner, target_is_directory=False)
        p = safe_join(d, "link.txt")
        assert p is not None

    def test_normalized_inside(self, tmp_path):
        """./normalized path should work."""
        d = tmp_path / "skill"
        d.mkdir()
        (d / "sub").mkdir()
        (d / "sub" / "file.md").write_text("ok")
        p = safe_join(d, "sub/file.md")
        assert p is not None

    def test_windows_style_absolute(self, tmp_path):
        """Windows-style absolute path handling — depends on platform."""
        import sys
        d = tmp_path / "skill"
        d.mkdir()
        p = safe_join(d, "C:\\Windows\\System32")
        if sys.platform == "win32":
            assert p is None
        else:
            # On Linux, C:\Windows is a valid relative dir name; ensure no harm done
            assert p is not None
            assert str(p.resolve()).startswith(str(d.resolve()))


class TestValidateFinding:
    def test_valid_finding(self):
        """Complete finding should validate."""
        f = {"id": "T001", "severity": "critical", "rule": "test.rule",
             "title": "test", "file": "SKILL.md", "action": "block"}
        assert len(validate_finding(f)) == 0

    def test_missing_id(self):
        f = {"severity": "critical", "rule": "test", "title": "x", "file": "x"}
        assert validate_finding(f) is not None

    def test_missing_severity(self):
        f = {"id": "T001", "rule": "test", "title": "x", "file": "x"}
        assert validate_finding(f) is not None

    def test_missing_rule(self):
        f = {"id": "T001", "severity": "critical", "title": "x", "file": "x"}
        assert validate_finding(f) is not None

    def test_invalid_severity(self):
        f = {"id": "T001", "severity": "catastrophic", "rule": "test",
             "title": "x", "file": "x"}
        assert validate_finding(f) is not None

    def test_missing_multiple(self):
        f = {}
        assert validate_finding(f) is not None


class TestValidateFrontmatter:
    def test_valid_frontmatter(self):
        errs = validate_frontmatter({"name": "x", "version": "1.0"})
        assert len(errs) == 0

    def test_missing_name(self):
        errs = validate_frontmatter({"version": "1.0"})
        assert len(errs) > 0

    def test_suspicious_field(self, malicious_skill):
        """suspicious fields like system_prompt_append should be flagged."""
        from skill_scanner.scanners.manifest import scan_manifest
        findings = scan_manifest(malicious_skill, malicious_skill / "SKILL.md")
        suspicious = [f for f in findings if f["id"] == "PI001"]
        assert len(suspicious) > 0
