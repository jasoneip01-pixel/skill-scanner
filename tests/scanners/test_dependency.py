"""Tests for dependency scanner."""

import pytest
from skill_scanner.scanners.dependency import scan_dependencies


class TestDependencyScanner:
    def test_no_deps(self, benign_skill):
        """Benign skill with no deps should not crash."""
        findings = scan_dependencies(benign_skill)
        assert isinstance(findings, list)

    def test_executable_in_resources(self, malicious_skill):
        """Executable .sh in resources should be flagged."""
        findings = scan_dependencies(malicious_skill)
        rs = [f for f in findings if f["id"] == "RS001" and "a.sh" in f.get("file", "")]
        assert len(rs) >= 1

    def test_exec_bit_file(self, malicious_skill):
        """File with exec bit set should be flagged (RS001 for .sh, RS002 for other)."""
        findings = scan_dependencies(malicious_skill)
        rs = [f for f in findings if f["id"] in ("RS001", "RS002")]
        assert len(rs) >= 1

    def test_truncated_scan(self, oversized_skill):
        """Many files in resources should produce truncation warning."""
        findings = scan_dependencies(oversized_skill)
        rs = [f for f in findings if f["id"] == "RS003"]
        assert len(rs) >= 1

    def test_no_resources_dir(self, tmp_path):
        """No resources directory should not crash."""
        sd = tmp_path / "skill"
        sd.mkdir()
        (sd / "SKILL.md").write_text("name: test\nversion: 1.0.0\n")
        findings = scan_dependencies(sd)
        assert isinstance(findings, list)
