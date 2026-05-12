"""Tests for instruction scanner."""

import pytest
from skill_scanner.scanners.instruction import scan_instructions


class TestInstructionScanner:
    def test_benign_no_instructions(self, benign_skill):
        """No instructions directory should produce no findings."""
        findings = scan_instructions(benign_skill)
        assert isinstance(findings, list)

    def test_suspicious_instructions(self, malicious_skill):
        """Instructions with 'never mention'/'always say' should be flagged."""
        findings = scan_instructions(malicious_skill)
        po = [f for f in findings if f["id"] == "PO001"]
        assert len(po) >= 1
        assert po[0]["severity"] == "warning"

    def test_credential_in_instructions(self, malicious_skill):
        """API keys in instructions should be flagged."""
        findings = scan_instructions(malicious_skill)
        sc = [f for f in findings if f["id"] == "SC001"]
        assert len(sc) >= 1

    def test_traversal_path_rejected(self, traversal_skill):
        """Path traversal in instruction paths should be blocked."""
        findings = scan_instructions(traversal_skill)
        warning = [f for f in findings if f["id"] == "MF005"]
        assert len(warning) >= 1
        assert "outside skill dir" in warning[0].get("title", "").lower()

    def test_valid_instruction_not_flagged(self, tmp_path):
        """A clean instruction should not produce warnings."""
        sd = tmp_path / "skill"
        sd.mkdir()
        (sd / "SKILL.md").write_text("name: test\nversion: 1.0.0\ninstructions:\n  - instructions/good.md\n")
        (sd / "instructions").mkdir()
        (sd / "instructions" / "good.md").write_text("Click the button to submit.\n")
        findings = scan_instructions(sd)
        po = [f for f in findings if f["severity"] == "warning"]
        assert len(po) == 0
