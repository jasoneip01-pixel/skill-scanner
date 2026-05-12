"""Tests for script scanner."""

import pytest
from skill_scanner.scanners.script import scan_scripts


class TestScriptScanner:
    def test_no_scripts_dir(self, benign_skill):
        """No scripts directory should return empty."""
        findings = scan_scripts(benign_skill)
        assert isinstance(findings, list)

    def test_data_exfiltration(self, malicious_skill):
        """curl --data-binary should be flagged."""
        findings = scan_scripts(malicious_skill)
        dx = [f for f in findings if f["id"].startswith("DX")]
        assert len(dx) >= 1

    def test_dangerous_commands(self, malicious_skill):
        """chmod 777 and rm -rf should be flagged."""
        findings = scan_scripts(malicious_skill)
        ws = [f for f in findings if f["id"].startswith("WS")]
        assert len(ws) >= 1

    def test_secrets_access(self, malicious_skill):
        """Secrets references should be flagged."""
        findings = scan_scripts(malicious_skill)
        fs = [f for f in findings if f["id"] == "FS001"]
        assert len(fs) >= 1

    def test_ossystem_detected(self, malicious_skill):
        """os.system() should be flagged."""
        findings = scan_scripts(malicious_skill)
        ws = [f for f in findings if f["id"] == "WS006"]
        assert len(ws) >= 1

    def test_oversized_script(self, oversized_skill):
        """Oversized scripts should produce a finding."""
        findings = scan_scripts(oversized_skill)
        oversized = [f for f in findings if f["id"] == "SC001"]
        assert len(oversized) >= 1

    def test_binary_script_safe(self, tmp_path):
        """Binary scripts should not crash."""
        sd = tmp_path / "skill"
        sd.mkdir()
        (sd / "scripts").mkdir()
        (sd / "scripts" / "binary.bin").write_bytes(b"\x00\x01\x02\x03")
        findings = scan_scripts(sd)
        assert isinstance(findings, list)
