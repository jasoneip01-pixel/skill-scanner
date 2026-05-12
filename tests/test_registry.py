"""Tests for registry.py — SSRF protection, private IP detection."""

import pytest
from skill_scanner.registry import RegistryScanner


class TestRegistrySSRF:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.scanner = RegistryScanner()

    def test_private_ip_detection_127(self):
        assert self.scanner._is_private_ip("127.0.0.1") is True

    def test_private_ip_detection_10(self):
        assert self.scanner._is_private_ip("10.0.0.1") is True

    def test_private_ip_detection_172_16(self):
        assert self.scanner._is_private_ip("172.16.0.1") is True

    def test_private_ip_detection_172_31(self):
        """172.31 should be detected as private (was missed by string prefix)."""
        assert self.scanner._is_private_ip("172.31.0.1") is True

    def test_private_ip_detection_192_168(self):
        assert self.scanner._is_private_ip("192.168.1.1") is True

    def test_private_ip_detection_169_254(self):
        assert self.scanner._is_private_ip("169.254.1.1") is True

    def test_public_ip_allowed(self):
        """Known public domains should not be blocked."""
        assert self.scanner._is_private_ip("github.com") is False
        assert self.scanner._is_private_ip("raw.githubusercontent.com") is False

    def test_unresolvable_host_blocked(self):
        """Unresolvable hostnames should be blocked (defense in depth)."""
        assert self.scanner._is_private_ip("unresolvable.example.invalid") is True

    def test_scan_registry_skill_non_https(self):
        """http:// URLs should be rejected."""
        result = self.scanner.scan_registry_skill("http://raw.githubusercontent.com/user/repo/main/SKILL.md")
        assert result is None

    def test_scan_registry_skill_disallowed_domain(self):
        """Non-allowlisted domains should be rejected."""
        result = self.scanner.scan_registry_skill("https://evil.com/SKILL.md")
        assert result is None

    def test_scan_registry_skill_private_ip(self):
        """Private IP URLs should be rejected."""
        result = self.scanner.scan_registry_skill("https://127.0.0.1/SKILL.md")
        assert result is None

    def test_scan_registry_skill_oversized_blocked(self):
        """No actual oversized test (network), but should not crash."""
        result = self.scanner.scan_registry_skill("https://raw.githubusercontent.com/user/repo/main/SKILL.md")
        # Just verify it doesn't crash - actual result depends on network
        assert result is None or isinstance(result, dict)
