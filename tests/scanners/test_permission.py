"""Tests for permission scanner."""

import pytest
from skill_scanner.scanners.permission import scan_permissions


class TestPermissionScanner:
    def test_no_permission_issues(self, benign_skill):
        """Benign skill should pass permission scan."""
        findings = scan_permissions(benign_skill)
        warning = [f for f in findings if f["severity"] != "passed"]
        assert len(warning) == 0

    def test_network_without_justification(self, malicious_skill):
        """network: true with no endpoint docs should warn."""
        findings = scan_permissions(malicious_skill)
        net = [f for f in findings if f["id"] == "NET001"]
        assert len(net) >= 1

    def test_high_risk_tool_guardrails(self, malicious_skill):
        """payment.refund and crm.updateCustomer need guardrails."""
        findings = scan_permissions(malicious_skill)
        guard = [f for f in findings if f["id"] == "TOOL001"]
        assert len(guard) >= 1
        # Should flag both tools
        assert any("crm" in f.get("title", "") for f in guard)
        assert any("refund" in f.get("title", "") for f in guard)

    def test_tool_permission_mismatch(self, malicious_skill):
        """POST tool described as 'read' should be flagged."""
        findings = scan_permissions(malicious_skill)
        mismatch = [f for f in findings if f["id"] == "TS001"]
        assert len(mismatch) >= 1

    def test_traversal_path_safe_rejection(self, traversal_skill):
        """Traversal paths in instructions should not cause crash."""
        findings = scan_permissions(traversal_skill)
        assert isinstance(findings, list)
