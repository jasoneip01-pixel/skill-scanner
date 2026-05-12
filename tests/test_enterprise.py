"""Tests for enterprise.py — ComplianceReporter, NotificationSender, RBACManager."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest
from skill_scanner.enterprise import ComplianceReporter, NotificationSender, RBACManager


class TestComplianceReporter:
    def test_generate_soc2(self):
        """SOC2 report should have 5 controls."""
        results = {"verdict": "passed", "dimensions": {"skill": {"status": "passed", "checks": 3}}}
        report = ComplianceReporter.generate(results, "soc2")
        assert report["framework"] == "soc2"
        assert len(report["sections"]) == 5
        assert "compliance_score" in report
        assert "overall_verdict" in report

    def test_generate_gdpr(self):
        """GDPR report should have 3 controls."""
        results = {"verdict": "passed", "dimensions": {"skill": {"status": "passed", "checks": 3}}}
        report = ComplianceReporter.generate(results, "gdpr")
        assert report["framework"] == "gdpr"
        assert len(report["sections"]) == 3

    def test_generate_pci_dss(self):
        """PCI-DSS report should have 3 controls."""
        results = {"verdict": "passed", "dimensions": {"skill": {"status": "passed", "checks": 3}}}
        report = ComplianceReporter.generate(results, "pci_dss")
        assert report["framework"] == "pci_dss"
        assert len(report["sections"]) == 3

    def test_compliance_score_all_compliant(self):
        """All compliant controls should give 100%."""
        results = {"verdict": "passed", "dimensions": {"permission": {"status": "passed", "checks": 2},
                                                        "skill": {"status": "passed", "checks": 3}}}
        report = ComplianceReporter.generate(results, "soc2")
        assert report["compliance_score"] == 100

    def test_compliance_score_all_non_compliant(self):
        """All blocked controls should give 0%."""
        results = {"verdict": "blocked", "dimensions": {"permission": {"status": "blocked", "checks": 2, "blocked": True},
                                                         "skill": {"status": "blocked", "checks": 3, "blocked": True}}}
        report = ComplianceReporter.generate(results, "soc2")
        assert report["compliance_score"] == 0

    def test_compliance_score_mixed(self):
        """Mixed compliance should give partial score."""
        results = {
            "verdict": "blocked",
            "dimensions": {
                "permission": {"status": "passed", "checks": 2},
                "skill": {"status": "blocked", "checks": 3, "blocked": True},
            },
        }
        report = ComplianceReporter.generate(results, "soc2")
        assert 0 < report["compliance_score"] < 100

    def test_not_scanned_dimension(self):
        """Not scanned dimensions should produce no_evidence."""
        results = {"verdict": "passed", "dimensions": {}}
        report = ComplianceReporter.generate(results, "soc2")
        for sec in report["sections"]:
            assert sec["status"] == "no_evidence"

    def test_warnings_gives_needs_review(self):
        """Warnings should give needs_review status."""
        results = {"verdict": "passed", "dimensions": {"skill": {"status": "passed", "checks": 3, "warnings": 1}}}
        report = ComplianceReporter.generate(results, "soc2")
        skill_controls = [s for s in report["sections"] if s["dimension"] == "skill"]
        assert all(s["status"] == "needs_review" for s in skill_controls)

    def test_custom_framework_falls_back_to_soc2(self):
        """Unknown framework should fall back to SOC2 controls."""
        results = {"verdict": "passed", "dimensions": {}}
        report = ComplianceReporter.generate(results, "custom")
        assert len(report["sections"]) == 5  # SOC2 fallback

    def test_remediation_list(self):
        """Non-compliant controls should appear in remediation_required."""
        results = {"verdict": "blocked", "dimensions": {"permission": {"status": "blocked", "checks": 2, "blocked": True},
                                                         "skill": {"status": "passed", "checks": 3}}}
        report = ComplianceReporter.generate(results, "soc2")
        assert len(report["remediation_required"]) > 0


class TestNotificationSender:
    def test_send_slack_success(self, monkeypatch):
        """Send Slack should return True on success."""
        def mock_urlopen(req, timeout=10):
            class MockResp:
                status = 200
            return MockResp()
        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        result = {"blocked": True, "critical": 4, "warnings": 8, "skill_dir": "/tmp/test", "policy": "moderate", "duration_ms": 13}
        assert NotificationSender.send_slack("https://hooks.slack.com/test", result) is True

    def test_send_slack_failure(self, monkeypatch):
        """Send Slack should return False on failure."""
        def mock_fail(req, timeout=10):
            raise Exception("timeout")
        monkeypatch.setattr("urllib.request.urlopen", mock_fail)
        assert NotificationSender.send_slack("https://hooks.slack.com/bad", {}) is False

    def test_send_teams_success(self, monkeypatch):
        """Send Teams should return True on success."""
        def mock_urlopen(req, timeout=10):
            class MockResp:
                status = 200
            return MockResp()
        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        result = {"blocked": False, "critical": 0, "warnings": 2, "skill_dir": "/tmp/test", "policy": "moderate", "duration_ms": 5}
        assert NotificationSender.send_teams("https://outlook.office.com/webhook/test", result) is True

    def test_send_teams_failure(self, monkeypatch):
        """Send Teams should return False on failure."""
        def mock_fail(req, timeout=10):
            raise Exception("unauthorized")
        monkeypatch.setattr("urllib.request.urlopen", mock_fail)
        assert NotificationSender.send_teams("https://outlook.office.com/webhook/bad", {}) is False


class TestRBACManager:
    @pytest.fixture
    def rbac(self, tmp_path):
        return RBACManager(config_path=str(tmp_path / "rbac.json"))

    def test_default_role_is_viewer(self, rbac):
        """Unknown user should have viewer role."""
        assert not rbac.can("unknown_user", "scan")
        assert rbac.can("unknown_user", "report_view")

    def test_assign_role(self, rbac):
        """assign_role should persist role."""
        rbac.assign_role("user_a", "developer")
        assert rbac.can("user_a", "scan")
        assert not rbac.can("user_a", "policy_write")

    def test_admin_can_do_all(self, rbac):
        """Admin should have all permissions."""
        rbac.assign_role("admin_user", "admin")
        assert rbac.can("admin_user", "scan")
        assert rbac.can("admin_user", "policy_write")
        assert rbac.can("admin_user", "user_manage")
        assert rbac.can("admin_user", "report_view")

    def test_security_lead_permissions(self, rbac):
        """Security lead should have scan + policy + approve."""
        rbac.assign_role("sec_user", "security_lead")
        assert rbac.can("sec_user", "scan")
        assert rbac.can("sec_user", "policy_write")
        assert rbac.can("sec_user", "baseline_approve")
        assert not rbac.can("sec_user", "user_manage")

    def test_invalid_role_raises(self, rbac):
        """assign_role with unknown role should raise ValueError."""
        with pytest.raises(ValueError, match="Unknown role"):
            rbac.assign_role("user_x", "superadmin")

    def test_persist_config(self, rbac, tmp_path):
        """RBAC config should be persisted to disk."""
        rbac.assign_role("persist_user", "developer")
        loaded = json.loads((tmp_path / "rbac.json").read_text())
        assert loaded["users"]["persist_user"] == "developer"

    def test_load_config(self, tmp_path):
        """RBAC should load persisted config on init."""
        cfg_path = tmp_path / "rbac.json"
        cfg_path.parent.mkdir(exist_ok=True)
        cfg_path.write_text(json.dumps({"users": {"bob": "admin"}, "roles": RBACManager.ROLES}))
        rbac = RBACManager(config_path=str(cfg_path))
        assert rbac.can("bob", "user_manage")
