"""Phase 4: Enterprise features — compliance reports, notifications, RBAC."""

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional


class ComplianceReporter:
    """Generate compliance audit reports (SOC2, GDPR, PCI-DSS aligned)."""

    FRAMEWORKS = ["soc2", "gdpr", "pci_dss", "iso27001", "custom"]

    @staticmethod
    def generate(scan_results: dict, framework: str = "soc2") -> dict:
        """Generate a compliance audit report from scan results."""
        report = {
            "report_type": f"Agent Skill Security Audit — {framework.upper()}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "framework": framework,
            "overall_verdict": scan_results.get("verdict", "unknown"),
            "sections": [],
        }

        controls = ComplianceReporter._controls_for(framework)
        for control in controls:
            section = ComplianceReporter._evaluate_control(control, scan_results)
            report["sections"].append(section)

        # Compute compliance score
        compliant = sum(1 for s in report["sections"] if s["status"] == "compliant")
        total = len(report["sections"])
        report["compliance_score"] = round(compliant / total * 100) if total else 0
        report["remediation_required"] = [
            s for s in report["sections"] if s["status"] == "non_compliant"
        ]

        return report

    @staticmethod
    def _controls_for(framework: str) -> list[dict]:
        """Return control list for a compliance framework."""
        controls = {
            "soc2": [
                {"id": "CC6.1", "name": "Logical Access Controls", "dimension": "permission"},
                {"id": "CC6.6", "name": "External Network Access", "dimension": "skill"},
                {"id": "CC7.1", "name": "Vulnerability Detection", "dimension": "skill"},
                {"id": "CC7.2", "name": "Change Detection", "dimension": "skill"},
                {"id": "CC8.1", "name": "Change Management", "dimension": "skill"},
            ],
            "gdpr": [
                {"id": "Art.25", "name": "Data Protection by Design", "dimension": "permission"},
                {"id": "Art.32", "name": "Security of Processing", "dimension": "skill"},
                {"id": "Art.35", "name": "Data Protection Impact Assessment", "dimension": "rag"},
            ],
            "pci_dss": [
                {"id": "Req.6", "name": "Secure Systems and Applications", "dimension": "skill"},
                {"id": "Req.7", "name": "Access Control", "dimension": "permission"},
                {"id": "Req.11", "name": "Regular Testing", "dimension": "skill"},
            ],
        }
        return controls.get(framework, controls["soc2"])

    @staticmethod
    def _evaluate_control(control: dict, results: dict) -> dict:
        """Evaluate a single compliance control against scan results."""
        dim = control.get("dimension", "skill")
        dim_result = results.get("dimensions", {}).get(dim, {})

        # Determine coverage: did the scanner actually run for this dimension?
        dim_status = dim_result.get("status", "not_scanned")
        dim_checks = dim_result.get("checks", 0)

        if dim_status == "not_scanned" or dim_checks == 0:
            coverage = "not_covered"
            status = "no_evidence"
        elif dim_result.get("blocked"):
            coverage = "covered"
            status = "non_compliant"
        elif dim_result.get("warnings", 0) > 0:
            coverage = "covered"
            status = "needs_review"
        else:
            coverage = "covered"
            status = "compliant"

        return {
            "control_id": control["id"],
            "control_name": control["name"],
            "dimension": dim,
            "status": status,
            "coverage_status": coverage,
            "evidence": f"Dimension '{dim}' scan: {dim_status} ({dim_checks} checks)",
        }


class NotificationSender:
    """Send scan result notifications to Slack, Teams, or generic webhooks."""

    @staticmethod
    def send_slack(webhook_url: str, result: dict) -> bool:
        """Send scan summary to Slack via incoming webhook."""
        import urllib.request

        emoji = "❌" if result.get("blocked") else "✅"
        color = "#ef4444" if result.get("blocked") else "#4ade80"

        payload = {
            "attachments": [{
                "color": color,
                "title": f"{emoji} Skill Scanner — Scan Result",
                "fields": [
                    {"title": "Skill", "value": result.get("skill_dir", "—"), "short": True},
                    {"title": "Policy", "value": result.get("policy", "—"), "short": True},
                    {"title": "Critical", "value": str(result.get("critical", 0)), "short": True},
                    {"title": "Warnings", "value": str(result.get("warnings", 0)), "short": True},
                    {"title": "Duration", "value": f"{result.get('duration_ms', 0)}ms", "short": True},
                    {"title": "Verdict", "value": "BLOCKED" if result.get("blocked") else "PASSED", "short": True},
                ],
                "footer": "Skill Scanner v0.3.0",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }]
        }

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(webhook_url, data=data)
            req.add_header("Content-Type", "application/json")
            urllib.request.urlopen(req, timeout=10)
            return True
        except Exception:
            return False

    @staticmethod
    def send_teams(webhook_url: str, result: dict) -> bool:
        """Send scan summary to Microsoft Teams via incoming webhook."""
        import urllib.request

        color = "FF0000" if result.get("blocked") else "00FF00"
        title = "❌ MERGE BLOCKED" if result.get("blocked") else "✅ SCAN PASSED"

        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "title": title,
            "text": (
                f"**Skill:** {result.get('skill_dir', '—')}  \n"
                f"**Policy:** {result.get('policy', '—')}  \n"
                f"**Critical:** {result.get('critical', 0)} | "
                f"**Warnings:** {result.get('warnings', 0)} | "
                f"**Duration:** {result.get('duration_ms', 0)}ms"
            ),
        }

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(webhook_url, data=data)
            req.add_header("Content-Type", "application/json")
            urllib.request.urlopen(req, timeout=10)
            return True
        except Exception:
            return False


class RBACManager:
    """Simplified RBAC for enterprise deployments."""

    ROLES = {
        "admin": ["scan", "policy_write", "user_manage", "report_view", "registry_manage",
                  "baseline_approve", "exception_approve", "notification_configure"],
        "security_lead": ["scan", "policy_write", "report_view", "registry_view",
                         "baseline_approve", "exception_approve"],
        "developer": ["scan", "report_view"],
        "viewer": ["report_view"],
    }

    def __init__(self, config_path: str = ".agent-skills/rbac.json"):
        self.config_path = Path(config_path)
        self._load()

    def _load(self):
        if self.config_path.exists():
            self.config = json.loads(self.config_path.read_text())
        else:
            self.config = {"users": {}, "roles": self.ROLES}

    def save(self):
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(self.config, indent=2))

    def assign_role(self, user_id: str, role: str):
        if role not in self.ROLES:
            raise ValueError(f"Unknown role: {role}")
        self.config["users"][user_id] = role
        self.save()

    def can(self, user_id: str, action: str) -> bool:
        role = self.config["users"].get(user_id, "viewer")
        # Use config roles for custom role support, fall back to built-in ROLES
        roles = self.config.get("roles", self.ROLES)
        return action in roles.get(role, [])
