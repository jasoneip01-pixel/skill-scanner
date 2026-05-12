"""Phase 2: Rego Policy Engine — programmable security rules."""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


class PolicyEngine:
    """OPA-compatible Rego policy engine for Skill Scanner.

    Evaluates scan findings against user-defined Rego policies.
    Falls back to built-in YAML policies if OPA is unavailable.
    """

    def __init__(self, policy_dir: Optional[str] = None):
        self.policy_dir = Path(policy_dir) if policy_dir else None
        self._opa_available = self._check_opa()

    def _check_opa(self) -> bool:
        try:
            result = subprocess.run(
                ["opa", "version"], capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def evaluate(self, findings: list[dict], policy_name: str = "moderate") -> dict:
        """Evaluate findings against policy. Returns action per finding + summary verdict."""
        if self._opa_available and self.policy_dir:
            return self._evaluate_with_opa(findings, policy_name)
        return self._evaluate_with_builtin(findings, policy_name)

    def _evaluate_with_opa(self, findings: list[dict], policy_name: str) -> dict:
        """Evaluate using OPA Rego engine."""
        policy_file = self.policy_dir / f"{policy_name}.rego"
        if not policy_file.exists():
            return self._evaluate_with_builtin(findings, policy_name)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"findings": findings}, f)
            input_path = f.name

        try:
            result = subprocess.run(
                ["opa", "eval", "--data", str(policy_file),
                 "--input", input_path, "data.skill_scanner"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                return self._parse_opa_output(result.stdout, findings)
        except Exception:
            pass
        finally:
            Path(input_path).unlink(missing_ok=True)

        return self._evaluate_with_builtin(findings, policy_name)

    def _parse_opa_output(self, stdout: str, findings: list[dict]) -> dict:
        """Parse OPA evaluation output into standard format."""
        try:
            data = json.loads(stdout)
            verdict = data.get("result", [{}])[0].get("expressions", [{}])[0].get("value", {})
            return {
                "verdict": verdict.get("allow", False),
                "blocked_rules": verdict.get("blocked_rules", []),
                "risk_score": verdict.get("risk_score", 0),
                "engine": "opa",
            }
        except (json.JSONDecodeError, KeyError, IndexError):
            return {"verdict": True, "blocked_rules": [], "risk_score": 0, "engine": "opa_fallback"}

    def _evaluate_with_builtin(self, findings: list[dict], policy_name: str) -> dict:
        """Fallback: use built-in YAML policy evaluation."""
        from skill_scanner.policies import load_policy
        try:
            policy = load_policy(policy_name)
        except FileNotFoundError:
            policy = load_policy("moderate")

        policy_data = policy.get("policy", {})
        block_rules = set(policy_data.get("block_on", []))
        thresholds = policy_data.get("thresholds", {})

        blocked_rules = list(set(
            f["rule"] for f in findings
            if f.get("action") == "block" or f.get("severity") == "critical"
        ))

        critical_count = len([f for f in findings if f["severity"] == "critical"])
        warning_count = len([f for f in findings if f["severity"] == "warning"])

        max_critical = thresholds.get("max_critical", 0)
        max_warnings = thresholds.get("max_warnings", 5)

        allow = (
            critical_count <= max_critical
            and warning_count <= max_warnings
            and len(blocked_rules) == 0
        )

        return {
            "verdict": allow,
            "blocked_rules": blocked_rules,
            "critical_count": critical_count,
            "warning_count": warning_count,
            "risk_score": critical_count * 40 + warning_count * 15,
            "engine": "builtin",
        }
