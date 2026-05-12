"""Phase 4: Agent Surface Scanner — full agent capability boundary analysis.

Scans all 7 dimensions of an Agent's capability surface:
    Skill + Tool + Prompt + Model + RAG + Memory + Permission
"""

import json
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone


class AgentSurfaceScanner:
    """Full agent surface scan — the complete release gate."""

    DIMENSIONS = ["skill", "tool", "prompt", "model", "rag", "memory", "permission"]

    # Directories to skip during recursive glob
    IGNORE_DIRS = {".git", "node_modules", "venv", ".venv", "dist", "build",
                   "__pycache__", ".gitignore", "env", ".env", "target"}

    MAX_GLOB_FILES = 500  # Safety limit on files scanned per glob

    def __init__(self, agent_dir: str):
        self.agent_dir = Path(agent_dir)
        if not self.agent_dir.exists():
            raise FileNotFoundError(f"Agent directory not found: {agent_dir}")

    def _safe_glob(self, pattern: str) -> list[Path]:
        """Recursive glob with exclusions and safety limits."""
        results = []
        for p in self.agent_dir.glob(pattern):
            # Skip paths under ignored directories
            try:
                rel = p.relative_to(self.agent_dir)
                if any(part in self.IGNORE_DIRS for part in rel.parts[:-1]):
                    continue
            except ValueError:
                continue
            results.append(p)
            if len(results) >= self.MAX_GLOB_FILES:
                break
        return results

    def scan_all(self, policy_name: str = "moderate") -> dict:
        """Scan all 7 dimensions of the agent surface."""
        results = {
            "agent_dir": str(self.agent_dir),
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "policy": policy_name,
            "dimensions": {},
            "surface_diff": {},
            "verdict": "unknown",
            "blocked_dimensions": [],
        }

        for dim in self.DIMENSIONS:
            scanner = getattr(self, f"_scan_{dim}", lambda: {"status": "not_implemented"})
            results["dimensions"][dim] = scanner()

        # Aggregate verdict
        blocked = [
            dim for dim, result in results["dimensions"].items()
            if result.get("blocked", False)
        ]
        criticals = sum(
            result.get("critical", 0)
            for result in results["dimensions"].values()
        )
        warnings = sum(
            result.get("warnings", 0)
            for result in results["dimensions"].values()
        )

        results.update({
            "blocked_dimensions": blocked,
            "verdict": "blocked" if blocked else "passed",
            "total_critical": criticals,
            "total_warnings": warnings,
        })

        return results

    def _scan_skill(self) -> dict:
        """Scan skill directory within agent."""
        skill_dirs = self._safe_glob("skills/*/SKILL.md")
        if not skill_dirs:
            # Try root-level SKILL.md
            if (self.agent_dir / "SKILL.md").exists():
                skill_dirs = [self.agent_dir / "SKILL.md"]

        if not skill_dirs:
            return {"status": "passed", "blocked": False, "critical": 0, "message": "No skills found"}

        from skill_scanner.engine import scan_skill
        all_findings = []
        for sd in skill_dirs:
            result = scan_skill(str(sd.parent))
            all_findings.extend(result.get("findings", []))

        critical = [f for f in all_findings if f["severity"] == "critical"]
        return {
            "status": "blocked" if critical else "passed",
            "blocked": len(critical) > 0,
            "critical": len(critical),
            "warnings": len([f for f in all_findings if f["severity"] == "warning"]),
            "skills_scanned": len(skill_dirs),
            "blocked_rules": list(set(f["rule"] for f in critical)),
        }

    def _scan_tool(self) -> dict:
        """Scan tool definitions for permission overreach."""
        tool_files = self._safe_glob("**/tools/*.yaml")
        if not tool_files:
            return {"status": "passed", "blocked": False, "critical": 0, "tools_found": 0}

        import yaml
        findings = []
        for tf in tool_files:
            try:
                data = yaml.safe_load(tf.read_text())
                if not isinstance(data, dict):
                    continue
                if data.get("method", "").upper() in ("POST", "DELETE") and not data.get("guardrails"):
                    findings.append({
                        "tool": data.get("name", tf.stem),
                        "issue": "write_operation_without_guardrails",
                        "severity": "critical",
                    })
            except Exception:
                continue

        critical = [f for f in findings if f["severity"] == "critical"]
        return {
            "status": "blocked" if critical else "passed",
            "blocked": len(critical) > 0,
            "critical": len(critical),
            "tools_found": len(tool_files),
        }

    def _scan_prompt(self) -> dict:
        """Scan system prompts for injection vulnerabilities and hardcoded secrets."""
        prompt_files = self._safe_glob("**/*prompt*") + self._safe_glob("**/system.md")
        if not prompt_files:
            return {"status": "passed", "blocked": False, "critical": 0, "message": "No prompt files found"}

        import re
        findings = []
        secret_patterns = [
            (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API key in prompt"),
            (r'AKIA[0-9A-Z]{16}', "AWS key in prompt"),
            (r'ghp_[a-zA-Z0-9]{36}', "GitHub token in prompt"),
        ]

        for pf in prompt_files:
            text = pf.read_text()
            for pattern, desc in secret_patterns:
                if re.search(pattern, text):
                    findings.append({"file": str(pf), "issue": desc, "severity": "critical"})

        critical = [f for f in findings if f["severity"] == "critical"]
        return {
            "status": "blocked" if critical else "passed",
            "blocked": len(critical) > 0,
            "critical": len(critical),
            "prompt_files_scanned": len(prompt_files),
        }

    def _scan_model(self) -> dict:
        """Record model configuration for audit trail."""
        config_files = self._safe_glob("**/model*.yaml") + self._safe_glob("**/model*.json")
        models = []
        for cf in config_files:
            try:
                if cf.suffix == ".json":
                    data = json.loads(cf.read_text())
                else:
                    import yaml
                    data = yaml.safe_load(cf.read_text())
                if isinstance(data, dict) and "model" in data:
                    models.append(data["model"])
            except Exception:
                pass

        return {
            "status": "passed",
            "blocked": False,
            "critical": 0,
            "models_configured": list(set(models)),
            "note": "Model surface is recorded for audit. No active scan performed.",
        }

    def _scan_rag(self) -> dict:
        """Scan RAG configuration for data governance risks."""
        rag_files = self._safe_glob("**/rag*.yaml") + self._safe_glob("**/knowledge*")
        if not rag_files:
            return {"status": "passed", "blocked": False, "critical": 0, "message": "No RAG config found"}

        findings = []
        for rf in rag_files:
            text = rf.read_text()
            if any(kw in text.lower() for kw in ["pii", "personal_data", "customer_data"]):
                findings.append({
                    "file": str(rf),
                    "issue": "RAG may access PII/customer data",
                    "severity": "warning",
                })

        return {
            "status": "passed",
            "blocked": False,
            "critical": 0,
            "warnings": len(findings),
            "rag_files_scanned": len(rag_files),
        }

    def _scan_memory(self) -> dict:
        """Scan memory configuration for persistence risks."""
        mem_files = self._safe_glob("**/memory*.yaml") + self._safe_glob("**/memory*.json")
        if not mem_files:
            return {"status": "passed", "blocked": False, "critical": 0, "message": "No memory config found"}

        findings = []
        for mf in mem_files:
            text = mf.read_text()
            if "indefinite" in text.lower() or "permanent" in text.lower():
                findings.append({
                    "file": str(mf),
                    "issue": "Memory configured for indefinite/permanent retention",
                    "severity": "warning",
                })

        return {
            "status": "passed",
            "blocked": False,
            "critical": 0,
            "warnings": len(findings),
            "memory_files_scanned": len(mem_files),
        }

    def _scan_permission(self) -> dict:
        """Scan permission declarations for principle of least privilege."""
        perm_files = self._safe_glob("**/permissions*.yaml") + self._safe_glob("**/policy*.yaml")
        if not perm_files:
            return {"status": "passed", "blocked": False, "critical": 0, "message": "No permission policy found"}

        import yaml
        findings = []
        broad_perms = ["*", "admin", "superuser", "all", "full_access"]

        for pf in perm_files:
            try:
                data = yaml.safe_load(pf.read_text())
                perms = data.get("permissions", []) if isinstance(data, dict) else []
                if isinstance(perms, str):
                    perms = [perms]
                for p in perms:
                    if any(bp in str(p).lower() for bp in broad_perms):
                        findings.append({
                            "file": str(pf),
                            "issue": f"Overly broad permission: {p}",
                            "severity": "critical",
                        })
            except Exception:
                continue

        critical = [f for f in findings if f["severity"] == "critical"]
        return {
            "status": "blocked" if critical else "passed",
            "blocked": len(critical) > 0,
            "critical": len(critical),
            "permission_files_scanned": len(perm_files),
        }
