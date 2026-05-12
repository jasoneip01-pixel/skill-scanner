"""Core scanning engine — orchestrates all scanners and applies policy."""

import time
from pathlib import Path
from typing import Optional

from skill_scanner.scanners.manifest import scan_manifest
from skill_scanner.scanners.script import scan_scripts
from skill_scanner.scanners.instruction import scan_instructions
from skill_scanner.scanners.permission import scan_permissions
from skill_scanner.scanners.dependency import scan_dependencies


def scan_skill(
    skill_dir: str, policy_name: str = "moderate", baseline_dir: Optional[str] = None
) -> dict:
    """Run all scanners against a skill directory, return structured results."""
    base = Path(skill_dir)
    if not base.exists():
        raise FileNotFoundError(f"Skill directory not found: {skill_dir}")
    skill_path = base / "SKILL.md"
    if not skill_path.exists():
        raise FileNotFoundError(f"No SKILL.md found in {skill_dir}")

    start = time.time()
    findings = []

    findings.extend(scan_manifest(base, skill_path))
    findings.extend(scan_scripts(base))
    findings.extend(scan_instructions(base))
    findings.extend(scan_permissions(base))
    findings.extend(scan_dependencies(base))

    dur_ms = int((time.time() - start) * 1000)

    critical = [f for f in findings if f["severity"] == "critical"]
    warnings = [f for f in findings if f["severity"] == "warning"]
    passed_checks = len([f for f in findings if f["severity"] == "passed"])

    blocked = len(critical) > 0

    return {
        "findings": findings,
        "critical": len(critical),
        "warnings": len(warnings),
        "passed": passed_checks,
        "total": len(findings),
        "blocked": blocked,
        "blocked_rules": list(set(f["rule"] for f in findings if f["action"] == "block")),
        "duration_ms": dur_ms,
        "skill_dir": str(skill_dir),
        "policy": policy_name,
    }
