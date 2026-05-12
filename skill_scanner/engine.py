"""Core scanning engine — orchestrates all scanners and applies policy."""

import time
from pathlib import Path
from typing import Optional

from skill_scanner.parser import parse_skill
from skill_scanner.scanners.manifest import scan_manifest
from skill_scanner.scanners.script import scan_scripts
from skill_scanner.scanners.instruction import scan_instructions
from skill_scanner.scanners.permission import scan_permissions
from skill_scanner.scanners.dependency import scan_dependencies
from skill_scanner.policy_engine import PolicyEngine
from skill_scanner.trace_engine import TraceRecorder, TraceComparator


def scan_skill(
    skill_dir: str, policy_name: str = "moderate",
    baseline_dir: Optional[str] = None, diff_mode: bool = False,
) -> dict:
    """Run all scanners against a skill directory, return structured results."""
    base = Path(skill_dir)
    if not base.exists():
        raise FileNotFoundError(f"Skill directory not found: {skill_dir}")
    skill_path = base / "SKILL.md"
    if not skill_path.exists():
        raise FileNotFoundError(f"No SKILL.md found in {skill_dir}")

    start = time.time()
    all_findings = []
    scanner_results = {}

    scanners = {
        "manifest": lambda: scan_manifest(base, skill_path),
        "scripts": lambda: scan_scripts(base),
        "instructions": lambda: scan_instructions(base),
        "permissions": lambda: scan_permissions(base),
        "dependencies": lambda: scan_dependencies(base),
    }

    for name, scanner_fn in scanners.items():
        findings = scanner_fn()
        all_findings.extend(findings)
        passed = len([f for f in findings if f["severity"] in ("passed", "info")])
        scanner_results[name] = {"checks": len(findings), "passed": passed}

    # Diff mode: compare against baseline
    diff_result = None
    if diff_mode:
        if baseline_dir:
            try:
                recorder = TraceRecorder()
                comparator = TraceComparator()
                _build_baseline_trace(recorder, baseline_dir)
                _build_baseline_trace(recorder, skill_dir, is_current=True)
                diff_data = comparator.compare(
                    recorder.load(f"baseline-{Path(baseline_dir).name}") or {},
                    recorder.load(f"current-{Path(skill_dir).name}") or {},
                )
                if diff_data and diff_data.get("diffs"):
                    for d in diff_data["diffs"]:
                        sev = d.get("severity", "warning")
                        action = "block" if sev == "critical" else "warn"
                        all_findings.append({
                            "id": "DF001", "severity": sev, "action": action,
                            "title": f"Diff: {d['type']} — {d.get('tool', '')}",
                            "file": "surface_diff",
                            "desc": d.get("detail", ""),
                            "rule": f"diff.{d['type']}",
                        })
                diff_result = diff_data
            except Exception as e:
                all_findings.append({
                    "id": "DF000", "severity": "critical", "action": "block",
                    "title": "Diff requested but baseline comparison failed",
                    "file": "surface_diff",
                    "desc": str(e),
                    "rule": "diff.failed",
                })
        else:
            all_findings.append({
                "id": "DF000", "severity": "warning", "action": "warn",
                "title": "Diff mode enabled but no baseline specified",
                "file": "surface_diff",
                "desc": "Use --baseline <directory> to enable comparison",
                "rule": "diff.no_baseline",
            })

    dur_ms = int((time.time() - start) * 1000)

    # Apply policy engine — verdict DRIVES blocked state
    engine = PolicyEngine()
    verdict = engine.evaluate(all_findings, policy_name)

    # Generate finding for OPA errors
    if verdict.get("engine") == "opa_fallback":
        opa_error = verdict.get("opa_error", "OPA evaluation failed")
        all_findings.append({
            "id": "OP001", "severity": "critical", "action": "block",
            "title": "OPA policy engine evaluation failed",
            "file": "policy/",
            "desc": opa_error,
            "rule": "opa.evaluation_failed",
        })

    blocked = verdict.get("verdict") is False  # False = blocked
    blocked_rules = verdict.get("blocked_rules", [])

    critical = [f for f in all_findings if f["severity"] == "critical"]
    warnings = [f for f in all_findings if f["severity"] == "warning"]
    passed_checks = sum(rs["passed"] for rs in scanner_results.values())
    total = len(all_findings)

    return {
        "findings": all_findings,
        "critical": len(critical),
        "warnings": len(warnings),
        "passed": passed_checks,
        "total": total,
        "blocked": blocked,
        "blocked_rules": blocked_rules,
        "scanner_results": scanner_results,
        "diff_result": diff_result,
        "duration_ms": dur_ms,
        "skill_dir": str(skill_dir),
        "policy": policy_name,
        "verdict": verdict,
    }


def _build_baseline_trace(recorder: TraceRecorder, directory: str, is_current: bool = False):
    """Build a simple trace from skill metadata for baseline comparison."""
    base = Path(directory)
    skill_path = base / "SKILL.md"
    if not skill_path.exists():
        return
    parsed = parse_skill(skill_path)
    if parsed.errors or not parsed.metadata:
        return
    data = parsed.metadata
    calls = []
    for tool in data.get("tools", []):
        calls.append({"tool": tool, "method": "GET", "params": {}})
    prefix = "current" if is_current else "baseline"
    recorder.record(f"{prefix}-{base.name}", "1.0", calls)
