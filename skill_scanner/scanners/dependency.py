"""Dependency scanner — uses parser for manifest parsing."""

from pathlib import Path

from skill_scanner.parser import parse_skill, validate_finding


def scan_dependencies(base: Path) -> list[dict]:
    """Scan dependency declarations and resource directories for risks."""
    findings = []
    base = Path(base).resolve()

    skill_path = base / "SKILL.md"
    if not skill_path.exists():
        return findings

    parsed = parse_skill(skill_path)
    if parsed.errors or not parsed.metadata:
        return findings

    manifest = parsed.metadata

    # Check resources directory for executable files
    resources_dir = base / "resources"
    if resources_dir.exists():
        exec_extensions = {".sh", ".py", ".js", ".rb", ".exe", ".bin", ".bat", ".ps1"}
        for item in resources_dir.rglob("*"):
            if item.is_file() and item.suffix.lower() in exec_extensions:
                findings.append({
                    "id": "RS001", "severity": "critical", "action": "block",
                    "title": "Executable file in resources directory",
                    "file": str(item.relative_to(base)),
                    "desc": f"Resources should not contain executable code: {item.suffix}",
                    "rule": "resource.executable",
                })
            elif item.is_file() and item.stat().st_mode & 0o111:
                findings.append({
                    "id": "RS002", "severity": "warning", "action": "warn",
                    "title": "File with execute permission in resources",
                    "file": str(item.relative_to(base)),
                    "desc": "Resources directory file has execute bit set",
                    "rule": "resource.executable_bit",
                })

    # CVE scan: information-only for now
    deps = manifest.get("dependencies", [])
    if isinstance(deps, str):
        deps = [deps]

    if deps:
        findings.append({
            "id": "CV000", "severity": "info", "action": "pass",
            "title": f"CVE scan: {len(deps)} dependencies (DB not configured)",
            "file": "SKILL.md",
            "desc": "CVE database integration not configured. Set SKILL_SCANNER_CVE_DB to enable.",
            "rule": "dependency.cve_pending",
        })

    return [f for f in findings if not validate_finding(f)]
