"""Manifest scanner — uses parser module for front matter + body support."""

import re
from pathlib import Path

from skill_scanner.parser import parse_skill, validate_frontmatter


def scan_manifest(base: Path, skill_path: Path) -> list[dict]:
    """Scan SKILL.md manifest for prompt injection and policy bypass."""
    findings = []

    # Parse SKILL.md (supports both front matter and YAML-only)
    parsed = parse_skill(skill_path)
    metadata = parsed.metadata

    if parsed.parse_warnings:
        for w in parsed.parse_warnings:
            findings.append({
                "id": "MF001", "severity": "critical", "action": "block",
                "title": "Invalid SKILL.md",
                "file": "SKILL.md",
                "desc": w,
                "rule": "manifest.invalid_yaml",
            })
        return findings

    if not metadata or not isinstance(metadata, dict):
        findings.append({
            "id": "MF002", "severity": "critical", "action": "block",
            "title": "Empty or invalid SKILL.md",
            "file": "SKILL.md",
            "desc": "SKILL.md did not yield valid YAML metadata",
            "rule": "manifest.empty",
        })
        return findings

    # Validate front matter structure
    findings.extend(validate_frontmatter(metadata))

    # Validate version format (semver)
    version = metadata.get("version", "")
    if version and not re.match(r"^\d+\.\d+\.\d+", str(version)):
        findings.append({
            "id": "MF004", "severity": "info", "action": "pass",
            "title": "Non-semver version format",
            "file": "SKILL.md",
            "desc": f"Version '{version}' does not follow semver (x.y.z)",
            "rule": "manifest.version_format",
        })

    # Check if Markdown body contains suspicious content
    if parsed.body:
        body_lower = parsed.body.lower()
        suspicious_body_patterns = [
            ("ignore all previous", "Attempts to override prior instructions"),
            ("always do what i say", "Blind obedience instruction"),
            ("you are now", "Role rewrite attempt"),
            ("from now on", "Temporal override attempt"),
        ]
        for pattern, desc in suspicious_body_patterns:
            if pattern in body_lower:
                findings.append({
                    "id": "PI003", "severity": "warning", "action": "warn",
                    "title": f"Markdown body: '{pattern}'",
                    "file": "SKILL.md",
                    "desc": desc,
                    "rule": "business_claim_changed",
                })

    # Pass check: manifest parsed successfully
    findings.append({
        "id": "MF000", "severity": "passed", "action": "pass",
        "title": "Manifest parsed",
        "file": "SKILL.md",
        "desc": f"Format: {'front matter' if parsed.body else 'yaml-only'} | Skill: {metadata.get('name', '?')} v{metadata.get('version', '?')}",
        "rule": "manifest.basic",
    })

    return findings
