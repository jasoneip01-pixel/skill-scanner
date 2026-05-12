"""Manifest scanner — detects prompt injection, unsupported fields, hidden directives."""

import yaml
import re
from pathlib import Path

SUSPICIOUS_FIELDS = {
    "system_prompt", "system_prompt_append", "ignore_safety",
    "ignore_all_previous", "override_policy", "bypass_guardrails",
    "hidden_instructions", "hidden_prompt",
}

# Fields expected in a standard SKILL.md manifest
KNOWN_FIELDS = {
    "name", "version", "description", "author", "license",
    "capabilities", "tools", "instructions", "scripts",
    "resources", "dependencies", "dependencies",
}


def scan_manifest(base: Path, skill_path: Path) -> list[dict]:
    """Scan SKILL.md manifest for prompt injection and policy bypass."""
    findings = []

    try:
        raw = yaml.safe_load(skill_path.read_text())
    except yaml.YAMLError as e:
        return [{
            "id": "MF001", "severity": "critical", "action": "block",
            "title": "Invalid SKILL.md YAML",
            "file": "SKILL.md",
            "desc": f"YAML parse error: {e}",
            "rule": "manifest.invalid_yaml",
        }]

    if not raw or not isinstance(raw, dict):
        return [{
            "id": "MF002", "severity": "critical", "action": "block",
            "title": "Empty or invalid SKILL.md",
            "file": "SKILL.md",
            "desc": "SKILL.md must be a valid YAML dictionary",
            "rule": "manifest.empty",
        }]

    # Check for suspicious / hidden fields
    for field in SUSPICIOUS_FIELDS:
        if field in raw:
            findings.append({
                "id": "PI001", "severity": "critical", "action": "block",
                "title": f"Prompt injection via '{field}' field",
                "file": "SKILL.md",
                "desc": f"Field '{field}' can override agent safety instructions",
                "snippet": str(raw[field])[:200],
                "rule": "prompt_injection.critical",
            })

    # Check for unknown fields (potential prompt injection via non-standard fields)
    for key in raw:
        if key not in KNOWN_FIELDS and key not in SUSPICIOUS_FIELDS:
            val_str = str(raw[key])[:200]
            # Detect if the unknown field looks like a prompt override
            if any(p in val_str.lower() for p in ["always", "never", "ignore", "pretend"]):
                findings.append({
                    "id": "PI002", "severity": "critical", "action": "block",
                    "title": f"Suspicious unknown field: '{key}'",
                    "file": "SKILL.md",
                    "desc": f"Non-standard field contains prompt-like content",
                    "snippet": val_str,
                    "rule": "prompt_injection.critical",
                })

    # Check required fields
    for required in ["name", "version", "description"]:
        if required not in raw:
            findings.append({
                "id": "MF003", "severity": "warning", "action": "warn",
                "title": f"Missing required field: '{required}'",
                "file": "SKILL.md",
                "desc": f"SKILL.md should include '{required}' field",
                "rule": "manifest.missing_field",
            })

    # Validate version format (semver)
    version = raw.get("version", "")
    if version and not re.match(r"^\d+\.\d+\.\d+", str(version)):
        findings.append({
            "id": "MF004", "severity": "info", "action": "pass",
            "title": "Non-semver version format",
            "file": "SKILL.md",
            "desc": f"Version '{version}' does not follow semver (x.y.z)",
            "rule": "manifest.version_format",
        })

    # All clear on manifest basics
    findings.append({
        "id": "MF000", "severity": "passed", "action": "pass",
        "title": "Manifest structure valid",
        "file": "SKILL.md",
        "desc": f"Skill: {raw.get('name', 'unknown')} v{raw.get('version', '?')}",
        "rule": "manifest.basic",
    })

    return findings
