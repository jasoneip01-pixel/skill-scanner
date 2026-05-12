"""Instruction scanner — detects manipulative language, bias, policy drift."""

import re
from pathlib import Path


SUSPICIOUS_INSTRUCTIONS = [
    "ignore all previous",
    "ignore safety",
    "never mention",
    "always say",
    "pretend",
    "act as if",
    "do not tell",
    "do not disclose",
    "omit",
    "skip compliance",
    "bypass",
    "circumvent",
    "without question",
    "without verification",
    "no matter what",
    "under any circumstances",
    "you must always",
    "you are now",
    "from now on you are",
    "your new role is",
]

CREDENTIAL_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API key"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
    (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
    (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token"),
    (r'xox[baprs]-[a-zA-Z0-9-]+', "Slack Token"),
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
]


def scan_instructions(base: Path) -> list[dict]:
    """Scan instruction files for manipulative language and credential leaks."""
    findings = []

    # Read manifest to find instruction file paths
    import yaml
    skill_path = base / "SKILL.md"
    if not skill_path.exists():
        return findings

    try:
        manifest = yaml.safe_load(skill_path.read_text())
    except Exception:
        return findings

    if not isinstance(manifest, dict):
        return findings

    instruction_files = manifest.get("instructions", [])
    if isinstance(instruction_files, str):
        instruction_files = [instruction_files]

    for instr_rel in instruction_files:
        instr_path = base / instr_rel
        if not instr_path.exists():
            continue
        try:
            text = instr_path.read_text()
        except Exception:
            continue

        lines = text.split("\n")

        # Suspicious instruction patterns
        for pattern in SUSPICIOUS_INSTRUCTIONS:
            if pattern.lower() in text.lower():
                for i, line in enumerate(lines, 1):
                    if pattern.lower() in line.lower():
                        findings.append({
                            "id": "PO001", "severity": "warning", "action": "warn",
                            "title": f"Suspicious instruction: '{pattern}'",
                            "file": f"{instr_rel}:{i}",
                            "desc": "Instruction may induce agent to hide information or bypass safeguards",
                            "snippet": line.strip()[:200],
                            "rule": "business_claim_changed",
                        })
                        break  # One finding per file per pattern

        # Credential exposure
        for pattern, name in CREDENTIAL_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                findings.append({
                    "id": "SC001", "severity": "critical", "action": "block",
                    "title": f"Credential exposure: {name}",
                    "file": instr_rel,
                    "desc": f"Found {len(matches)} potential {name} pattern(s)",
                    "rule": "credential_exposure",
                })

    return findings
