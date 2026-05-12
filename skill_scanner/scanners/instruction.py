"""Instruction scanner — uses parser + safe_join for manifest-relative paths."""

import re
from pathlib import Path

from skill_scanner.parser import parse_skill, safe_join, validate_finding


SUSPICIOUS_INSTRUCTIONS = [
    "ignore all previous", "ignore safety", "never mention",
    "always say", "pretend", "act as if", "do not tell",
    "do not disclose", "omit", "skip compliance", "bypass",
    "circumvent", "without question", "without verification",
    "no matter what", "under any circumstances",
    "you must always", "you are now", "from now on you are",
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
    base = Path(base).resolve()

    skill_path = base / "SKILL.md"
    if not skill_path.exists():
        return findings

    parsed = parse_skill(skill_path)
    if parsed.errors or not parsed.metadata:
        return findings

    manifest = parsed.metadata
    instruction_files = manifest.get("instructions", [])
    if isinstance(instruction_files, str):
        instruction_files = [instruction_files]

    for instr_rel in instruction_files:
        # SAFE JOIN: prevent path traversal
        instr_path = safe_join(base, instr_rel)
        if instr_path is None or not instr_path.exists():
            findings.append({
                "id": "MF005", "severity": "warning", "action": "warn",
                "title": f"Ignored instruction file (outside skill dir): {instr_rel}",
                "file": "SKILL.md",
                "rule": "manifest.path_traversal",
            })
            continue

        try:
            text = instr_path.read_text(encoding="utf-8", errors="replace")
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
                            "desc": "Instruction may induce agent to hide information",
                            "snippet": line.strip()[:200],
                            "rule": "business_claim_changed",
                        })
                        break

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

    return [f for f in findings if not validate_finding(f)]
