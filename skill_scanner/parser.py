"""SKILL.md parser — supports YAML front matter + Markdown body.

Real Agent Skill files are typically:
    ---
    name: my-skill
    version: 1.0.0
    ...
    ---
    Markdown instruction body here ...
"""

import re
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParsedSkill:
    """Parsed and validated SKILL.md."""
    metadata: dict = field(default_factory=dict)
    body: str = ""
    raw_text: str = ""
    parse_warnings: list = field(default_factory=list)


def parse_skill(path: Path) -> ParsedSkill:
    """Parse a SKILL.md file. Supports both:
    1. YAML-only (legacy): yaml.safe_load on whole file
    2. Front matter + body: ---\nYAML\n---\nMarkdown
    """
    raw = path.read_text(encoding="utf-8")
    stripped = raw.strip()

    # Try front matter first: ---\n...\n---
    fm_match = re.match(r"^---\s*\n(.*?)\n---\s*\n?(.*)", stripped, re.DOTALL)

    if fm_match:
        yaml_text = fm_match.group(1)
        body = fm_match.group(2).strip()
        try:
            metadata = yaml.safe_load(yaml_text)
            if not isinstance(metadata, dict):
                metadata = {}
        except yaml.YAMLError as e:
            return ParsedSkill(
                metadata={},
                body=body,
                raw_text=raw,
                parse_warnings=[f"YAML front matter parse error: {e}"],
            )
        return ParsedSkill(metadata=metadata, body=body, raw_text=raw)

    # Fallback: treat entire file as YAML (legacy single-file format)
    try:
        metadata = yaml.safe_load(stripped)
        if not isinstance(metadata, dict):
            metadata = {}
        return ParsedSkill(metadata=metadata, body="", raw_text=raw)
    except yaml.YAMLError as e:
        return ParsedSkill(
            metadata={},
            body="",
            raw_text=raw,
            parse_warnings=[f"YAML parse error: {e}"],
        )


def validate_frontmatter(metadata: dict) -> list[dict]:
    """Validate parsed metadata structure. Returns findings."""
    findings = []
    SUSPICIOUS = {
        "system_prompt", "system_prompt_append", "ignore_safety",
        "ignore_all_previous", "override_policy", "bypass_guardrails",
    }
    KNOWN = {
        "name", "version", "description", "author", "license",
        "capabilities", "tools", "instructions", "scripts",
        "resources", "dependencies",
    }

    # Required fields
    for req in ("name", "version"):
        if req not in metadata:
            findings.append({
                "id": "MF003", "severity": "warning", "action": "warn",
                "title": f"Missing required field: '{req}'",
                "file": "SKILL.md",
                "rule": "manifest.missing_field",
            })

    # Suspicious fields
    for field in SUSPICIOUS:
        if field in metadata:
            findings.append({
                "id": "PI001", "severity": "critical", "action": "block",
                "title": f"Prompt injection via '{field}' field",
                "file": "SKILL.md",
                "desc": f"Field '{field}' can override agent safety instructions",
                "snippet": str(metadata[field])[:200],
                "rule": "prompt_injection.critical",
            })

    # Unknown fields with suspicious content
    for key in metadata:
        if key not in KNOWN and key not in SUSPICIOUS:
            val_str = str(metadata[key])[:200]
            if any(p in val_str.lower() for p in ["always", "never", "ignore", "pretend"]):
                findings.append({
                    "id": "PI002", "severity": "critical", "action": "block",
                    "title": f"Suspicious unknown field: '{key}'",
                    "file": "SKILL.md",
                    "rule": "prompt_injection.critical",
                    "snippet": val_str,
                })

    return findings
