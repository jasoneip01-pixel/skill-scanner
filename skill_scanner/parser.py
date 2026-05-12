"""Parser utilities — SKILL.md front matter parser + safe path resolution."""

import os
import re
from pathlib import Path
from dataclasses import dataclass, field

MAX_SKILL_FILE_SIZE = 1 * 1024 * 1024  # 1MB


@dataclass
class ParsedSkill:
    """Parsed and validated SKILL.md."""
    metadata: dict = field(default_factory=dict)
    body: str = ""
    raw_text: str = ""
    errors: list = field(default_factory=list)
    parse_warnings: list = field(default_factory=list)


def safe_join(base: Path, rel: str) -> Path | None:
    """Safely join a path under base, preventing directory traversal and symlink escape.

    Returns None if the resolved path is outside base.
    """
    if not rel or not isinstance(rel, str):
        return None
    # Reject absolute paths
    if os.path.isabs(rel):
        return None
    # Normalize and resolve
    try:
        candidate = (base / rel).resolve()
    except (ValueError, OSError):
        return None
    root = base.resolve()
    # Check that candidate is within root
    try:
        candidate.relative_to(root)
        return candidate
    except ValueError:
        return None


def safe_resolve(path: Path) -> Path | None:
    """Resolve a path and verify it stays under its parent."""
    try:
        resolved = path.resolve()
        parent = path.parent.resolve()
        resolved.relative_to(parent)
        return resolved
    except (ValueError, OSError):
        return None


def parse_skill(path: Path) -> ParsedSkill:
    """Parse a SKILL.md file. Supports both:
    1. YAML-only (legacy): yaml.safe_load on whole file
    2. Front matter + body: ---\nYAML\n---\nMarkdown
    """
    import yaml

    if not path.exists():
        return ParsedSkill(errors=[f"File not found: {path}"])

    file_size = path.stat().st_size
    if file_size > MAX_SKILL_FILE_SIZE:
        return ParsedSkill(
            errors=[f"File too large: {file_size} bytes (max {MAX_SKILL_FILE_SIZE})"]
        )

    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError) as e:
        return ParsedSkill(errors=[f"Cannot read file: {e}"])

    stripped = raw.strip()

    # Try front matter first: ---\n...\n---
    fm_match = re.match(r"^---\s*\r?\n(.*?)\r?\n---\s*\r?\n?(.*)", stripped, re.DOTALL)

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
                "file": "SKILL.md", "rule": "manifest.missing_field",
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
                    "file": "SKILL.md", "rule": "prompt_injection.critical",
                    "snippet": val_str,
                })

    return findings


FINDING_SCHEMA = {"id", "severity", "title", "file", "rule"}


def validate_finding(f: dict) -> list[str]:
    """Validate that a finding has all required fields. Returns error list."""
    errors = []
    for key in FINDING_SCHEMA:
        if key not in f:
            errors.append(f"Missing required finding field: '{key}'")
    if "severity" in f and f["severity"] not in ("critical", "warning", "passed", "info"):
        errors.append(f"Invalid severity: {f['severity']}")
    if "action" in f and f["action"] not in ("block", "warn", "pass", "approval_required"):
        errors.append(f"Invalid action: {f['action']}")
    return errors
