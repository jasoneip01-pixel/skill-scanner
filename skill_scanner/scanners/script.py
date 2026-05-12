"""Script scanner — detects data exfiltration, dangerous operations, secrets access."""

import re
from pathlib import Path

DANGEROUS_COMMANDS = [
    (r"chmod\s+777", "WS001", "Overly permissive file mode", "dangerous_script"),
    (r"rm\s+-rf\s+/", "WS002", "Destructive root-level rm -rf", "dangerous_script"),
    (r"sudo\s+", "WS003", "Privilege escalation via sudo", "dangerous_script"),
    (r"\beval\s*\(", "WS004", "Dynamic code execution via eval()", "dangerous_script"),
    (r"\bexec\s*\(", "WS005", "Dynamic code execution via exec()", "dangerous_script"),
    (r"os\.system\s*\(", "WS006", "Shell execution via os.system()", "dangerous_script"),
]

SECRETS_PATTERNS = [
    ("/etc/secrets", "Secrets mount access"),
    ("/etc/ssl/private", "SSL private key access"),
    ("~/.ssh", "SSH key access"),
    ("AWS_SECRET_ACCESS_KEY", "AWS credential"),
    ("GITHUB_TOKEN", "GitHub token"),
    ("OPENAI_API_KEY", "OpenAI API key"),
    ("ANTHROPIC_API_KEY", "Anthropic API key"),
]

EXFIL_PATTERNS = [
    # curl --data-binary @file → external URL
    (r"curl\s+.*--data-binary\s+@", "DX001", "Data exfiltration via curl", "data_exfiltration.high"),
    # wget --post-file
    (r"wget\s+.*--post-file", "DX002", "Data exfiltration via wget", "data_exfiltration.high"),
    # base64 encode + pipe to network
    (r"base64\s+.*\|\s*(curl|wget|nc)", "DX003", "Encoded data exfiltration", "data_exfiltration.high"),
    # nc / netcat to external host
    (r"nc\s+.*\d+\.\d+\.\d+\.\d+", "DX004", "Raw network connection via netcat", "suspicious_network_access"),
]


def scan_scripts(base: Path) -> list[dict]:
    """Scan all scripts in a skill directory for security issues."""
    findings = []
    scripts_dir = base / "scripts"
    if not scripts_dir.exists():
        return findings

    for script_file in scripts_dir.iterdir():
        if not script_file.is_file():
            continue
        try:
            text = script_file.read_text()
        except Exception:
            continue

        rel = f"scripts/{script_file.name}"
        lines = text.split("\n")

        # Data exfiltration checks
        for pattern, exfil_id, exfil_title, exfil_rule in EXFIL_PATTERNS:
            if re.search(pattern, text, re.DOTALL):
                matching_lines = [l.strip()[:150] for l in lines if re.search(pattern, l)]
                snippet = matching_lines[0] if matching_lines else text[:200]
                findings.append({
                    "id": exfil_id, "severity": "critical", "action": "block",
                    "title": exfil_title,
                    "file": rel,
                    "desc": f"Script may exfiltrate data to external hosts",
                    "snippet": snippet,
                    "rule": exfil_rule,
                })

        # Dangerous command checks
        for pattern, cmd_id, cmd_title, cmd_rule in DANGEROUS_COMMANDS:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    findings.append({
                        "id": cmd_id, "severity": "warning", "action": "warn",
                        "title": cmd_title,
                        "file": f"{rel}:{i}",
                        "desc": f"Line {i}: {line.strip()[:100]}",
                        "snippet": line.strip()[:150],
                        "rule": cmd_rule,
                    })

        # Secrets access checks
        for pattern, desc in SECRETS_PATTERNS:
            if pattern in text:
                findings.append({
                    "id": "FS001", "severity": "warning", "action": "warn",
                    "title": f"Secrets file access: {desc}",
                    "file": rel,
                    "desc": f"Script references {pattern}",
                    "rule": "secrets_file_access",
                })

    return findings
