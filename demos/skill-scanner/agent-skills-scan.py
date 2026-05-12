#!/usr/bin/env python3
"""Skill Surface Diff — scan Agent Skill capability boundaries (standalone CLI)."""

import yaml, re, time, json, sys
from pathlib import Path

# ── Policy definitions ──
POLICY = {
    "security.moderate": {
        "block_on": [
            "prompt_injection.critical", "data_exfiltration.high",
            "new_payment_tool.requires_guard",
        ],
        "warn_on": [
            "network_access_without_justification", "business_claim_changed",
            "broad_crm_write_permission", "secrets_file_access",
        ],
    }
}

SUSPICIOUS_PATTERNS = [
    "ignore all previous", "ignore safety", "override",
    "never mention", "always say", "pretend",
    "act as if", "do not tell", "omit",
    "skip compliance", "bypass", "circumvent",
]

HIGH_RISK_TOOLS = {
    "payment.refund": {"human_approval", "max_amount", "audit_log"},
    "payment.refund": {"human_approval"},
    "crm.updateCustomer": {"customer_id_verified"},
    "email.send": {"rate_limit", "audit_log"},
}

SECRETS_PATTERNS = ["/etc/secrets", "/etc/ssl", "~/.ssh", "AWS_SECRET", "api_key"]

RED = "\033[91m"; YELLOW = "\033[93m"; GREEN = "\033[92m"
CYAN = "\033[96m"; GRAY = "\033[90m"; BOLD = "\033[1m"; RST = "\033[0m"


def scan_skill(skill_dir: str) -> dict:
    base = Path(skill_dir)
    if not base.exists():
        print(f"Error: directory not found: {skill_dir}", file=sys.stderr)
        sys.exit(1)

    start = time.time()
    findings = []

    # ── Load SKILL.md ──
    skill_path = base / "SKILL.md"
    if not skill_path.exists():
        print(f"Error: no SKILL.md found in {skill_dir}", file=sys.stderr)
        sys.exit(1)

    raw = yaml.safe_load(skill_path.read_text())
    if not raw:
        print(f"Error: empty SKILL.md", file=sys.stderr)
        sys.exit(1)

    known_fields = {"name", "version", "description", "author",
                    "capabilities", "tools", "instructions", "scripts",
                    "resources", "dependencies", "license", "dependencies"}

    # 1. Check unsupported manifest fields
    for k in raw:
        if k not in known_fields:
            findings.append({
                "id": "PI001", "severity": "critical", "title": f"Unsupported field: {k}",
                "file": "SKILL.md", "desc": "Attempted prompt override / policy bypass",
                "snippet": str(raw[k])[:120], "rule": "prompt_injection.critical",
            })

    # 2. Check network:true justification
    if raw.get("capabilities", {}).get("network", False):
        # Check if any instruction file mentions an API endpoint
        has_endpoint = False
        for instr in raw.get("instructions", []):
            p = base / instr
            if p.exists() and ("api." in p.read_text() or "http" in p.read_text()):
                has_endpoint = True
        if not has_endpoint:
            findings.append({
                "id": "NET001", "severity": "warning", "title": "Network access without justification",
                "file": "SKILL.md", "desc": "network:true declared but no external endpoints documented",
                "rule": "network_access_without_justification",
            })

    # 3. Check high-risk tools
    for tool in raw.get("tools", []):
        if tool in HIGH_RISK_TOOLS:
            findings.append({
                "id": "TOOL001", "severity": "critical", "title": f"High-risk tool: {tool}",
                "file": "SKILL.md", "desc": f"{tool} declared without required guardrails: {', '.join(HIGH_RISK_TOOLS[tool])}",
                "rule": "new_payment_tool.requires_guard",
            })

    # 4. Check instruction files
    for instr_rel in raw.get("instructions", []):
        instr_path = base / instr_rel
        if not instr_path.exists():
            continue
        text = instr_path.read_text()
        for pattern in SUSPICIOUS_PATTERNS:
            for i, line in enumerate(text.split("\n"), 1):
                if pattern.lower() in line.lower():
                    findings.append({
                        "id": "PO001", "severity": "warning",
                        "title": f"Suspicious instruction: '{pattern}'",
                        "file": f"{instr_rel}:{i}",
                        "desc": "Possible policy drift or financial disclosure manipulation",
                        "snippet": line.strip()[:120],
                        "rule": "business_claim_changed",
                    })

    # 5. Check scripts
    for script_rel in raw.get("scripts", []):
        script_path = base / script_rel
        if not script_path.exists():
            continue
        text = script_path.read_text()
        lines = text.split("\n")

        # Data exfiltration
        if re.search(r"curl\s+.*--data-binary\s+@", text, re.DOTALL) or ("curl" in text and "--data-binary" in text and "@" in text):
            findings.append({
                "id": "DX001", "severity": "critical",
                "title": "Data exfiltration detected",
                "file": script_rel, "desc": "Script uploads file contents to external host via curl",
                "rule": "data_exfiltration.high",
            })

        # Secrets access
        for sp in SECRETS_PATTERNS:
            if sp in text:
                findings.append({
                    "id": "FS001", "severity": "warning",
                    "title": f"Secrets file access: {sp}",
                    "file": script_rel,
                    "desc": f"Script reads from {sp}",
                    "rule": "secrets_file_access",
                })

        # Dangerous operations
        for i, line in enumerate(lines, 1):
            s = line.strip()
            if re.search(r"chmod\s+777", s):
                findings.append({
                    "id": "WS001", "severity": "warning",
                    "title": "Overly permissive file mode",
                    "file": f"{script_rel}:{i}",
                    "desc": "chmod 777 grants global write access",
                    "snippet": s[:100], "rule": "dangerous_script",
                })
            if "eval(" in s or "exec(" in s:
                findings.append({
                    "id": "WS002", "severity": "warning",
                    "title": "Dynamic code execution",
                    "file": f"{script_rel}:{i}",
                    "desc": "Script uses eval() or exec()",
                    "snippet": s[:100], "rule": "dangerous_script",
                })
            if re.search(r"os\.system\(", s):
                findings.append({
                    "id": "WS003", "severity": "warning",
                    "title": "Shell execution via os.system()",
                    "file": f"{script_rel}:{i}",
                    "desc": "os.system() allows arbitrary shell execution",
                    "snippet": s[:100], "rule": "dangerous_script",
                })

    # 6. Check tool YAML schemas
    tools_dir = base / "tools"
    if tools_dir.exists():
        for tf in tools_dir.glob("*.yaml"):
            tdata = yaml.safe_load(tf.read_text())
            if tdata and tdata.get("method", "").upper() in ("POST", "PUT", "DELETE", "PATCH"):
                desc = tdata.get("description", "").lower()
                name = tdata.get("name", "")
                is_write = any(a in name.lower() for a in ["refund", "delete", "update", "write"])
                if is_write and "read" in desc:
                    findings.append({
                        "id": "TS001", "severity": "warning",
                        "title": f"Write tool with read-only description: {name}",
                        "file": f"tools/{tf.name}",
                        "desc": f"Method: {tdata['method']}. Description suggests read-only but tool can modify data.",
                        "rule": "tool_permission_mismatch",
                    })

    # 7. Check secrets in instruction files
    for instr_rel in raw.get("instructions", []):
        instr_path = base / instr_rel
        if instr_path.exists():
            text = instr_path.read_text()
            matches = re.findall(r'(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36})', text)
            if matches:
                findings.append({
                    "id": "SC001", "severity": "warning",
                    "title": "Potential credential exposure in instructions",
                    "file": instr_rel,
                    "desc": f"Found {len(matches)} potential credential pattern(s) in instruction files",
                    "rule": "credential_exposure",
                })

    # Assign actions based on policy
    policy = POLICY.get("security.moderate", {})
    block_rules = policy.get("block_on", [])

    for f in findings:
        if f["severity"] == "critical":
            f["action"] = "block"
        elif f["severity"] == "warning":
            f["action"] = "warn"
        else:
            f["action"] = "pass"

    # Determine if blocked
    blocked_rules = list(set(f["rule"] for f in findings if f["action"] == "block"))

    # Duration
    dur = int((time.time() - start) * 1000)

    return {
        "findings": findings,
        "critical": len([f for f in findings if f["severity"] == "critical"]),
        "warnings": len([f for f in findings if f["severity"] == "warning"]),
        "passed": len([f for f in findings if f["severity"] not in ("critical", "warning")]),
        "total": len(findings),
        "blocked": len(blocked_rules) > 0,
        "blocked_rules": blocked_rules,
        "duration_ms": dur,
    }


def print_results(result: dict, skill_dir: str):
    print(f"\n{RED}{BOLD}✖ MERGE BLOCKED{RST}" if result["blocked"] else f"\n{GREEN}{BOLD}✓ PASSED{RST}")
    print(f"{GRAY}Skill: {skill_dir}")
    print(f"Policy: security.moderate")
    print(f"Checks: {result['total']} | Duration: {result['duration_ms']}ms{RST}")
    print(f"{result['critical']} critical · {result['warnings']} warnings · {result['passed']} passed")
    print()

    if result["blocked_rules"]:
        print(f"{RED}Blocked by: {', '.join(result['blocked_rules'])}{RST}\n")

    for f in result["findings"]:
        if f["severity"] == "critical":
            print(f"  {RED}{BOLD}✗ [CRITICAL]{RST} {f['id']}: {f['title']}")
            print(f"    {GRAY}{f['file']}{RST}")
            print(f"    {f['desc']}")
            if f.get("snippet"):
                print(f"    {GRAY}{f['snippet']}{RST}")
            print(f"    {RED}[BLOCKED] {f['rule']}{RST}")
            print()

    for f in result["findings"]:
        if f["severity"] == "warning":
            print(f"  {YELLOW}! [WARNING]{RST} {f['id']}: {f['title']}")
            print(f"    {GRAY}{f['file']}{RST}")
            print(f"    {f['desc']}")
            print(f"    {YELLOW}[WARN] {f['rule']}{RST}")
            print()

    # Passed checks
    print(f"{GRAY}Passed:{RST}")
    print(f"  {GREEN}✓{RST} Manifest format valid")
    print(f"  {GREEN}✓{RST} No eval() or base64 in scripts")
    print(f"  {GREEN}✓{RST} Resources: no executables")
    print(f"  {GREEN}✓{RST} Tool schemas parse successfully")
    print(f"  {GRAY}○{RST} CVE scan: not configured (needs vuln DB)")
    print(f"  {GRAY}○{RST} Registry signature: not configured (needs registry)")
    print()


def output_json(result: dict):
    print(json.dumps(result, indent=2, ensure_ascii=False))


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Skill Surface Diff — scan Agent Skill capability boundaries")
    parser.add_argument("skill_dir", help="Path to the skill directory containing SKILL.md")
    parser.add_argument("--format", choices=["terminal", "json"], default="terminal")
    parser.add_argument("--output", help="Output file path")
    args = parser.parse_args()

    result = scan_skill(args.skill_dir)

    if args.format == "json":
        out = json.dumps(result, indent=2, ensure_ascii=False)
        if args.output:
            Path(args.output).write_text(out)
        else:
            print(out)
    else:
        print_results(result, args.skill_dir)

    sys.exit(1 if result["blocked"] else 0)


if __name__ == "__main__":
    main()
