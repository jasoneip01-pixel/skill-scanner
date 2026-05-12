"""Permission scanner — uses parser + safe_join for all manifest-relative paths."""

from pathlib import Path

from skill_scanner.parser import parse_skill, safe_join, validate_finding


HIGH_RISK_TOOLS = {
    "payment.refund": {"required_guards": ["human_approval", "max_amount", "audit_log"]},
    "payment.charge": {"required_guards": ["max_amount", "rate_limit"]},
    "crm.updateCustomer": {"required_guards": ["customer_id_verified"]},
    "crm.deleteCustomer": {"required_guards": ["human_approval", "audit_log"]},
    "email.send": {"required_guards": ["rate_limit", "audit_log"]},
    "email.send_bulk": {"required_guards": ["human_approval", "rate_limit"]},
    "database.execute": {"required_guards": ["read_only_schema", "reviewed_query"]},
    "file.delete": {"required_guards": ["human_approval", "audit_log"]},
}

WRITE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}


def scan_permissions(base: Path) -> list[dict]:
    """Scan tool definitions and permissions for overreach and mismatches."""
    findings = []
    base = Path(base).resolve()

    skill_path = base / "SKILL.md"
    if not skill_path.exists():
        return findings

    parsed = parse_skill(skill_path)
    if parsed.errors or not parsed.metadata:
        return findings

    manifest = parsed.metadata

    # Check declared capabilities vs network justification
    capabilities = manifest.get("capabilities", {})
    if isinstance(capabilities, dict) and capabilities.get("network", False):
        has_endpoint = False
        instructions = manifest.get("instructions", [])
        if isinstance(instructions, str):
            instructions = [instructions]
        for instr in instructions:
            p = safe_join(base, instr)
            if p and p.exists():
                txt = p.read_text(encoding="utf-8", errors="replace")
                if "api." in txt.lower() or "http://" in txt or "https://" in txt:
                    has_endpoint = True
                    break
        if not has_endpoint:
            findings.append({
                "id": "NET001", "severity": "warning", "action": "warn",
                "title": "Network access declared without justification",
                "file": "SKILL.md",
                "desc": "network:true but no external API endpoints documented in instructions",
                "rule": "network_access_without_justification",
            })

    # Check declared tools against high-risk registry
    tools = manifest.get("tools", [])
    if isinstance(tools, str):
        tools = [tools]
    for tool_name in tools:
        if tool_name in HIGH_RISK_TOOLS:
            guards = HIGH_RISK_TOOLS[tool_name]["required_guards"]
            findings.append({
                "id": "TOOL001", "severity": "critical", "action": "block",
                "title": f"High-risk tool without guardrails: {tool_name}",
                "file": "SKILL.md",
                "desc": f"Required guards: {', '.join(guards)}",
                "rule": "new_payment_tool.requires_guard",
            })

    # Scan individual tool YAML files for write/read mismatches
    import yaml
    tools_dir = base / "tools"
    if tools_dir.exists():
        for tf in tools_dir.glob("*.yaml"):
            if not tf.is_file():
                continue
            try:
                tdata = yaml.safe_load(tf.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue
            if not isinstance(tdata, dict):
                continue

            method = tdata.get("method", "").upper()
            name = tdata.get("name", "")
            desc = (tdata.get("description", "") or "").lower()

            if method in WRITE_METHODS:
                is_destructive = any(w in name.lower() for w in
                    ["refund", "delete", "update", "write", "destroy", "remove"])
                if is_destructive and "read" in desc:
                    findings.append({
                        "id": "TS001", "severity": "warning", "action": "warn",
                        "title": f"Write tool with read-only description: {name}",
                        "file": f"tools/{tf.name}",
                        "desc": f"HTTP {method} — description says 'read' but tool can modify data",
                        "rule": "tool_permission_mismatch",
                    })

    return [f for f in findings if not validate_finding(f)]
