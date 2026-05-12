# Skill Scanner Rego Policy (OPA-compatible)
#
# Use: opa eval --data policy.rego --input findings.json "data.skill_scanner"
#
package skill_scanner

# Default: allow unless explicitly blocked
default allow = true

# Block if any finding has action="block"
blocked_rules[r] {
    finding := input.findings[_]
    finding.action == "block"
    r := finding.rule
}

# Override allow if any finding is blocked
allow = false {
    count(blocked_rules) > 0
}

# Risk score — weighted sum
risk_score = s {
    critical_count := count([f | f := input.findings[_]; f.severity == "critical"])
    warning_count := count([f | f := input.findings[_]; f.severity == "warning"])
    s := critical_count * 40 + warning_count * 15
}

# Block conditions
violations[msg] {
    finding := input.findings[_]
    finding.action == "block"
    msg := sprintf("BLOCKED: %s — %s", [finding.rule, finding.title])
}

# Warning conditions
warnings[msg] {
    finding := input.findings[_]
    finding.action == "warn"
    msg := sprintf("WARNING: %s — %s", [finding.rule, finding.title])
}
