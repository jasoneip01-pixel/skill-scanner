"""Skill Scanner CLI — agent-skills command."""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from skill_scanner.engine import scan_skill
from skill_scanner.policies import load_policy, list_policies
from skill_scanner.policy_engine import PolicyEngine
from skill_scanner.trace_engine import TraceRecorder, TraceComparator
from skill_scanner.registry import RegistryScanner
from skill_scanner.agent_surface import AgentSurfaceScanner
from skill_scanner.enterprise import ComplianceReporter, NotificationSender

console = Console(highlight=False)

SEVERITY_COLORS = {
    "critical": "red",
    "warning": "yellow",
    "passed": "green",
    "info": "dim",
}


@click.group()
@click.version_option(package_name="skill-scanner")
def main():
    """Agent Skill Scanner — detect unsafe capability expansion before Agent Skills reach production."""
    pass


@main.command()
@click.argument("skill_dir", type=click.Path(exists=True))
@click.option("--policy", "-p", default="moderate",
              help="Policy name: moderate, strict, permissive")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["terminal", "json", "sarif", "junit", "markdown"]),
              default="terminal", help="Output format")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--diff", "diff_mode", is_flag=True, help="Version diff mode (requires baseline)")
@click.option("--baseline", type=click.Path(exists=True), help="Baseline skill directory for comparison")
def scan(skill_dir, policy, output_format, output, diff_mode, baseline):
    """Run a security scan on a Skill directory.

    SKILL_DIR: Path to the skill directory containing SKILL.md
    """
    try:
        result = scan_skill(skill_dir, policy_name=policy,
                           baseline_dir=baseline, diff_mode=diff_mode)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    if output_format == "json":
        out = json.dumps(result, indent=2, ensure_ascii=False)
        if output:
            Path(output).write_text(out)
            console.print(f"[green]✓[/green] Output written to {output}")
        else:
            print(out)

    elif output_format == "sarif":
        sarif = _to_sarif(result)
        if output:
            Path(output).write_text(json.dumps(sarif, indent=2))
            console.print(f"[green]✓[/green] SARIF report written to {output}")
        else:
            print(json.dumps(sarif, indent=2))

    elif output_format == "junit":
        junit = _to_junit(result)
        if output:
            Path(output).write_text(junit)
            console.print(f"[green]✓[/green] JUnit report written to {output}")
        else:
            print(junit)

    elif output_format == "markdown":
        md = _to_markdown(result)
        if output:
            Path(output).write_text(md)
            console.print(f"[green]✓[/green] Markdown report written to {output}")
        else:
            print(md)

    else:
        _print_terminal(result, skill_dir)
        if output:
            _save_report(result, output)
            console.print(f"\n[dim]Report saved to {output}[/dim]")

    sys.exit(1 if result["blocked"] else 0)


@main.command()
@click.option("--template", "-t", default="moderate",
              type=click.Choice(["moderate", "strict", "permissive"]),
              help="Policy template to generate")
@click.option("--output", "-o", default=".agent-skills/policy.yaml",
              type=click.Path(), help="Output path")
def init(template, output):
    """Initialize a security policy for your project."""
    try:
        policy = load_policy(template)
    except FileNotFoundError:
        console.print(f"[red]Template '{template}' not found[/red]")
        sys.exit(1)

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    import yaml
    output_path.write_text(yaml.dump(policy, default_flow_style=False, sort_keys=False))
    console.print(f"[green]✓[/green] Policy initialized: {output_path}")
    console.print(f"   Template: [cyan]{template}[/cyan]")


@main.command()
def policies():
    """List available policy templates."""
    table = Table(title="Available Policies", box=box.SIMPLE)
    table.add_column("Name", style="cyan")
    table.add_column("Description")

    for name in list_policies():
        try:
            p = load_policy(name)
            desc = p.get("policy", {}).get("description", "—")
        except Exception:
            desc = "—"
        table.add_row(name, desc)

    console.print(table)


def _print_terminal(result: dict, skill_dir: str):
    """Print rich terminal output."""
    # Header
    if result["blocked"]:
        console.print(Panel(
            Text("✖ MERGE BLOCKED", style="bold red"),
            title="Skill Scanner", subtitle=f"v0.3.0"
        ))
    else:
        console.print(Panel(
            Text("✓ PASSED", style="bold green"),
            title="Skill Scanner", subtitle=f"v0.3.0"
        ))

    # Summary stats
    stats = Table(show_header=False, box=None, padding=(0, 2))
    stats.add_column(style="dim")
    stats.add_column()
    stats.add_row("Skill:", skill_dir)
    stats.add_row("Policy:", result["policy"])
    stats.add_row("Duration:", f"{result['duration_ms']}ms")
    stats.add_row("Checks:", str(result["total"]))
    console.print(stats)

    # Finding summary
    console.print(
        f"[red]{result['critical']} critical[/red] · "
        f"[yellow]{result['warnings']} warnings[/yellow] · "
        f"[green]{result['passed']} passed[/green]"
    )

    if result["blocked_rules"]:
        console.print(f"\n[red bold]Blocked by:[/red bold] {', '.join(result['blocked_rules'])}")

    # Findings table
    if result["findings"]:
        console.print()
        ftable = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        ftable.add_column("ID", style="dim", width=6)
        ftable.add_column("Severity", width=8)
        ftable.add_column("Title")
        ftable.add_column("File", style="dim")

        for f in result["findings"]:
            sev = f["severity"]
            color = SEVERITY_COLORS.get(sev, "white")
            icon = {"critical": "✗", "warning": "!", "passed": "✓", "info": "○"}.get(sev, "·")
            ftable.add_row(
                f["id"],
                f"[{color}]{icon} {sev}[/{color}]",
                f["title"],
                f["file"],
            )

        console.print(ftable)

    # Exit code hint
    if result["blocked"]:
        console.print("\n[red]❌ Scan blocked — fix critical issues before merge[/red]")
    else:
        console.print("\n[green]✅ All checks passed[/green]")


def _to_sarif(result: dict) -> dict:
    """Convert scan results to SARIF format."""
    SEVERITY_MAP = {
        "critical": "error",
        "warning": "warning",
        "passed": "note",
        "info": "note",
    }
    seen_rules = set()
    rules = []
    results = []
    for f in result["findings"]:
        # Exclude passed/info findings from SARIF results
        if f["severity"] in ("passed", "info"):
            continue
        rule_id = f["rule"]
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "shortDescription": {"text": f["title"]},
                "fullDescription": {"text": f.get("desc", "")},
                "defaultConfiguration": {"level": SEVERITY_MAP.get(f["severity"], "warning")},
            })
        # Extract line number from file field if present
        file_uri = f["file"]
        line_no = None
        if ":" in file_uri:
            parts = file_uri.rsplit(":", 1)
            if parts[-1].isdigit():
                file_uri = parts[0]
                line_no = int(parts[-1])
        loc = {"uri": file_uri}
        region = {}
        if line_no:
            region["startLine"] = line_no
        phys = {"artifactLocation": loc}
        if region:
            phys["region"] = region
        results.append({
            "ruleId": rule_id,
            "message": {"text": f["title"]},
            "locations": [{"physicalLocation": phys}],
            "level": SEVERITY_MAP.get(f["severity"], "warning"),
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Skill Scanner",
                    "version": "0.3.0",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    }


def _to_junit(result: dict) -> str:
    """Convert scan results to JUnit XML format."""
    import xml.etree.ElementTree as ET

    ts = ET.Element("testsuite", name="skill-scanner", tests=str(result["total"]),
                    failures=str(result["critical"]), errors="0")
    for f in result["findings"]:
        tc = ET.SubElement(ts, "testcase",
                           classname=f.get("rule", "unknown"),
                           name=f["title"],
                           file=f["file"])
        if f["severity"] == "critical":
            ET.SubElement(tc, "failure", message=f.get("desc", ""),
                         type="critical")
        elif f["severity"] == "warning":
            ET.SubElement(tc, "failure", message=f.get("desc", ""),
                         type="warning")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(ts, encoding="unicode")


def _to_markdown(result: dict) -> str:
    """Convert scan results to Markdown (for PR comments)."""
    lines = [f"# Skill Scanner Report\n"]
    lines.append(f"**Skill:** `{result['skill_dir']}`  ")
    lines.append(f"**Policy:** {result['policy']}  ")
    lines.append(f"**Duration:** {result['duration_ms']}ms  ")
    lines.append(f"**Status:** {'❌ BLOCKED' if result['blocked'] else '✅ PASSED'}  ")
    lines.append("")
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|-------|")
    lines.append(f"| Critical | {result['critical']} |")
    lines.append(f"| Warnings | {result['warnings']} |")
    lines.append(f"| Passed   | {result['passed']} |")
    lines.append("")
    if result["findings"]:
        lines.append("## Findings\n")
        for f in result["findings"]:
            emoji = {"critical": "❌", "warning": "⚠️", "passed": "✅", "info": "ℹ️"}
            e = emoji.get(f["severity"], "•")
            lines.append(f"- {e} **[{f['id']}]** {f['title']} (`{f['file']}`)")
            if f.get("desc"):
                lines.append(f"  - {f['desc']}")
    lines.append("")
    lines.append("---")
    lines.append(f"*Skill Scanner v0.3.0*")
    return "\n".join(lines)


def _save_report(result: dict, output: str):
    """Save terminal report to file."""
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    old_console = console.file
    console.file = buf
    try:
        _print_terminal(result, result["skill_dir"])
    finally:
        console.file = old_console

    Path(output).write_text(buf.getvalue())


# ── Phase 2: Trace commands ──

@main.group()
def trace():
    """Record and compare Agent tool call traces."""
    pass


@trace.command()
@click.argument("skill_name")
@click.argument("version")
@click.option("--input", "-i", "trace_file", type=click.Path(exists=True),
              help="JSON trace file to record as baseline")
def record(skill_name, version, trace_file):
    """Record a tool trace as baseline for a skill version."""
    try:
        calls = json.loads(Path(trace_file).read_text())
        if not isinstance(calls, list):
            calls = calls.get("calls", [])
    except Exception as e:
        console.print(f"[red]Error reading trace file:[/red] {e}")
        sys.exit(1)

    recorder = TraceRecorder()
    tid = recorder.record(skill_name, version, calls)
    console.print(f"[green]✓[/green] Trace recorded: [cyan]{tid}[/cyan]")
    console.print(f"   {len(calls)} tool calls recorded")


@trace.command()
@click.argument("current_trace", type=click.Path(exists=True))
@click.option("--baseline-trace", "-b", required=True,
              help="Baseline trace ID or file to compare against")
def diff(current_trace, baseline_trace):
    """Compare two traces to detect capability drift."""
    recorder = TraceRecorder()

    # Load baseline
    baseline = recorder.load(baseline_trace)
    if not baseline:
        try:
            baseline = json.loads(Path(baseline_trace).read_text())
        except Exception:
            console.print(f"[red]Baseline trace not found:[/red] {baseline_trace}")
            sys.exit(1)

    # Load current
    try:
        current = json.loads(Path(current_trace).read_text())
    except Exception as e:
        console.print(f"[red]Error reading current trace:[/red] {e}")
        sys.exit(1)

    result = TraceComparator.compare(baseline, current)

    if result["blocked"]:
        console.print(Panel(Text("✖ CAPABILITY DRIFT DETECTED", style="bold red"), title="Trace Diff"))
    else:
        console.print(Panel(Text("✓ No significant drift", style="bold green"), title="Trace Diff"))

    console.print(f"[dim]{result['summary']}[/dim]")

    if result["diffs"]:
        console.print()
        for d in result["diffs"]:
            sev_color = "red" if d["severity"] == "critical" else "yellow"
            console.print(f"  [{sev_color}]{d['severity']:8s}[/{sev_color}] {d['detail']}")


# ── Phase 3: Registry commands ──

@main.group()
def registry():
    """Scan and monitor public Skill registries."""
    pass


@registry.command()
@click.option("--query", "-q", default="SKILL.md", help="Search query")
@click.option("--max", "-n", default=10, help="Max results")
def discover(query, max):
    """Discover skills from GitHub code search."""
    scanner = RegistryScanner()
    results = scanner.discover_from_github(query, max)

    if not results:
        console.print("[yellow]No skills discovered. Set GITHUB_TOKEN env var for GitHub search.[/yellow]")
        return

    console.print(f"[green]Found {len(results)} skills:[/green]\n")
    for r in results:
        console.print(f"  • [cyan]{r['repo']}[/cyan] — {r['path']}")


@registry.command()
@click.argument("url")
def scan_url(url):
    """Fetch and scan a skill from a raw URL."""
    scanner = RegistryScanner()
    result = scanner.scan_registry_skill(url)

    if result is None:
        console.print(f"[red]Failed to fetch or scan:[/red] {url}")
        sys.exit(1)

    _print_terminal(result, url)


@registry.command()
def stats():
    """Show registry statistics."""
    scanner = RegistryScanner()
    stats = scanner.sync_stats()

    table = Table(title="Registry Stats", box=box.SIMPLE)
    table.add_column("Metric", style="dim")
    table.add_column("Value")
    table.add_row("Skills indexed", str(stats["total_skills"]))
    table.add_row("Malicious reports", str(stats["malicious_reports"]))
    table.add_row("Last sync", str(stats.get("last_sync", "never")))
    console.print(table)


# ── Phase 4: Agent surface & enterprise commands ──

@main.command()
@click.argument("agent_dir", type=click.Path(exists=True))
@click.option("--policy", "-p", default="moderate", help="Policy level")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["terminal", "json"]), default="terminal")
def audit(agent_dir, policy, output_format):
    """Full agent surface audit — scan all 7 dimensions.

    AGENT_DIR: Path to the agent project directory.
    """
    try:
        scanner = AgentSurfaceScanner(agent_dir)
        result = scanner.scan_all(policy)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    if output_format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(1 if result["verdict"] == "blocked" else 0)

    # Terminal output
    blocked = result["verdict"] == "blocked"
    if blocked:
        console.print(Panel(Text("✖ AGENT RELEASE BLOCKED", style="bold red"), title="Agent Surface Audit"))
    else:
        console.print(Panel(Text("✓ AGENT RELEASE APPROVED", style="bold green"), title="Agent Surface Audit"))

    console.print(f"[dim]Scanned {len(result['dimensions'])} dimensions | {result['total_critical']} critical · {result['total_warnings']} warnings[/dim]")

    if result["blocked_dimensions"]:
        console.print(f"\n[red bold]Blocked dimensions:[/red bold] {', '.join(result['blocked_dimensions'])}")

    # Dimension summary
    console.print()
    dtable = Table(box=box.SIMPLE)
    dtable.add_column("Dimension", style="cyan")
    dtable.add_column("Status")
    dtable.add_column("Critical")
    dtable.add_column("Warnings")
    dtable.add_column("Details")

    for dim, dresult in result["dimensions"].items():
        status = dresult.get("status", "unknown")
        status_color = "green" if status == "passed" else "red"
        dtable.add_row(
            dim,
            f"[{status_color}]{status}[/{status_color}]",
            str(dresult.get("critical", 0)),
            str(dresult.get("warnings", 0)),
            dresult.get("message", dresult.get("note", "—")),
        )

    console.print(dtable)
    sys.exit(1 if blocked else 0)


@main.command()
@click.argument("agent_dir", type=click.Path(exists=True))
@click.option("--framework", "-f", default="soc2",
              type=click.Choice(ComplianceReporter.FRAMEWORKS))
@click.option("--format", "output_format",
              type=click.Choice(["terminal", "json"]),
              default="terminal", help="Output format")
@click.option("--output", "-o", type=click.Path(), help="Output file")
def compliance(agent_dir, framework, output_format, output):
    """Generate compliance audit report (SOC2, GDPR, PCI-DSS).

    AGENT_DIR: Path to the agent project directory.
    """
    try:
        scanner = AgentSurfaceScanner(agent_dir)
        scan_results = scanner.scan_all()
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    report = ComplianceReporter.generate(scan_results, framework)

    if output_format == "json" or output:
        text = json.dumps(report, indent=2, ensure_ascii=False)
        if output:
            Path(output).write_text(text)
            console.print(f"[green]✓[/green] Compliance report saved: {output}")
        else:
            print(text)
    else:
        console.print(f"\n[bold]Compliance Report: {framework.upper()}[/bold]")
        console.print(f"Score: {report['compliance_score']}% | Verdict: {report['overall_verdict']}")
        for sec in report["sections"]:
            color = "green" if sec["status"] == "compliant" else "red"
            console.print(f"  [{color}]{sec['control_id']}[/{color}] {sec['control_name']}: {sec['status']}")

    if report["remediation_required"]:
        console.print(f"[red]{len(report['remediation_required'])} controls need remediation[/red]")


@main.command()
@click.argument("skill_dir", type=click.Path(exists=True))
@click.option("--slack", help="Slack webhook URL")
@click.option("--teams", help="Teams webhook URL")
def notify(skill_dir, slack, teams):
    """Send scan results to Slack/Teams."""
    try:
        result = scan_skill(skill_dir)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    notifier = NotificationSender()
    sent = False

    if slack:
        if notifier.send_slack(slack, result):
            console.print("[green]✓[/green] Slack notification sent")
            sent = True
        else:
            console.print("[red]✗[/red] Slack notification failed")

    if teams:
        if notifier.send_teams(teams, result):
            console.print("[green]✓[/green] Teams notification sent")
            sent = True
        else:
            console.print("[red]✗[/red] Teams notification failed")

    if not sent:
        console.print("[yellow]No webhook URLs provided. Set --slack or --teams.[/yellow]")
