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
        result = scan_skill(skill_dir, policy_name=policy)
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
            title="Skill Scanner", subtitle=f"v0.2.0"
        ))
    else:
        console.print(Panel(
            Text("✓ PASSED", style="bold green"),
            title="Skill Scanner", subtitle=f"v0.2.0"
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
    rules = []
    results = []
    for f in result["findings"]:
        rule_id = f["rule"]
        rules.append({
            "id": rule_id,
            "shortDescription": {"text": f["title"]},
            "fullDescription": {"text": f.get("desc", "")},
            "defaultConfiguration": {"level": f["severity"]},
        })
        results.append({
            "ruleId": rule_id,
            "message": {"text": f["title"]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f["file"]}
            }}],
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Skill Scanner",
                    "version": "0.2.0",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    }


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
