import json
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agents.triage_agent import TriageAgent
from agents.investigator_agent import InvestigatorAgent
from agents.responder_agent import ResponderAgent
from core.alert import Alert, Severity

console = Console()


def load_alerts(file_path: str) -> list[Alert]:
    with open(file_path) as f:
        data = json.load(f)
    return [Alert.from_dict(a) for a in data]


def display_triage_results(results):
    table = Table(title="Alert Triage Results", show_header=True)
    table.add_column("Alert ID", style="cyan")
    table.add_column("Title", style="white", max_width=40)
    table.add_column("Score", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("FP?", justify="center")
    table.add_column("Confidence", justify="center")

    severity_colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "info": "blue",
    }

    for r in results:
        sev = r.assigned_severity.value
        color = severity_colors.get(sev, "white")
        table.add_row(
            r.alert_id,
            r.reasoning[:40] + "..." if len(r.reasoning) > 40 else r.reasoning,
            str(r.severity_score),
            f"[{color}]{sev.upper()}[/{color}]",
            "Yes" if r.is_false_positive else "No",
            f"{r.confidence:.0%}",
        )

    console.print(table)


def display_investigation(investigation):
    console.print(Panel(f"[bold]Investigation: {investigation.alert_id}[/bold]"))

    if investigation.findings:
        console.print("\n[bold cyan]Findings:[/bold cyan]")
        for f in investigation.findings:
            console.print(f"  - {f}")

    if investigation.timeline:
        console.print("\n[bold cyan]Attack Timeline:[/bold cyan]")
        for event in investigation.timeline:
            console.print(f"  {event}")

    if investigation.root_cause:
        console.print(f"\n[bold cyan]Root Cause:[/bold cyan] {investigation.root_cause}")

    if investigation.risk_assessment:
        console.print(f"\n[bold red]Risk Assessment:[/bold red] {investigation.risk_assessment}")

    if investigation.recommendations:
        console.print("\n[bold cyan]Recommendations:[/bold cyan]")
        for rec in investigation.recommendations:
            console.print(f"  - {rec}")


def display_response_plan(actions):
    table = Table(title="Response Plan", show_header=True)
    table.add_column("#", justify="center", style="cyan")
    table.add_column("Action", style="white")
    table.add_column("Target", style="yellow")
    table.add_column("Description", max_width=50)
    table.add_column("Approval", justify="center")

    for i, action in enumerate(actions, 1):
        table.add_row(
            str(i),
            action.action_type,
            action.target,
            action.description,
            "[red]Required[/red]" if action.requires_approval else "[green]Auto[/green]",
        )

    console.print(table)


@click.group()
def cli():
    pass


@cli.command()
@click.option("--file", "-f", default="samples/sample_alerts.json", help="Path to alerts JSON file")
@click.option("--mock", is_flag=True, default=True, help="Use mock LLM for demo")
def triage(file, mock):
    """Triage alerts."""
    console.print(Panel("[bold]Agentic SOC - Alert Triage[/bold]", style="blue"))

    alerts = load_alerts(file)
    console.print(f"Loaded {len(alerts)} alerts\n")

    agent = TriageAgent(use_mock=mock)
    results = agent.batch_triage(alerts)
    display_triage_results(results)

    critical_count = sum(1 for r in results if r.assigned_severity == Severity.CRITICAL)
    high_count = sum(1 for r in results if r.assigned_severity == Severity.HIGH)

    if critical_count or high_count:
        console.print(
            f"\n[bold red]Action Required: {critical_count} critical, {high_count} high severity alerts[/bold red]"
        )


@cli.command()
@click.option("--file", "-f", default="samples/sample_alerts.json", help="Path to alerts JSON file")
@click.option("--alert-id", "-a", default=None, help="Specific alert ID to investigate")
@click.option("--mock", is_flag=True, default=True, help="Use mock LLM for demo")
def investigate(file, alert_id, mock):
    """Investigate an alert."""
    console.print(Panel("[bold]Agentic SOC - Investigation[/bold]", style="yellow"))

    alerts = load_alerts(file)

    if alert_id:
        alerts = [a for a in alerts if a.alert_id == alert_id]
        if not alerts:
            console.print(f"[red]Alert {alert_id} not found[/red]")
            return

    triage_agent = TriageAgent(use_mock=mock)
    investigator = InvestigatorAgent(use_mock=mock)

    for alert in alerts[:1]:
        console.print(f"Triaging alert: {alert.alert_id}...")
        triage_result = triage_agent.triage(alert)

        console.print(f"Investigating alert: {alert.alert_id}...\n")
        investigation = investigator.investigate(alert, triage_result)
        display_investigation(investigation)


@cli.command()
@click.option("--file", "-f", default="samples/sample_alerts.json", help="Path to alerts JSON file")
@click.option("--alert-id", "-a", default=None, help="Specific alert ID to respond to")
@click.option("--mock", is_flag=True, default=True, help="Use mock LLM for demo")
def respond(file, alert_id, mock):
    """Generate a response plan."""
    console.print(Panel("[bold]Agentic SOC - Incident Response[/bold]", style="red"))

    alerts = load_alerts(file)

    if alert_id:
        alerts = [a for a in alerts if a.alert_id == alert_id]
        if not alerts:
            console.print(f"[red]Alert {alert_id} not found[/red]")
            return

    triage_agent = TriageAgent(use_mock=mock)
    investigator = InvestigatorAgent(use_mock=mock)
    responder = ResponderAgent(use_mock=mock)

    alert = alerts[0]
    console.print(f"Processing alert: {alert.alert_id}")
    console.print("Step 1/3: Triaging...")
    triage_result = triage_agent.triage(alert)

    console.print("Step 2/3: Investigating...")
    investigation = investigator.investigate(alert, triage_result)

    console.print("Step 3/3: Planning response...\n")
    actions = responder.plan_response(alert, investigation)
    display_response_plan(actions)


if __name__ == "__main__":
    cli()
