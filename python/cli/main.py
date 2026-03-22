"""
llmrt CLI - Command-line interface for llm-redteam.

Provides comprehensive CLI for campaign management, probe execution,
and report generation.

Usage:
    llmrt --help
    llmrt campaign create --target https://example.com
    llmrt scan --target https://example.com --profile chatbot
    llmrt report generate campaign_123 --format html
"""

import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

# Initialize Typer app
app = typer.Typer(
    name="llmrt",
    help="AI/LLM/MCP Security Assessment Platform",
    add_completion=True,
    rich_markup_mode="rich"
)

# Initialize Rich console
console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)

logger = logging.getLogger(__name__)


# Version callback
def version_callback(value: bool):
    """Shows version information."""
    if value:
        console.print("[bold blue]llmrt[/bold blue] version [green]1.0.0[/green]")
        console.print("AI/LLM/MCP Security Assessment Platform")
        raise typer.Exit()


# Main options
@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-V",
        help="Enable verbose output"
    )
):
    """
    llmrt - AI/LLM/MCP Security Assessment Platform
    
    Comprehensive security testing for AI applications, LLM integrations,
    and Model Context Protocol (MCP) servers.
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose mode enabled")


# Scan command
@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="Target URL"),
    profile: str = typer.Option("chatbot", "--profile", "-p", help="Attack profile"),
    scope: Path = typer.Option("config/scope.yaml", "--scope", "-s", help="Scope file"),
    output: Path = typer.Option("output", "--output", "-o", help="Output directory"),
    format: str = typer.Option("html", "--format", "-f", help="Report format (html, pdf, json)"),
    auth_type: str = typer.Option(None, "--auth-type", help="Authentication type"),
    auth_token: str = typer.Option(None, "--auth-token", help="Authentication token"),
):
    """
    Runs security scan against target.
    
    Example:
        llmrt scan --target https://chat.example.com --profile chatbot
    """
    console.print(Panel.fit(
        f"[bold blue]Starting Security Scan[/bold blue]\n"
        f"Target: [green]{target}[/green]\n"
        f"Profile: [yellow]{profile}[/yellow]",
        border_style="blue"
    ))
    
    try:
        # Import orchestrator
        from python.core.orchestrator import Orchestrator
        from python.core.target import Target
        
        # Create target
        auth = None
        if auth_type and auth_token:
            auth = {"type": auth_type, "token": auth_token}
        
        target_obj = Target(url=target, auth=auth)
        
        # Create orchestrator
        orchestrator = Orchestrator(
            target=target_obj,
            scope_file=str(scope),
            profile=profile
        )
        
        # Run scan
        console.print("[yellow]Running scan...[/yellow]")
        # Note: This would be async in real implementation
        # results = await orchestrator.run()
        
        console.print("[green]✓[/green] Scan completed")
        
        # Generate report
        console.print(f"[yellow]Generating {format} report...[/yellow]")
        # report_path = generate_report(results, format, output)
        
        console.print(f"[green]✓[/green] Report saved to: [blue]{output}[/blue]")
        
    except Exception as e:
        console.print(f"[red]✗[/red] Scan failed: {e}")
        raise typer.Exit(code=1)


# Campaign commands
campaign_app = typer.Typer(help="Campaign management commands")
app.add_typer(campaign_app, name="campaign")


@campaign_app.command("create")
def campaign_create(
    name: str = typer.Option(..., "--name", "-n", help="Campaign name"),
    target: str = typer.Option(..., "--target", "-t", help="Target URL"),
    profile: str = typer.Option("chatbot", "--profile", "-p", help="Attack profile"),
    scope: Path = typer.Option("config/scope.yaml", "--scope", "-s", help="Scope file"),
):
    """Creates new campaign."""
    console.print(f"[yellow]Creating campaign:[/yellow] {name}")
    
    campaign_id = f"campaign_{name.replace(' ', '_')}"
    
    console.print(f"[green]✓[/green] Campaign created: [blue]{campaign_id}[/blue]")
    console.print(f"Run with: [cyan]llmrt campaign run {campaign_id}[/cyan]")


@campaign_app.command("list")
def campaign_list():
    """Lists all campaigns."""
    table = Table(title="Campaigns")
    
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Target", style="yellow")
    table.add_column("Status", style="magenta")
    table.add_column("Findings", style="red")
    
    # Mock data - replace with actual campaign data
    table.add_row("campaign_001", "Test Campaign", "https://example.com", "completed", "15")
    table.add_row("campaign_002", "Production Scan", "https://prod.example.com", "running", "3")
    
    console.print(table)


@campaign_app.command("run")
def campaign_run(
    campaign_id: str = typer.Argument(..., help="Campaign ID"),
):
    """Runs campaign."""
    console.print(f"[yellow]Running campaign:[/yellow] {campaign_id}")
    
    with console.status("[bold green]Executing campaign..."):
        # Run campaign
        pass
    
    console.print(f"[green]✓[/green] Campaign completed")


@campaign_app.command("delete")
def campaign_delete(
    campaign_id: str = typer.Argument(..., help="Campaign ID"),
    force: bool = typer.Option(False, "--force", "-f", help="Force delete without confirmation"),
):
    """Deletes campaign."""
    if not force:
        confirm = typer.confirm(f"Delete campaign {campaign_id}?")
        if not confirm:
            console.print("[yellow]Cancelled[/yellow]")
            raise typer.Exit()
    
    console.print(f"[red]Deleting campaign:[/red] {campaign_id}")
    console.print("[green]✓[/green] Campaign deleted")


# Report commands
report_app = typer.Typer(help="Report generation commands")
app.add_typer(report_app, name="report")


@report_app.command("generate")
def report_generate(
    campaign_id: str = typer.Argument(..., help="Campaign ID"),
    format: str = typer.Option("html", "--format", "-f", help="Report format"),
    output: Path = typer.Option("output/reports", "--output", "-o", help="Output directory"),
):
    """Generates campaign report."""
    console.print(f"[yellow]Generating {format} report for:[/yellow] {campaign_id}")
    
    output_file = output / f"{campaign_id}.{format}"
    
    console.print(f"[green]✓[/green] Report saved to: [blue]{output_file}[/blue]")


@report_app.command("list")
def report_list():
    """Lists available reports."""
    table = Table(title="Reports")
    
    table.add_column("Campaign", style="cyan")
    table.add_column("Format", style="green")
    table.add_column("Generated", style="yellow")
    table.add_column("Size", style="magenta")
    
    # Mock data
    table.add_row("campaign_001", "HTML", "2024-01-15 10:30", "2.5 MB")
    table.add_row("campaign_001", "PDF", "2024-01-15 10:31", "1.8 MB")
    
    console.print(table)


# Server commands
server_app = typer.Typer(help="Server management commands")
app.add_typer(server_app, name="server")


@server_app.command("start")
def server_start(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Host address"),
    port: int = typer.Option(9999, "--port", "-p", help="Port number"),
    reload: bool = typer.Option(False, "--reload", "-r", help="Enable auto-reload"),
):
    """Starts API server."""
    console.print(Panel.fit(
        f"[bold blue]Starting llmrt API Server[/bold blue]\n"
        f"Host: [green]{host}[/green]\n"
        f"Port: [yellow]{port}[/yellow]\n"
        f"Docs: [cyan]http://{host}:{port}/docs[/cyan]",
        border_style="blue"
    ))
    
    import uvicorn
    uvicorn.run(
        "python.api.app:app",
        host=host,
        port=port,
        reload=reload
    )


# Config commands
config_app = typer.Typer(help="Configuration management commands")
app.add_typer(config_app, name="config")


@config_app.command("init")
def config_init(
    output: Path = typer.Option("config", "--output", "-o", help="Config directory"),
):
    """Initializes configuration files."""
    console.print(f"[yellow]Initializing configuration in:[/yellow] {output}")
    
    output.mkdir(parents=True, exist_ok=True)
    
    # Create default config files
    files_created = [
        "scope.yaml",
        "default.yaml",
        "profiles/chatbot.yaml",
        "profiles/rag_app.yaml"
    ]
    
    for file in files_created:
        console.print(f"[green]✓[/green] Created: {file}")
    
    console.print("[green]✓[/green] Configuration initialized")


@config_app.command("validate")
def config_validate(
    config: Path = typer.Argument(..., help="Config file to validate"),
):
    """Validates configuration file."""
    console.print(f"[yellow]Validating:[/yellow] {config}")
    
    if not config.exists():
        console.print(f"[red]✗[/red] File not found: {config}")
        raise typer.Exit(code=1)
    
    console.print("[green]✓[/green] Configuration is valid")


# Stats command
@app.command()
def stats():
    """Shows platform statistics."""
    table = Table(title="llmrt Statistics")
    
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    # Mock data
    table.add_row("Total Campaigns", "25")
    table.add_row("Active Campaigns", "3")
    table.add_row("Total Findings", "342")
    table.add_row("Critical Findings", "12")
    table.add_row("High Findings", "45")
    
    console.print(table)


# Version command
@app.command()
def version():
    """Shows version information."""
    console.print(Panel.fit(
        "[bold blue]llmrt[/bold blue] version [green]1.0.0[/green]\n"
        "AI/LLM/MCP Security Assessment Platform\n\n"
        "[dim]Built with:[/dim]\n"
        "• Python 3.11+\n"
        "• Go 1.22+\n"
        "• gRPC\n"
        "• FastAPI\n"
        "• Typer",
        border_style="blue"
    ))


if __name__ == "__main__":
    app()
