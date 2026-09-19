"""
MCPry CLI — Command-line interface.

Provides the `mcpry` command with subcommands for scanning MCP servers,
viewing OWASP reference info, and managing configuration.
"""

import typer
from rich.console import Console

from mcpry import __version__
from mcpry.config import APP_NAME, APP_TAGLINE

app = typer.Typer(
    name="mcpry",
    help=f"{APP_NAME} — {APP_TAGLINE}",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="Path to MCP server source code or GitHub repository URL.",
    ),
    format: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json, or html.",
    ),
    output: str = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path (for json/html formats).",
    ),
    no_llm: bool = typer.Option(
        False,
        "--no-llm",
        help="Run static analysis only (no Gemini API calls).",
    ),
    severity: str = typer.Option(
        None,
        "--severity",
        "-s",
        help="Minimum severity to display: critical, high, medium, low, info.",
    ),
) -> None:
    """Scan an MCP server for security vulnerabilities."""
    console.print(
        f"\n[bold cyan]🔍 {APP_NAME}[/bold cyan] [dim]v{__version__}[/dim]"
    )
    console.print(f"[dim]{APP_TAGLINE}[/dim]\n")
    console.print(f"[yellow]⏳ Scanning:[/yellow] {target}\n")

    # TODO: Wire up the full scan pipeline in subsequent phases
    console.print("[dim]Scanner engine will be wired up in the next build phase.[/dim]")


@app.command()
def version() -> None:
    """Show MCPry version."""
    console.print(f"[bold cyan]{APP_NAME}[/bold cyan] v{__version__}")


@app.command(name="owasp-info")
def owasp_info() -> None:
    """Print OWASP MCP Top 10 reference information."""
    from rich.table import Table
    from mcpry.models import OWASPCategory

    table = Table(
        title=f"🛡️  OWASP MCP Top 10 (2025)",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("ID", style="bold", width=8)
    table.add_column("Title", style="white")
    table.add_column("Description", style="dim")

    for cat in OWASPCategory:
        table.add_row(cat.value, cat.title, cat.description)

    console.print(table)
    console.print()


if __name__ == "__main__":
    app()
