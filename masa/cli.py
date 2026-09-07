"""Command-line interface.

Exit codes are chosen for CI use:
  0  scan completed, nothing at or above the --fail-on threshold
  1  scan completed, findings at or above the threshold
  2  the package was refused (invalid, or a safety limit was hit)
  3  an unexpected error
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from masa import __version__
from masa.analyzers import all_analyzers
from masa.config import DEFAULT_LIMITS, ScanConfig
from masa.errors import MasaError, ValidationError
from masa.models import OWASP_MOBILE_TOP_10, Report, Severity
from masa.patterns import SECRET_RULES
from masa.report import PdfUnavailable, write_html, write_json, write_pdf
from masa.runner import scan as run_scan

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=(
        "Static security analysis for Android APKs and iOS IPAs, mapped to the "
        "OWASP Mobile Top 10 (2024) and MASVS.\n\n"
        "Analyse only applications you own or are explicitly authorised to test."
    ),
)
console = Console()
err_console = Console(stderr=True)

_LEGAL_NOTICE = (
    "[bold]Authorised use only.[/bold] This tool is for analysing applications you "
    "own or have explicit written authorisation to test. Unauthorised analysis of "
    "third-party applications may violate their terms of service or the law in your "
    "jurisdiction.\n\n"
    "Analysis is [bold]static only[/bold]: the package is decompiled and pattern "
    "matched, never installed or executed. Everything stays on this machine — no "
    "package contents are transmitted anywhere."
)

_SEVERITY_STYLE = {
    "Critical": "bold red",
    "High": "red",
    "Medium": "yellow",
    "Low": "cyan",
    "Info": "dim",
}


def _notice_marker() -> Path:
    return Path.home() / ".cache" / "mobile-app-security-analyzer" / "notice-shown"


def _show_notice_once(force: bool = False) -> None:
    marker = _notice_marker()
    if not force and marker.exists():
        return
    console.print(Panel(_LEGAL_NOTICE, title="Before you scan", border_style="yellow"))
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    except OSError:
        pass  # a read-only home is not a reason to fail the scan


@app.command()
def scan(
    target: Path = typer.Argument(
        ..., help="Path to the .apk or .ipa to analyse.", exists=False
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write the report here (extension picks the format)."
    ),
    fmt: str = typer.Option(
        "terminal", "--format", "-f",
        help="terminal | html | json | pdf | all. 'all' writes HTML and JSON.",
    ),
    fail_on: str = typer.Option(
        "none", "--fail-on",
        help="Exit 1 when a finding of this severity or higher is present "
             "(critical|high|medium|low|info|none).",
    ),
    severity: str = typer.Option(
        "info", "--severity", "-s", help="Lowest severity to report."
    ),
    online: bool = typer.Option(
        False, "--online",
        help="Allow OSV.dev lookups for bundled libraries. Only library names and "
             "versions are sent; never file contents.",
    ),
    keep_artifacts: bool = typer.Option(
        False, "--keep-artifacts",
        help="Keep the decompiled tree on disk for your own review.",
    ),
    workdir: Optional[Path] = typer.Option(
        None, "--workdir", help="Parent directory for the sandbox (default: system temp)."
    ),
    no_external_tools: bool = typer.Option(
        False, "--no-external-tools", help="Do not invoke apktool/jadx even if installed."
    ),
    disable_rule: list[str] = typer.Option(
        [], "--disable-rule", help="Rule ID to suppress. Repeatable."
    ),
    disable_analyzer: list[str] = typer.Option(
        [], "--disable-analyzer", help="Analyzer name to skip. Repeatable."
    ),
    max_size_mb: int = typer.Option(
        DEFAULT_LIMITS.max_input_bytes // (1024 * 1024), "--max-size-mb",
        help="Reject packages larger than this.",
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q",
        help="Suppress progress output and coverage notes.",
    ),
) -> None:
    """Scan an APK or IPA and produce a report."""
    _show_notice_once()

    try:
        floor = Severity.parse(severity)
    except ValueError:
        err_console.print(f"[red]Unknown severity: {severity}[/red]")
        raise typer.Exit(3)

    limits = DEFAULT_LIMITS
    if max_size_mb > 0:
        from dataclasses import replace

        limits = replace(limits, max_input_bytes=max_size_mb * 1024 * 1024)

    config = ScanConfig(
        limits=limits,
        keep_artifacts=keep_artifacts,
        workdir=workdir,
        enable_external_tools=not no_external_tools,
        enable_network=online,
        offline_only=not online,
        disabled_rules=frozenset(disable_rule),
        disabled_analyzers=frozenset(disable_analyzer),
        severity_floor=floor.name,
    )

    def progress(message: str) -> None:
        if not quiet:
            console.print(f"[dim]  {message}…[/dim]")

    try:
        result = run_scan(target, config, progress=progress)
    except ValidationError as exc:
        err_console.print(f"[bold red]Refused:[/bold red] {exc}")
        raise typer.Exit(2)
    except MasaError as exc:
        err_console.print(f"[bold red]Scan failed:[/bold red] {exc}")
        raise typer.Exit(3)
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted.[/yellow]")
        raise typer.Exit(3)

    report = result.report
    _write_outputs(report, output, fmt)

    _print_report(report, verbose=not quiet)

    if result.artifacts_path:
        console.print(
            f"\n[yellow]Decompiled artifacts kept at:[/yellow] {result.artifacts_path}\n"
            "[dim]These may contain credentials extracted from the package. "
            "Delete them when you are done.[/dim]"
        )

    raise typer.Exit(_exit_code(report, fail_on))


def _write_outputs(report: Report, output: Optional[Path], fmt: str) -> None:
    fmt = fmt.lower()
    if fmt == "terminal":
        return
    if output is None:
        stem = Path(report.app.file_name).stem or "report"
        output = Path(f"{stem}-report")

    if fmt == "all":
        html_path = write_html(report, output.with_suffix(".html"))
        json_path = write_json(report, output.with_suffix(".json"))
        console.print(f"[green]Wrote[/green] {html_path}\n[green]Wrote[/green] {json_path}")
        return

    suffix = output.suffix.lower()
    if fmt == "html" or suffix == ".html":
        path = write_html(report, output if suffix == ".html" else output.with_suffix(".html"))
    elif fmt == "json" or suffix == ".json":
        path = write_json(report, output if suffix == ".json" else output.with_suffix(".json"))
    elif fmt == "pdf" or suffix == ".pdf":
        target = output if suffix == ".pdf" else output.with_suffix(".pdf")
        try:
            path = write_pdf(report, target)
        except PdfUnavailable as exc:
            # Rich treats square brackets as markup, and the message names the
            # "[pdf]" extra, so it is printed without markup interpretation.
            err_console.print(str(exc), style="red", markup=False)
            raise typer.Exit(3)
    else:
        err_console.print(f"[red]Unknown format: {fmt}[/red]")
        raise typer.Exit(3)
    console.print(f"[green]Wrote[/green] {path}")


def _print_report(report: Report, verbose: bool = True) -> None:
    app_info = report.app
    grade_style = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "bold red"}
    header = Text()
    header.append(f"{app_info.file_name}\n", style="bold")
    header.append(
        f"{app_info.package_name or 'unknown package'}"
        f"{f'  v{app_info.version_name}' if app_info.version_name else ''}"
        f"  ·  {app_info.platform.value}\n",
        style="dim",
    )
    header.append("Risk ", style="dim")
    header.append(
        f"{report.risk_grade} ({report.risk_score:.0f}/100)",
        style=grade_style.get(report.risk_grade, "white"),
    )
    console.print(Panel(header, border_style="blue"))

    counts = report.severity_counts()
    summary = Table(show_header=True, header_style="dim", box=None, pad_edge=False)
    for label in ("Critical", "High", "Medium", "Low", "Info"):
        summary.add_column(label, justify="right")
    summary.add_row(
        *[
            Text(str(counts[label]), style=_SEVERITY_STYLE[label])
            for label in ("Critical", "High", "Medium", "Low", "Info")
        ]
    )
    console.print(summary)
    console.print()

    if not report.findings:
        console.print("[green]No findings.[/green] This means no rule matched — it is "
                      "not a statement that the app is secure.\n")
    else:
        grouped = report.by_owasp()
        table = Table(show_header=True, header_style="bold dim", expand=True)
        table.add_column("Sev", width=8)
        table.add_column("OWASP", width=5)
        table.add_column("Rule", width=26, overflow="fold")
        table.add_column("Finding", overflow="fold")
        for oid, findings in grouped.items():
            for finding in findings:
                table.add_row(
                    Text(finding.severity.label, style=_SEVERITY_STYLE[finding.severity.label]),
                    oid,
                    Text(finding.rule_id, style="dim"),
                    finding.title,
                )
        console.print(table)

    if verbose and report.stats.degraded:
        console.print("\n[yellow]Coverage notes[/yellow]")
        for note in report.stats.degraded:
            console.print(f"  [dim]·[/dim] {note}")

    if report.errors:
        console.print("\n[red]Errors[/red]")
        for error in report.errors:
            console.print(f"  [dim]·[/dim] {error}")

    console.print(
        "\n[dim]Static analysis only — no code from the package was executed. "
        "Findings need human confirmation; absence of a finding is not evidence "
        "of absence of a vulnerability.[/dim]"
    )


def _exit_code(report: Report, fail_on: str) -> int:
    if fail_on.lower() in ("none", ""):
        return 0
    try:
        threshold = Severity.parse(fail_on)
    except ValueError:
        err_console.print(f"[red]Unknown --fail-on severity: {fail_on}[/red]")
        return 3
    worst = max((f.severity.rank for f in report.findings), default=0)
    return 1 if worst >= threshold.rank else 0


@app.command()
def rules() -> None:
    """List the analyzers and detection rules that ship with this tool."""
    table = Table(title="Analyzers", show_header=True, header_style="bold")
    table.add_column("Name", style="cyan")
    table.add_column("Platforms")
    table.add_column("What it checks", overflow="fold")
    for analyzer in all_analyzers():
        table.add_row(
            analyzer.name,
            ", ".join(p.value for p in analyzer.platforms),
            analyzer.description,
        )
    console.print(table)

    secrets = Table(title="Credential patterns", show_header=True, header_style="bold")
    secrets.add_column("Rule ID", style="cyan")
    secrets.add_column("Detects")
    secrets.add_column("Severity")
    for rule in SECRET_RULES:
        secrets.add_row(
            rule.id, rule.name,
            Text(rule.severity.label, style=_SEVERITY_STYLE[rule.severity.label]),
        )
    console.print(secrets)

    owasp = Table(title="OWASP Mobile Top 10 (2024)", show_header=True, header_style="bold")
    owasp.add_column("ID", style="cyan", width=5)
    owasp.add_column("Risk")
    for oid, category in OWASP_MOBILE_TOP_10.items():
        owasp.add_row(oid, category.title)
    console.print(owasp)


@app.command()
def version() -> None:
    """Print the tool version."""
    console.print(f"mobile-app-security-analyzer {__version__}")


@app.command()
def notice() -> None:
    """Show the legal and ethical use notice."""
    console.print(Panel(_LEGAL_NOTICE, title="Terms of use", border_style="yellow"))


def main() -> None:
    try:
        app()
    except Exception as exc:  # pragma: no cover - last-resort guard
        err_console.print(f"[bold red]Unexpected error:[/bold red] {exc}")
        sys.exit(3)


if __name__ == "__main__":
    main()
