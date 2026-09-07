"""Pipeline orchestration: validate, unpack, decompile, analyze, score.

This is the only module that sequences the whole scan. Errors in one analyzer are
contained so that a single bad rule cannot lose the rest of the report, and the
sandbox is always torn down, including on failure.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from masa import __version__
from masa.analyzers import all_analyzers
from masa.config import ScanConfig
from masa.context import ScanContext
from masa.decompile import android as android_pipeline
from masa.decompile import ios as ios_pipeline
from masa.errors import AnalysisTimeout, MasaError, ValidationError
from masa.ingest.safe_archive import SafeZip
from masa.ingest.sandbox import Sandbox
from masa.ingest.validator import PackageInfo, validate_package
from masa.models import AppInfo, Finding, Platform, Report, ScanStats
from masa.scoring import deduplicate, score_findings, sort_findings

ProgressCallback = Callable[[str], None]


def _noop(_message: str) -> None:
    pass


@dataclass
class ScanResult:
    report: Report
    artifacts_path: Path | None = None
    """Set when --keep-artifacts was used, so the CLI can tell the user where."""


def scan(
    target: str | Path,
    config: ScanConfig | None = None,
    progress: ProgressCallback = _noop,
) -> ScanResult:
    """Run a full scan and return the report."""
    config = config or ScanConfig()
    started = time.monotonic()

    progress("Validating package")
    package = validate_package(target, config.limits)

    app = AppInfo(
        platform=package.platform,
        file_name=package.file_name,
        file_size=package.size,
        sha256=package.sha256,
    )
    report = Report(app=app, tool_version=__version__)
    degraded: list[str] = []
    artifacts_path: Path | None = None

    sandbox = Sandbox(
        limits=config.limits,
        parent=config.workdir,
        keep=config.keep_artifacts,
    )
    with sandbox:
        assert sandbox.root is not None
        extract_root = sandbox.subdir("extracted")
        artifacts_path = sandbox.root if config.keep_artifacts else None

        progress("Extracting package")
        with SafeZip(package.path, config.limits) as archive:
            extraction = archive.extract_all(extract_root)
        for reason, count in extraction.skipped_summary().items():
            degraded.append(f"{count} archive member(s) skipped: {reason}")

        ctx = ScanContext(
            package=package,
            app=app,
            config=config,
            root=extract_root,
            degraded=degraded,
        )

        progress(f"Decompiling ({package.platform.value})")
        _decompile(ctx, package, sandbox, config, degraded)

        progress("Running analyzers")
        findings, errors = _run_analyzers(ctx, config, started)
        report.errors.extend(errors)

        report.stats = ScanStats(
            files_scanned=extraction.files_written,
            bytes_scanned=extraction.bytes_written,
            strings_extracted=len(ctx.all_strings()),
            decompilers_used=_decompilers_used(ctx),
            degraded=list(dict.fromkeys(ctx.degraded)),
        )

    report.findings = sort_findings(deduplicate(findings))
    breakdown = score_findings(report.findings)
    report.risk_score = breakdown.score
    report.risk_grade = breakdown.grade
    report.stats.duration_seconds = round(time.monotonic() - started, 2)
    report.app.extra["score_breakdown"] = breakdown.as_dict()

    progress("Done")
    return ScanResult(report=report, artifacts_path=artifacts_path)


def _decompile(
    ctx: ScanContext,
    package: PackageInfo,
    sandbox: Sandbox,
    config: ScanConfig,
    degraded: list[str],
) -> None:
    try:
        if package.platform is Platform.ANDROID:
            ctx.android = android_pipeline.build_artifacts(
                package, ctx.root, sandbox, config, degraded
            )
            android_pipeline.populate_app_info(ctx.app, ctx.android, package)
        elif package.platform is Platform.IOS:
            ctx.ios = ios_pipeline.build_artifacts(
                package, ctx.root, sandbox, config, degraded
            )
            ios_pipeline.populate_app_info(ctx.app, ctx.ios, package)
    except MasaError as exc:
        degraded.append(f"decompilation failed: {exc}")


def _run_analyzers(
    ctx: ScanContext, config: ScanConfig, started: float
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    errors: list[str] = []
    floor = _severity_floor(config)

    for analyzer in all_analyzers():
        if analyzer.name in config.disabled_analyzers:
            continue
        if not analyzer.applies_to(ctx.platform):
            continue
        if time.monotonic() - started > config.limits.total_timeout_seconds:
            errors.append(
                f"scan timeout reached; analyzers after '{analyzer.name}' did not run"
            )
            break
        try:
            produced = list(analyzer.analyze(ctx))
        except Exception as exc:  # a broken rule must not lose the whole report
            errors.append(f"analyzer '{analyzer.name}' failed: {type(exc).__name__}: {exc}")
            continue
        for finding in produced:
            if finding.rule_id in config.disabled_rules:
                continue
            if finding.severity.rank < floor:
                continue
            findings.append(finding)
    return findings, errors


def _severity_floor(config: ScanConfig) -> int:
    from masa.models import Severity

    try:
        return Severity.parse(config.severity_floor).rank
    except ValueError:
        return Severity.INFO.rank


def _decompilers_used(ctx: ScanContext) -> list[str]:
    used = ["built-in (pure Python)"]
    if ctx.android:
        if ctx.android.apktool_root:
            used.append("apktool")
        if ctx.android.jadx_source_root:
            used.append("jadx")
    return used
