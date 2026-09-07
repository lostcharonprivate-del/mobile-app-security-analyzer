"""iOS pipeline: IPA -> Info.plist, Mach-O facts, strings and framework list.

Full iOS reverse engineering is macOS-centric (otool, class-dump, Hopper, Ghidra).
This pipeline deliberately does not depend on any of them: the Mach-O reader and
plistlib cover the static facts, and `otool`/`class-dump` are used only to enrich
the result when they happen to be installed. On Linux the analysis degrades to
plist, zip-level and strings analysis rather than failing.
"""

from __future__ import annotations

import re
from pathlib import Path

from masa.config import ScanConfig
from masa.context import IosArtifacts
from masa.decompile import macho as machomod
from masa.decompile.binio import ParseError
from masa.decompile.safexml import parse_plist
from masa.errors import DecompileError
from masa.ingest.safe_archive import SafeZip, iter_files
from masa.ingest.sandbox import Sandbox, run_tool, tool_available
from masa.ingest.validator import PackageInfo
from masa.models import AppInfo, Platform

_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{5,256}")
_MAX_BINARY_BYTES = 256 * 1024 * 1024


def build_artifacts(
    package: PackageInfo,
    extract_root: Path,
    sandbox: Sandbox,
    config: ScanConfig,
    degraded: list[str],
) -> IosArtifacts:
    artifacts = IosArtifacts()
    limits = config.limits

    with SafeZip(package.path, limits) as archive:
        artifacts.archive_names = archive.namelist()

    bundle = _find_bundle(extract_root, package, degraded)
    if bundle is None:
        return artifacts

    artifacts.plists = _load_plists(extract_root, bundle, config, degraded)
    artifacts.info_plist = artifacts.plists.get("Info.plist", {})
    if not artifacts.info_plist:
        degraded.append("Info.plist could not be read; iOS configuration checks skipped")

    artifacts.frameworks = sorted(
        {
            name.split("/Frameworks/", 1)[1].split("/")[0]
            for name in artifacts.archive_names
            if "/Frameworks/" in name and ".framework/" in name
        }
    )

    binary = _find_binary(bundle, artifacts.info_plist, degraded)
    if binary is not None:
        artifacts.binary_path = binary
        _load_binary(binary, artifacts, config, degraded)

    artifacts.entitlements = _load_entitlements(bundle, config, degraded)

    if config.enable_external_tools:
        _enrich_with_tools(binary, artifacts, sandbox, config, degraded)

    return artifacts


def _find_bundle(
    root: Path, package: PackageInfo, degraded: list[str]
) -> Path | None:
    if package.app_bundle:
        candidate = root / package.app_bundle
        if candidate.is_dir():
            return candidate
    payload = root / "Payload"
    if payload.is_dir():
        for child in sorted(payload.iterdir()):
            if child.is_dir() and child.name.endswith(".app"):
                return child
    degraded.append("Payload/*.app directory was not extracted; iOS analysis skipped")
    return None


def _load_plists(
    root: Path, bundle: Path, config: ScanConfig, degraded: list[str]
) -> dict[str, dict]:
    """Parse every plist in the bundle, keyed by path relative to the .app."""
    out: dict[str, dict] = {}
    for path in iter_files(bundle, config.limits):
        if path.suffix.lower() != ".plist":
            continue
        try:
            if path.stat().st_size > config.limits.max_xml_bytes:
                continue
            parsed = parse_plist(path.read_bytes(), config.limits)
        except (DecompileError, OSError) as exc:
            degraded.append(f"{path.name}: {exc}")
            continue
        if not isinstance(parsed, dict):
            continue
        try:
            key = str(path.relative_to(bundle))
        except ValueError:
            key = path.name
        out[key] = parsed
    return out


def _find_binary(
    bundle: Path, info_plist: dict, degraded: list[str]
) -> Path | None:
    """Locate the main executable named by CFBundleExecutable."""
    name = info_plist.get("CFBundleExecutable")
    if isinstance(name, str) and name:
        # The name comes from the analysed package, so treat it as untrusted:
        # take the basename only and require the result to stay inside the bundle.
        candidate = bundle / Path(name).name
        if candidate.is_file() and _inside(bundle, candidate):
            return candidate
        degraded.append(f"CFBundleExecutable '{name}' was not found in the bundle")

    # Fall back to the extension-less file whose name matches the bundle.
    fallback = bundle / bundle.name.removesuffix(".app")
    if fallback.is_file():
        return fallback
    for child in sorted(bundle.iterdir()):
        if child.is_file() and not child.suffix:
            try:
                if machomod.looks_like_macho(child.read_bytes()[:8]):
                    return child
            except OSError:
                continue
    degraded.append("main Mach-O binary was not found; binary checks skipped")
    return None


def _inside(root: Path, candidate: Path) -> bool:
    try:
        return candidate.resolve().is_relative_to(root.resolve())
    except (OSError, ValueError):
        return False


def _load_binary(
    binary: Path, artifacts: IosArtifacts, config: ScanConfig, degraded: list[str]
) -> None:
    try:
        size = binary.stat().st_size
        if size > _MAX_BINARY_BYTES:
            degraded.append("main binary is too large to analyse; skipped")
            return
        data = binary.read_bytes()
    except OSError as exc:
        degraded.append(f"could not read the main binary: {exc}")
        return

    try:
        artifacts.macho = machomod.parse_macho(data)
        for warning in artifacts.macho.warnings:
            degraded.append(f"main binary: {warning}")
        artifacts.class_names = list(artifacts.macho.objc_classes)
    except (ParseError, DecompileError) as exc:
        degraded.append(f"main binary is not a parseable Mach-O: {exc}")

    cap = config.limits.max_strings_per_binary
    artifacts.binary_strings = [
        match.group().decode("ascii", "replace")
        for match in _PRINTABLE_RUN.finditer(data)
    ][:cap]


def _load_entitlements(
    bundle: Path, config: ScanConfig, degraded: list[str]
) -> dict:
    """Pull the entitlements plist out of embedded.mobileprovision if present."""
    provision = bundle / "embedded.mobileprovision"
    if not provision.is_file():
        return {}
    try:
        raw = provision.read_bytes()
    except OSError:
        return {}
    # The provisioning profile is a CMS blob with an XML plist inside it.
    start = raw.find(b"<?xml")
    end = raw.find(b"</plist>")
    if start < 0 or end < 0:
        return {}
    try:
        parsed = parse_plist(raw[start : end + len(b"</plist>")], config.limits)
    except DecompileError as exc:
        degraded.append(f"embedded.mobileprovision: {exc}")
        return {}
    if isinstance(parsed, dict):
        entitlements = parsed.get("Entitlements")
        if isinstance(entitlements, dict):
            return entitlements
        return parsed
    return {}


def _enrich_with_tools(
    binary: Path | None,
    artifacts: IosArtifacts,
    sandbox: Sandbox,
    config: ScanConfig,
    degraded: list[str],
) -> None:
    """Add class-dump output when the tool exists. Never required."""
    if binary is None:
        return
    if not tool_available("class-dump"):
        if not artifacts.class_names:
            degraded.append(
                "class-dump is not installed; Objective-C class names were read "
                "from the Mach-O __objc_classname section instead"
            )
        return
    result = run_tool(
        ["class-dump", "-H", "-o", str(sandbox.subdir("classdump")), str(binary)],
        cwd=sandbox.root or binary.parent,
        limits=config.limits,
    )
    if not result.ok:
        degraded.append("class-dump failed; using the built-in Mach-O reader")


def populate_app_info(
    app: AppInfo, artifacts: IosArtifacts, package: PackageInfo
) -> None:
    app.platform = Platform.IOS
    info = artifacts.info_plist
    app.package_name = _as_str(info.get("CFBundleIdentifier"))
    app.version_name = _as_str(info.get("CFBundleShortVersionString"))
    app.version_code = _as_str(info.get("CFBundleVersion"))
    app.min_os_version = _as_str(info.get("MinimumOSVersion"))
    app.extra["display_name"] = _as_str(info.get("CFBundleDisplayName"))
    app.extra["frameworks"] = artifacts.frameworks
    app.extra["archive_entries"] = package.entry_count
    app.extra["url_schemes"] = _url_schemes(info)

    app.permissions = sorted(
        key for key in info if isinstance(key, str) and key.startswith("NS") and key.endswith("UsageDescription")
    )

    if artifacts.macho is not None:
        app.extra["macho"] = artifacts.macho.as_dict()
    if artifacts.entitlements:
        app.signing = {
            "entitlements": {
                key: value
                for key, value in list(artifacts.entitlements.items())[:40]
                if isinstance(key, str)
            }
        }


def _url_schemes(info: dict) -> list[str]:
    schemes: list[str] = []
    for entry in info.get("CFBundleURLTypes", []) or []:
        if not isinstance(entry, dict):
            continue
        for scheme in entry.get("CFBundleURLSchemes", []) or []:
            if isinstance(scheme, str):
                schemes.append(scheme)
    return sorted(set(schemes))


def _as_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None
