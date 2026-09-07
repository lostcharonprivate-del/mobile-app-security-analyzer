"""Android pipeline: APK -> manifest, DEX, resources, signing info.

The pure-Python path is the default and is always complete enough to run every
analyzer. apktool and jadx, when present, are layered on top to add readable
source and decoded resources — they are an enhancement, never a requirement.
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

from masa.config import ScanConfig
from masa.context import AndroidArtifacts
from masa.decompile import arsc, axml, dex as dexmod
from masa.decompile.apksig import detect_signing
from masa.decompile.binio import ParseError
from masa.decompile.safexml import parse_xml
from masa.errors import DecompileError
from masa.ingest.safe_archive import SafeZip
from masa.ingest.sandbox import Sandbox, run_tool, tool_available
from masa.ingest.validator import PackageInfo
from masa.models import AppInfo, Platform

_DEX_NAME = re.compile(r"^classes\d*\.dex$")
_MAX_DEX_FILES = 32
_MAX_DEX_BYTES = 256 * 1024 * 1024


def build_artifacts(
    package: PackageInfo,
    extract_root: Path,
    sandbox: Sandbox,
    config: ScanConfig,
    degraded: list[str],
) -> AndroidArtifacts:
    """Populate everything the Android analyzers need."""
    artifacts = AndroidArtifacts()
    limits = config.limits

    with SafeZip(package.path, limits) as archive:
        artifacts.archive_names = archive.namelist()

    artifacts.manifest, artifacts.manifest_format = _load_manifest(
        extract_root, config, degraded
    )
    artifacts.dex_files = _load_dex(extract_root, config, degraded)
    artifacts.resources = _load_resources(extract_root, config, degraded)
    artifacts.signing = detect_signing(package.path, artifacts.archive_names)
    artifacts.native_libs = sorted(
        name
        for name in artifacts.archive_names
        if name.startswith("lib/") and name.endswith(".so")
    )

    if config.enable_external_tools:
        _run_optional_tools(package, sandbox, artifacts, config, degraded)

    return artifacts


def _load_manifest(
    root: Path, config: ScanConfig, degraded: list[str]
) -> tuple[axml.AxmlDocument | None, str]:
    path = root / "AndroidManifest.xml"
    if not path.is_file():
        degraded.append("AndroidManifest.xml was not extracted; manifest checks skipped")
        return None, ""
    try:
        data = path.read_bytes()
    except OSError as exc:
        degraded.append(f"could not read AndroidManifest.xml: {exc}")
        return None, ""

    if axml.looks_like_axml(data):
        try:
            doc = axml.parse_axml(data)
            for warning in doc.warnings:
                degraded.append(f"manifest: {warning}")
            return doc, "binary"
        except (ParseError, DecompileError) as exc:
            degraded.append(f"binary manifest could not be decoded: {exc}")
            return None, ""

    # Some packages (and apktool output) carry a plain-text manifest.
    try:
        return _manifest_from_text(data, config), "text"
    except DecompileError as exc:
        degraded.append(f"text manifest could not be parsed: {exc}")
        return None, ""


def _manifest_from_text(data: bytes, config: ScanConfig) -> axml.AxmlDocument:
    """Adapt a plain-text manifest into the same Element tree the AXML path yields."""
    root_element = parse_xml(data, config.limits)

    def convert(node, parent: axml.Element | None) -> axml.Element:
        name = node.tag
        if "}" in name:  # strip the {namespace} ElementTree prefix
            name = name.split("}", 1)[1]
        element = axml.Element(name=name, parent=parent)
        for key, value in node.attrib.items():
            attr = key
            if attr.startswith("{http://schemas.android.com/apk/res/android}"):
                attr = "android:" + attr.split("}", 1)[1]
            elif "}" in attr:
                attr = attr.split("}", 1)[1]
            element.attributes[attr] = value
        for child in node:
            element.children.append(convert(child, element))
        return element

    return axml.AxmlDocument(
        root=convert(root_element, None), strings=axml.StringPool([], False)
    )


def _load_dex(
    root: Path, config: ScanConfig, degraded: list[str]
) -> list[dexmod.DexFile]:
    files = sorted(
        (p for p in root.glob("*.dex") if _DEX_NAME.match(p.name)),
        key=lambda p: p.name,
    )
    if not files:
        degraded.append("no classes*.dex found; bytecode checks skipped")
        return []

    parsed: list[dexmod.DexFile] = []
    total = 0
    for path in files[:_MAX_DEX_FILES]:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        total += size
        if total > _MAX_DEX_BYTES:
            degraded.append(f"stopped after {len(parsed)} DEX files (size budget)")
            break
        try:
            data = path.read_bytes()
        except OSError as exc:
            degraded.append(f"could not read {path.name}: {exc}")
            continue
        try:
            dex = dexmod.parse_dex(data, name=path.name)
        except (ParseError, DecompileError) as exc:
            degraded.append(f"{path.name} could not be parsed: {exc}")
            continue
        for warning in dex.warnings:
            degraded.append(f"{path.name}: {warning}")
        parsed.append(dex)

    if len(files) > _MAX_DEX_FILES:
        degraded.append(
            f"APK has {len(files)} DEX files; analysed the first {_MAX_DEX_FILES}"
        )
    return parsed


def _load_resources(
    root: Path, config: ScanConfig, degraded: list[str]
) -> arsc.ResourceTable | None:
    path = root / "resources.arsc"
    if not path.is_file():
        return None
    try:
        if path.stat().st_size > config.limits.max_scan_file_bytes * 4:
            degraded.append("resources.arsc is too large to parse; resource checks skipped")
            return None
        table = arsc.parse_arsc(path.read_bytes())
    except (ParseError, DecompileError, OSError) as exc:
        degraded.append(f"resources.arsc could not be parsed: {exc}")
        return None
    for warning in table.warnings:
        degraded.append(f"resources.arsc: {warning}")
    return table


def _run_optional_tools(
    package: PackageInfo,
    sandbox: Sandbox,
    artifacts: AndroidArtifacts,
    config: ScanConfig,
    degraded: list[str],
) -> None:
    """Layer apktool/jadx output on top when those tools happen to be installed."""
    if not tool_available("apktool") and not tool_available("jadx"):
        degraded.append(
            "apktool and jadx are not installed; using the built-in DEX and "
            "resource parsers (all analyzers still run)"
        )
        return

    if tool_available("apktool"):
        out = sandbox.subdir("apktool")
        result = run_tool(
            ["apktool", "d", "-f", "-o", str(out), str(package.path)],
            cwd=sandbox.root or out,
            limits=config.limits,
        )
        if result.ok:
            artifacts.apktool_root = out
        else:
            degraded.append(
                f"apktool failed ({'timeout' if result.timed_out else result.returncode}); "
                "continuing with the built-in parsers"
            )

    if tool_available("jadx"):
        out = sandbox.subdir("jadx")
        result = run_tool(
            [
                "jadx",
                "--no-res",
                "--show-bad-code",
                "-j", "1",
                "-d", str(out),
                str(package.path),
            ],
            cwd=sandbox.root or out,
            limits=config.limits,
        )
        # jadx exits non-zero on partial decompilation but still writes usable source.
        if (out / "sources").is_dir():
            artifacts.jadx_source_root = out / "sources"
        elif not result.ok:
            degraded.append(
                f"jadx failed ({'timeout' if result.timed_out else result.returncode}); "
                "continuing with the built-in DEX parser"
            )


def populate_app_info(
    app: AppInfo, artifacts: AndroidArtifacts, package: PackageInfo
) -> None:
    """Fill the report's 'app info' section from the parsed manifest."""
    app.platform = Platform.ANDROID
    doc = artifacts.manifest
    if artifacts.signing:
        app.signing = artifacts.signing.as_dict()
    app.extra["native_libraries"] = artifacts.native_libs
    app.extra["dex_files"] = [d.name for d in artifacts.dex_files]
    app.extra["archive_entries"] = package.entry_count

    if doc is None or doc.root is None:
        return

    root = doc.root
    app.package_name = root.get("package")
    app.version_name = root.get("android:versionName")
    app.version_code = root.get("android:versionCode")

    for uses_sdk in doc.find_all("uses-sdk"):
        app.min_sdk = uses_sdk.get("android:minSdkVersion") or app.min_sdk
        app.target_sdk = uses_sdk.get("android:targetSdkVersion") or app.target_sdk

    app.permissions = sorted(
        {
            name
            for element in doc.find_all("uses-permission")
            if (name := element.get("android:name"))
        }
        | {
            name
            for element in doc.find_all("uses-permission-sdk-23")
            if (name := element.get("android:name"))
        }
    )

    components: dict[str, list[dict[str, object]]] = {}
    for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
        entries: list[dict[str, object]] = []
        for element in doc.find_all(kind):
            entries.append(
                {
                    "name": element.get("android:name") or "",
                    "exported": _resolve_exported(element),
                    "permission": element.get("android:permission"),
                    "read_permission": element.get("android:readPermission"),
                    "write_permission": element.get("android:writePermission"),
                    "authorities": element.get("android:authorities"),
                    "intent_filters": len(element.find_all("intent-filter")),
                }
            )
        if entries:
            components[kind] = entries
    app.components = components


def _resolve_exported(element: axml.Element) -> bool:
    """Explicit android:exported wins; otherwise an intent-filter implies exported."""
    declared = element.get_bool("android:exported")
    if declared is not None:
        return declared
    return bool(element.find_all("intent-filter"))
