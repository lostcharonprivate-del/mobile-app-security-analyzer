"""Inadequate supply chain security (M2).

Enumerates the third-party components compiled into the package and, when the
version can be established, checks them against OSV.dev.

Establishing a version from a built APK is the hard part: the build inlines
everything and there is no dependency manifest. Three sources are used, in
descending order of reliability — `META-INF/*.version` marker files, Maven
`pom.properties`, and version constants embedded in library code — and a library
whose version cannot be determined is reported as unverifiable rather than
silently dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from masa.analyzers.base import Analyzer, register
from masa.context import ScanContext
from masa.models import Confidence, Evidence, Finding, Platform, Severity
from masa.osv import Coordinate, OsvClient, Vulnerability

_VERSION = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:[-.][A-Za-z0-9]+)*$")
_SEMVER_IN_TEXT = re.compile(r"\b(\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?)\b")

# Class-package prefix -> Maven coordinate, for libraries common in Android apps.
_KNOWN_LIBRARIES: dict[str, str] = {
    "okhttp3": "com.squareup.okhttp3:okhttp",
    "okio": "com.squareup.okio:okio",
    "retrofit2": "com.squareup.retrofit2:retrofit",
    "com.squareup.picasso": "com.squareup.picasso:picasso",
    "com.google.gson": "com.google.code.gson:gson",
    "com.fasterxml.jackson.databind": "com.fasterxml.jackson.core:jackson-databind",
    "org.apache.commons.io": "commons-io:commons-io",
    "org.apache.commons.lang3": "org.apache.commons:commons-lang3",
    "com.bumptech.glide": "com.github.bumptech.glide:glide",
    "com.nostra13.universalimageloader": "com.nostra13.universalimageloader:universal-image-loader",
    "io.realm": "io.realm:realm-android-library",
    "org.greenrobot.eventbus": "org.greenrobot:eventbus",
    "io.reactivex.rxjava3": "io.reactivex.rxjava3:rxjava",
    "io.reactivex.rxjava2": "io.reactivex.rxjava2:rxjava",
    "com.facebook.react": "com.facebook.react:react-native",
    "io.flutter": "io.flutter:flutter_embedding",
    "org.chromium": "org.chromium:cronet",
    "net.sqlcipher": "net.zetetic:android-database-sqlcipher",
    "com.google.firebase": "com.google.firebase:firebase-common",
    "org.jsoup": "org.jsoup:jsoup",
    "com.google.protobuf": "com.google.protobuf:protobuf-java",
    "org.bouncycastle": "org.bouncycastle:bcprov-jdk15on",
    "com.airbnb.lottie": "com.airbnb.android:lottie",
    "com.jakewharton.timber": "com.jakewharton.timber:timber",
}

_VERSION_FILE = re.compile(r"^META-INF/(?P<name>[A-Za-z0-9_.\-]+)\.version$")
_POM_PROPERTIES = re.compile(r"^META-INF/maven/(?P<group>[^/]+)/(?P<artifact>[^/]+)/pom\.properties$")


@dataclass
class Library:
    name: str
    version: str | None = None
    ecosystem: str = "Maven"
    source: str = ""
    """How the version was established, shown in the report."""

    evidence_location: str = ""

    @property
    def coordinate(self) -> Coordinate | None:
        if not self.version:
            return None
        return Coordinate(self.ecosystem, self.name, self.version)

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "version_source": self.source,
        }


@register
class DependencyAnalyzer(Analyzer):
    name = "dependencies"
    description = "Bundled third-party libraries and their known vulnerabilities"
    platforms = (Platform.ANDROID, Platform.IOS)

    def analyze(self, ctx: ScanContext) -> Iterable[Finding]:
        libraries = self._discover(ctx)
        ctx.app.libraries = [lib.as_dict() for lib in libraries]
        if not libraries:
            return

        versioned = [lib for lib in libraries if lib.coordinate]
        client = OsvClient(enabled=ctx.config.enable_network)
        results = client.query_batch([lib.coordinate for lib in versioned if lib.coordinate])

        yield from self._vulnerability_findings(ctx, versioned, results)
        yield from self._inventory_finding(ctx, libraries, versioned, client)

    # -- discovery ------------------------------------------------------------

    def _discover(self, ctx: ScanContext) -> list[Library]:
        found: dict[str, Library] = {}
        if ctx.android:
            self._from_version_files(ctx, found)
            self._from_pom_properties(ctx, found)
            self._from_class_packages(ctx, found)
        if ctx.ios:
            self._from_frameworks(ctx, found)
        return sorted(found.values(), key=lambda lib: lib.name)

    def _from_version_files(self, ctx: ScanContext, found: dict[str, Library]) -> None:
        """AndroidX and many Google libraries ship META-INF/<artifact>.version."""
        for text_file in ctx.text_files():
            match = _VERSION_FILE.match(text_file.relative)
            if not match:
                continue
            version = text_file.text.strip().splitlines()[0].strip() if text_file.text.strip() else ""
            if not _VERSION.match(version):
                continue
            raw = match.group("name")
            # `androidx.core_core` encodes group_artifact.
            name = raw.replace("_", ":", 1) if "_" in raw else raw
            found[name] = Library(
                name=name,
                version=version,
                source="META-INF version marker",
                evidence_location=text_file.relative,
            )

    def _from_pom_properties(self, ctx: ScanContext, found: dict[str, Library]) -> None:
        for text_file in ctx.text_files():
            if not _POM_PROPERTIES.match(text_file.relative):
                continue
            fields: dict[str, str] = {}
            for line in text_file.lines():
                if "=" in line and not line.startswith("#"):
                    key, _, value = line.partition("=")
                    fields[key.strip()] = value.strip()
            group, artifact, version = (
                fields.get("groupId"), fields.get("artifactId"), fields.get("version")
            )
            if group and artifact and version and _VERSION.match(version):
                name = f"{group}:{artifact}"
                found[name] = Library(
                    name=name,
                    version=version,
                    source="Maven pom.properties",
                    evidence_location=text_file.relative,
                )

    def _from_class_packages(self, ctx: ScanContext, found: dict[str, Library]) -> None:
        """Identify libraries by the packages they contribute, then hunt a version."""
        class_names = [entry.name for entry in ctx.android.all_classes()]
        strings = [value for _, value in ctx.all_strings()]

        for prefix, coordinate in _KNOWN_LIBRARIES.items():
            if not any(name.startswith(prefix + ".") or name == prefix for name in class_names):
                continue
            if coordinate in found:
                continue
            version = self._guess_version(prefix, strings)
            found[coordinate] = Library(
                name=coordinate,
                version=version,
                source="library version constant" if version else "",
                evidence_location=f"classes.dex ({prefix}.*)",
            )

    @staticmethod
    def _guess_version(prefix: str, strings: list[str]) -> str | None:
        """Look for a version string the library itself embeds.

        OkHttp puts `okhttp/4.9.0` in its User-Agent; several libraries ship a
        bare semver constant. This is a hint, so a match only counts when it sits
        next to the library's own name.
        """
        short = prefix.rsplit(".", 1)[-1]
        marker = f"{short}/"
        for value in strings:
            if len(value) > 120:
                continue
            if value.startswith(marker):
                match = _SEMVER_IN_TEXT.search(value)
                if match:
                    return match.group(1)
        return None

    def _from_frameworks(self, ctx: ScanContext, found: dict[str, Library]) -> None:
        for framework in ctx.ios.frameworks:
            name = framework.split("/")[-1].removesuffix(".framework")
            if not name:
                continue
            found[name] = Library(
                name=name,
                version=None,
                ecosystem="SwiftURL",
                source="",
                evidence_location=framework,
            )

    # -- findings -------------------------------------------------------------

    def _vulnerability_findings(
        self,
        ctx: ScanContext,
        versioned: list[Library],
        results: dict[str, list[Vulnerability]],
    ) -> Iterator[Finding]:
        for library in versioned:
            coordinate = library.coordinate
            if coordinate is None:
                continue
            vulns = results.get(coordinate.key) or []
            if not vulns:
                continue
            severity = self._severity_for(vulns)
            listed = ", ".join(v.id for v in vulns[:6])
            yield self.finding(
                ctx,
                rule_id="DEP-KNOWN-VULN",
                title=f"{library.name} {library.version} has {len(vulns)} known vulnerabilities",
                severity=severity,
                owasp="M2",
                cwe="CWE-1395",
                masvs="MASVS-CODE",
                description=(
                    f"The package bundles `{library.name}` version "
                    f"`{library.version}` ({library.source}). OSV.dev lists "
                    f"{len(vulns)} advisory/advisories affecting this version: "
                    f"{listed}"
                    + (" and others" if len(vulns) > 6 else "")
                    + ". "
                    + (vulns[0].summary if vulns[0].summary else "")
                    + " A vulnerability in a bundled library is a vulnerability in "
                    "this app: it ships inside the binary and runs with the app's "
                    "permissions."
                ),
                remediation=(
                    f"Upgrade `{library.name}` to a version outside the affected "
                    "ranges listed in the advisories, then re-run this scan. Where "
                    "the dependency is transitive, pin the fixed version explicitly "
                    "rather than waiting for the parent to update."
                ),
                evidence=[
                    self.evidence(
                        ctx,
                        library.evidence_location or library.name,
                        f"{v.id} ({v.severity or 'severity unrated'}): {v.summary or v.url}",
                        redact=False,
                    )
                    for v in vulns[: ctx.limits.max_evidence_per_finding]
                ],
                references=[v.url for v in vulns[:5]],
                metadata={
                    "library": library.name,
                    "version": library.version,
                    "advisories": [v.id for v in vulns],
                },
            )

    @staticmethod
    def _severity_for(vulns: list[Vulnerability]) -> Severity:
        """Derive a severity from the highest CVSS base score present."""
        best = 0.0
        for vulnerability in vulns:
            score = _cvss_score(vulnerability.severity)
            best = max(best, score)
            if vulnerability.severity.upper() in ("CRITICAL",):
                best = max(best, 9.0)
            elif vulnerability.severity.upper() in ("HIGH",):
                best = max(best, 7.5)
        if best >= 9.0:
            return Severity.CRITICAL
        if best >= 7.0:
            return Severity.HIGH
        if best >= 4.0:
            return Severity.MEDIUM
        # No parseable score: a known advisory still warrants attention.
        return Severity.MEDIUM

    def _inventory_finding(
        self,
        ctx: ScanContext,
        libraries: list[Library],
        versioned: list[Library],
        client: OsvClient,
    ) -> Iterator[Finding]:
        unversioned = [lib for lib in libraries if not lib.coordinate]
        notes: list[str] = []
        if not ctx.config.enable_network:
            notes.append(
                "OSV.dev lookups were skipped because network access is disabled; "
                "re-run with --online to check these against known advisories"
            )
        notes.extend(client.errors)

        yield self.finding(
            ctx,
            rule_id="DEP-INVENTORY",
            title=f"{len(libraries)} third-party components identified",
            severity=Severity.INFO,
            owasp="M2",
            masvs="MASVS-CODE",
            confidence=Confidence.MEDIUM,
            description=(
                f"{len(libraries)} bundled component(s) were identified, "
                f"{len(versioned)} of them with a determinable version. "
                + (
                    f"{len(unversioned)} could not be version-matched, so they were "
                    "not checked for known vulnerabilities — a built package has no "
                    "dependency manifest, and a library that embeds no version "
                    "constant cannot be pinned down statically. "
                    if unversioned
                    else ""
                )
                + (" ".join(notes) if notes else "")
            ),
            remediation=(
                "Generate a software bill of materials at build time — where the "
                "dependency graph is actually known — and check that against an "
                "advisory feed in CI, rather than relying on what can be recovered "
                "from a compiled artifact."
            ),
            evidence=[
                self.evidence(
                    ctx,
                    lib.evidence_location or lib.name,
                    f"{lib.name} {lib.version or '(version unknown)'}"
                    + (f" — {lib.source}" if lib.source else ""),
                    redact=False,
                )
                for lib in libraries[: ctx.limits.max_evidence_per_finding]
            ],
            metadata={
                "components": [lib.as_dict() for lib in libraries][:200],
                "network_enabled": ctx.config.enable_network,
            },
        )


def _cvss_score(vector: str) -> float:
    """Pull a numeric score out of an OSV severity value.

    OSV returns either a CVSS vector string or a plain number depending on the
    source database, so both shapes are handled.
    """
    if not vector:
        return 0.0
    try:
        return float(vector)
    except ValueError:
        pass
    # A full CVSS vector needs a calculator to score exactly; approximate from
    # the impact metrics, which is enough to bucket into a severity band.
    if vector.startswith("CVSS:"):
        high_impact = sum(
            1 for part in ("C:H", "I:H", "A:H") if part in vector
        )
        network = "AV:N" in vector
        no_privileges = "PR:N" in vector
        no_interaction = "UI:N" in vector
        score = 3.0 + 2.0 * high_impact
        if network:
            score += 1.5
        if no_privileges:
            score += 0.8
        if no_interaction:
            score += 0.7
        return min(score, 10.0)
    return 0.0
