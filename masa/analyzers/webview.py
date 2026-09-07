"""Insufficient input/output validation (M4).

WebView configuration and the interfaces the app exposes to loaded content, plus
the deep-link surfaces that let another app hand this one a URL.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from masa.analyzers.base import Analyzer, register
from masa.context import ScanContext
from masa.models import Confidence, Evidence, Finding, Platform, Severity

# WebSettings setters that are only a problem when passed true.
# method -> (stable rule id suffix, label, severity, explanation)
_SETTING_RULE_IDS = {
    "setJavaScriptEnabled": "JAVASCRIPT-ENABLED",
    "setAllowFileAccessFromFileURLs": "FILE-ACCESS-FROM-FILE-URLS",
    "setAllowUniversalAccessFromFileURLs": "UNIVERSAL-ACCESS-FROM-FILE-URLS",
    "setAllowFileAccess": "ALLOW-FILE-ACCESS",
    "setAllowContentAccess": "ALLOW-CONTENT-ACCESS",
}

_DANGEROUS_SETTINGS = {
    "setJavaScriptEnabled": (
        "JavaScript execution",
        Severity.LOW,
        "JavaScript runs in the WebView. On its own this is normal; it becomes the "
        "amplifier for every other issue here.",
    ),
    "setAllowFileAccessFromFileURLs": (
        "file:// pages reading other files",
        Severity.HIGH,
        "A page loaded from a file:// URL can read other files through XHR.",
    ),
    "setAllowUniversalAccessFromFileURLs": (
        "file:// pages reading any origin",
        Severity.CRITICAL,
        "A page loaded from file:// can issue requests to any origin and read the "
        "responses, bypassing the same-origin policy entirely. Combined with any "
        "path an attacker can write to, this reads the app's private files and "
        "exfiltrates them.",
    ),
    "setAllowFileAccess": (
        "file:// URL loading",
        Severity.MEDIUM,
        "The WebView may load file:// URLs, which widens what a redirect or an "
        "injected URL can reach.",
    ),
    "setAllowContentAccess": (
        "content:// URL loading",
        Severity.MEDIUM,
        "The WebView may load content:// URLs, reaching content providers on the device.",
    ),
}


@register
class WebViewAnalyzer(Analyzer):
    name = "webview"
    description = "WebView configuration, JavaScript bridges and deep-link validation"
    platforms = (Platform.ANDROID, Platform.IOS)

    def analyze(self, ctx: ScanContext) -> Iterable[Finding]:
        if ctx.platform is Platform.ANDROID and ctx.android:
            yield from self._javascript_interface(ctx)
            yield from self._webview_settings(ctx)
            yield from self._loadurl_from_intent(ctx)
            yield from self._deep_links(ctx)

    def _javascript_interface(self, ctx: ScanContext) -> Iterator[Finding]:
        invocations = ctx.android.invocations_by_name("addJavascriptInterface")
        if not invocations:
            return
        try:
            min_sdk = int(ctx.app.min_sdk) if ctx.app.min_sdk else None
        except ValueError:
            min_sdk = None
        pre_17 = min_sdk is not None and min_sdk < 17

        yield self.finding(
            ctx,
            rule_id="WEB-JS-INTERFACE",
            title="WebView exposes a Java object to page JavaScript",
            severity=Severity.CRITICAL if pre_17 else Severity.HIGH,
            owasp="M4",
            cwe="CWE-749",
            masvs="MASVS-PLATFORM",
            description=(
                "`addJavascriptInterface` binds a Java object into the WebView's "
                "JavaScript context. Whatever HTML the WebView ends up displaying — "
                "including a page reached through a redirect, an injected iframe, or "
                "an ad network — can call the annotated methods on that object with "
                "arguments of its choosing."
                + (
                    " Because minSdkVersion is below 17, the @JavascriptInterface "
                    "annotation is not enforced and every public method is reachable, "
                    "including `getClass()` — which yields reflection and therefore "
                    "arbitrary code execution in the app's process (CVE-2012-6636)."
                    if pre_17
                    else " On API 17+ only @JavascriptInterface-annotated methods are "
                    "exposed, so the risk is bounded by what those methods do — but "
                    "each one is an entry point callable by untrusted page content."
                )
            ),
            remediation=(
                "Remove the bridge if the page content does not need it. If it does: "
                "load only content you control over HTTPS, keep the bridge object as "
                "small as possible, validate every argument, and never expose methods "
                "that touch the filesystem, credentials or other components. Prefer "
                "`WebMessagePort` for structured, origin-checked messaging."
            ),
            evidence=[
                self.evidence(
                    ctx, inv.site.location, "addJavascriptInterface(…)", redact=False
                )
                for inv in invocations
            ],
            references=[
                "https://cwe.mitre.org/data/definitions/749.html",
                "https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String)",
            ],
        )

    def _webview_settings(self, ctx: ScanContext) -> Iterator[Finding]:
        for method, (label, severity, explanation) in _DANGEROUS_SETTINGS.items():
            evidence: list[Evidence] = []
            for invocation in ctx.android.invocations_by_name(
                method, receivers=("WebSettings",)
            ):
                # Only a `true` argument enables the behaviour. An unresolved
                # argument is reported at lower confidence rather than dropped.
                enabled = invocation.arg(1)
                if enabled == 0:
                    continue
                evidence.append(
                    self.evidence(
                        ctx, invocation.site.location,
                        f"{method}({'true' if enabled == 1 else '…'})", redact=False,
                    )
                )
            if not evidence:
                continue
            if method == "setJavaScriptEnabled":
                continue  # reported only as context alongside the bridge finding
            yield self.finding(
                ctx,
                rule_id=f"WEB-{_SETTING_RULE_IDS[method]}",
                title=f"WebView enables {label}",
                severity=severity,
                owasp="M4",
                cwe="CWE-749",
                masvs="MASVS-PLATFORM",
                confidence=Confidence.HIGH,
                description=(
                    f"`{method}(true)` is called on a WebView's settings. "
                    f"{explanation}"
                ),
                remediation=(
                    f"Call `{method}(false)` unless a shipped feature depends on it. "
                    "These settings default to permissive values on older API levels, "
                    "so set them explicitly rather than relying on the default."
                ),
                evidence=evidence,
            )

    def _loadurl_from_intent(self, ctx: ScanContext) -> Iterator[Finding]:
        """A loadUrl in the same method as an Intent getter is an open-redirect shape."""
        load_sites = {
            site.location for site in ctx.android.sites_by_name("loadUrl")
        }
        intent_sites = {
            site.location
            for name in ("getStringExtra", "getData", "getQueryParameter")
            for site in ctx.android.sites_by_name(name)
        }
        shared = sorted(load_sites & intent_sites)
        if not shared:
            return
        yield self.finding(
            ctx,
            rule_id="WEB-LOADURL-FROM-INTENT",
            title="WebView loads a URL taken from an incoming Intent",
            severity=Severity.HIGH,
            owasp="M4",
            cwe="CWE-939",
            masvs="MASVS-PLATFORM",
            confidence=Confidence.MEDIUM,
            description=(
                "The same method both reads a value out of an Intent and calls "
                "`WebView.loadUrl`. If the URL is not validated, any app on the "
                "device — or any web page, when the activity is reachable through a "
                "browsable deep link — can choose what this WebView loads. That "
                "turns the app into an open redirect, and combines with any "
                "JavaScript bridge to reach the bridge from attacker-controlled "
                "content. This rule matches methods, not data flow, so confirm the "
                "value really reaches loadUrl."
            ),
            remediation=(
                "Validate before loading: parse the URL, require the https scheme, "
                "and check the host against an allowlist of domains you control. "
                "Reject anything else rather than falling back to loading it."
            ),
            evidence=[
                self.evidence(ctx, location, "Intent data reaches loadUrl(…)", redact=False)
                for location in shared
            ],
            references=["https://cwe.mitre.org/data/definitions/939.html"],
        )

    def _deep_links(self, ctx: ScanContext) -> Iterator[Finding]:
        doc = ctx.android.manifest
        if doc is None:
            return
        evidence: list[Evidence] = []
        for filt in doc.find_all("intent-filter"):
            categories = {c.get("android:name") for c in filt.find_all("category")}
            if "android.intent.category.BROWSABLE" not in categories:
                continue
            for data in filt.find_all("data"):
                scheme = data.get("android:scheme")
                if not scheme or scheme in ("http", "https"):
                    continue  # App Links are verified by the platform
                host = data.get("android:host")
                owner = filt.parent.get("android:name") if filt.parent else "(unknown)"
                evidence.append(
                    self.evidence(
                        ctx, "AndroidManifest.xml",
                        f'{owner}: custom scheme "{scheme}://{host or "*"}" is BROWSABLE',
                        line=filt.line or None, redact=False,
                    )
                )
        if not evidence:
            return
        yield self.finding(
            ctx,
            rule_id="WEB-CUSTOM-URL-SCHEME",
            title="Custom URL scheme is reachable from the browser",
            severity=Severity.MEDIUM,
            owasp="M4",
            cwe="CWE-939",
            masvs="MASVS-PLATFORM",
            description=(
                "The app registers a custom URL scheme with the BROWSABLE category, "
                "so any web page the user visits can launch this component and "
                "control the Intent data it receives. Unlike verified App Links, "
                "custom schemes are not tied to a domain you own: another app can "
                "register the same scheme, and the platform gives no guarantee about "
                "who handles the URL or where it came from."
            ),
            remediation=(
                "Treat everything in the incoming URI as untrusted input — validate "
                "and canonicalise every parameter before use, and never let it select "
                "a file path, a class to instantiate, or a URL to load. For links "
                "that must be trustworthy, use verified Android App Links (or "
                "Universal Links on iOS) bound to a domain you control."
            ),
            evidence=evidence,
            references=["https://cwe.mitre.org/data/definitions/939.html"],
        )
