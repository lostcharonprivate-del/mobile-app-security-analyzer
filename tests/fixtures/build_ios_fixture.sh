#!/usr/bin/env bash
# Build the intentionally-vulnerable test IPA.
#
# Compiles a real arm64 iOS Mach-O with clang against the iPhoneOS SDK, so the
# analyzer's Mach-O reader, plist parsing and strings extraction are exercised
# against a genuine binary. Requires Xcode; when the iOS SDK is unavailable the
# script falls back to the host SDK, which is still a valid Mach-O.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/ios_src"
OUT="${1:-$HERE/vulnerable-demo.ipa}"
APP_NAME="VulnerableDemo"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
BUNDLE="$WORK/Payload/$APP_NAME.app"
mkdir -p "$BUNDLE/Frameworks/DemoAnalytics.framework"

echo "==> compiling Mach-O"
if SDK="$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)" && [ -d "$SDK" ]; then
  TARGET_ARGS=(-target arm64-apple-ios13.0 -isysroot "$SDK")
  echo "    using iPhoneOS SDK"
else
  TARGET_ARGS=()
  echo "    iPhoneOS SDK not found; building for the host instead"
fi
clang "${TARGET_ARGS[@]}" \
  -framework Foundation -framework Security \
  -o "$BUNDLE/$APP_NAME" \
  "$SRC/main.m"

echo "==> writing Info.plist"
python3 - "$BUNDLE/Info.plist" <<'PYEOF'
import plistlib, sys

info = {
    "CFBundleIdentifier": "com.masa.vulnerable-ios",
    "CFBundleName": "VulnerableDemo",
    "CFBundleDisplayName": "Vulnerable Demo",
    "CFBundleExecutable": "VulnerableDemo",
    "CFBundleShortVersionString": "2.4.1",
    "CFBundleVersion": "241",
    "MinimumOSVersion": "11.0",
    "CFBundlePackageType": "APPL",
    "CFBundleSupportedPlatforms": ["iPhoneOS"],
    "UIFileSharingEnabled": True,
    "LSSupportsOpeningDocumentsInPlace": True,
    "ITSAppUsesNonExemptEncryption": False,
    # App Transport Security switched off globally, with weak per-domain exceptions.
    "NSAppTransportSecurity": {
        "NSAllowsArbitraryLoads": True,
        "NSAllowsArbitraryLoadsInWebContent": True,
        "NSExceptionDomains": {
            "insecure-ios-demo.example.com": {
                "NSExceptionAllowsInsecureHTTPLoads": True,
                "NSExceptionMinimumTLSVersion": "TLSv1.0",
                "NSExceptionRequiresForwardSecrecy": False,
            },
            "legacy.example.com": {
                "NSThirdPartyExceptionAllowsInsecureHTTPLoads": True,
            },
        },
    },
    # Custom URL schemes reachable from any app or web page.
    "CFBundleURLTypes": [
        {
            "CFBundleURLName": "com.masa.vulnerable-ios",
            "CFBundleURLSchemes": ["vulndemo", "vulndemo-auth"],
        }
    ],
    # A credential parked in the bundle configuration.
    "DemoBackendAPIKey": "AIzaSyC-9pQr4TzXkL2mNbV7wYuI0oPaSdFgHjK",
    "analytics_client_secret": "cs_live_8Hj3Kl9Mn2Pq5Rt7Vw1Xy4Za6Bc0De",
    # Permission prompts, one of them with a uselessly vague justification.
    "NSCameraUsageDescription": "We need it.",
    "NSMicrophoneUsageDescription": "Record audio notes attached to a job report.",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "Track delivery vehicles on an active route.",
    "NSContactsUsageDescription": "",
    "NSUserTrackingUsageDescription": "Show ads that are relevant to you across other apps.",
    "UIBackgroundModes": ["location", "fetch"],
}
with open(sys.argv[1], "wb") as handle:
    plistlib.dump(info, handle, fmt=plistlib.FMT_BINARY)
PYEOF

echo "==> writing framework metadata"
python3 - "$BUNDLE/Frameworks/DemoAnalytics.framework/Info.plist" <<'PYEOF'
import plistlib, sys
with open(sys.argv[1], "wb") as handle:
    plistlib.dump(
        {
            "CFBundleIdentifier": "com.thirdparty.demoanalytics",
            "CFBundleName": "DemoAnalytics",
            "CFBundleShortVersionString": "3.2.1",
        },
        handle,
        fmt=plistlib.FMT_BINARY,
    )
PYEOF

echo "==> writing embedded.mobileprovision"
python3 - "$BUNDLE/embedded.mobileprovision" <<'PYEOF'
import plistlib, sys

# A real provisioning profile is a CMS blob wrapping this plist. The analyzer
# carves the XML out of the surrounding bytes, so the fixture reproduces that
# shape rather than emitting a bare plist.
profile = {
    "AppIDName": "Vulnerable Demo",
    "TeamName": "MASA Test Fixtures",
    "Entitlements": {
        "application-identifier": "ABCDE12345.com.masa.vulnerable-ios",
        "get-task-allow": True,
        "keychain-access-groups": ["ABCDE12345.com.masa.vulnerable-ios"],
    },
}
body = plistlib.dumps(profile, fmt=plistlib.FMT_XML)
with open(sys.argv[1], "wb") as handle:
    handle.write(b"\x30\x82\x0a\x00" + b"\x00" * 32)  # CMS-ish prefix
    handle.write(body)
    handle.write(b"\x00" * 32)
PYEOF

echo "==> writing bundled config"
cat > "$BUNDLE/config.plist" <<'PLEOF'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>backend_url</key><string>http://config.insecure-ios-demo.example.com/settings</string>
    <key>db_password</key><string>iOS_Pr0d_D8_p4ssw0rd</string>
    <key>slack_webhook</key><string>https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX</string>
</dict>
</plist>
PLEOF

echo "==> packaging IPA"
rm -f "$OUT"
(cd "$WORK" && zip -q -r "$OUT" Payload)
echo "==> built $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes)"
