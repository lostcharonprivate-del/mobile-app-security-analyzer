#!/usr/bin/env bash
# Build the intentionally-vulnerable test APK with the real Android toolchain.
#
# The point of using aapt2/d8/apksigner rather than hand-written bytes is that the
# analyzer then gets exercised against a genuine binary AndroidManifest.xml, a
# genuine resources.arsc and genuine d8-produced DEX bytecode.
#
# Usage: build_android_fixture.sh [output.apk]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/android_src"
OUT="${1:-$HERE/vulnerable-demo.apk}"

SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}"
if [ ! -d "$SDK" ]; then
  echo "Android SDK not found at $SDK; set ANDROID_SDK_ROOT" >&2
  exit 2
fi
BT="$(ls -d "$SDK"/build-tools/*/ 2>/dev/null | sort -V | tail -1)"
PLATFORM="$(ls -d "$SDK"/platforms/android-*/ 2>/dev/null | sort -V | tail -1)"
ANDROID_JAR="$PLATFORM/android.jar"
for tool in aapt2 d8 zipalign apksigner; do
  [ -x "$BT$tool" ] || { echo "missing $tool in $BT" >&2; exit 2; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> compiling resources"
mkdir -p "$WORK/compiled" "$WORK/gen" "$WORK/classes" "$WORK/dex"
"$BT"aapt2 compile --dir "$SRC/res" -o "$WORK/compiled/res.zip"

echo "==> linking resources + manifest"
"$BT"aapt2 link \
  -I "$ANDROID_JAR" \
  --manifest "$SRC/AndroidManifest.xml" \
  --java "$WORK/gen" \
  -A "$SRC/assets" \
  --min-sdk-version 21 \
  --target-sdk-version 34 \
  -o "$WORK/base.apk" \
  "$WORK/compiled/res.zip"

echo "==> compiling java"
find "$SRC/java" "$WORK/gen" -name '*.java' > "$WORK/sources.txt"
javac -nowarn -source 8 -target 8 \
  -bootclasspath "$ANDROID_JAR" \
  -classpath "$ANDROID_JAR" \
  -d "$WORK/classes" \
  @"$WORK/sources.txt" 2>&1 | grep -v 'bootstrap class path' || true

echo "==> dexing"
find "$WORK/classes" -name '*.class' > "$WORK/classes.txt"
"$BT"d8 --lib "$ANDROID_JAR" --min-api 21 --output "$WORK/dex" @"$WORK/classes.txt"

echo "==> packaging"
cp "$WORK/base.apk" "$WORK/unsigned.apk"
(cd "$WORK/dex" && zip -q "$WORK/unsigned.apk" classes.dex)

echo "==> aligning"
"$BT"zipalign -f 4 "$WORK/unsigned.apk" "$WORK/aligned.apk"

echo "==> signing"
KEYSTORE="$WORK/debug.keystore"
keytool -genkeypair -v \
  -keystore "$KEYSTORE" -storepass android -keypass android \
  -alias masatest -keyalg RSA -keysize 2048 -validity 10000 \
  -dname "CN=MASA Test Fixture, OU=Testing, O=mobile-app-security-analyzer, C=US" \
  >/dev/null 2>&1
"$BT"apksigner sign \
  --ks "$KEYSTORE" --ks-pass pass:android --key-pass pass:android \
  --ks-key-alias masatest \
  --out "$OUT" "$WORK/aligned.apk"

echo "==> built $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes)"
