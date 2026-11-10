#!/usr/bin/env bash
# Build tests/fixtures/notesdemo.apk from notesdemo/AndroidManifest.xml.
#
# The built APK is committed so the androguard regression tests run hermetically
# in CI (which has no Android SDK). It is our own 5 KB fixture — hence the
# explicit .gitignore exception for exactly this file; the repo-wide *.apk ban
# on committing third-party sample apps still stands. Rebuild it after editing
# the manifest and re-commit both together:
#
#     bash tests/fixtures/build_notesdemo.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
AAPT2="${AAPT2:-$HOME/Android/Sdk/build-tools/34.0.0/aapt2}"
ANDROID_JAR="${ANDROID_JAR:-$HOME/Android/Sdk/platforms/android-36.1/android.jar}"
D8="${D8:-$HOME/Android/Sdk/build-tools/34.0.0/d8}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Trivial classes.dex — the APK needs at least one dex because the Java tests
# drive AnalyzeAPK on it, not just the manifest.
mkdir -p "$TMP/gen/com/example/notes"
cat > "$TMP/gen/com/example/notes/Notes.java" <<'EOF'
package com.example.notes;
public final class Notes {
    public int id;
    public Notes() {}
}
EOF
mkdir -p "$TMP/classes"  # JDK 8 javac does not create -d itself
if ! javac --version >/dev/null 2>&1; then
    javac -source 8 -target 8 -d "$TMP/classes" "$TMP/gen/com/example/notes/Notes.java"  # JDK 8
else
    javac --release 8 -d "$TMP/classes" "$TMP/gen/com/example/notes/Notes.java"
fi
(cd "$TMP/classes" && "$D8" --release --min-api 21 --output "$TMP" com/example/notes/Notes.class)

# Binary XML manifest + resources, then attach classes.dex to the archive.
"$AAPT2" link --no-compile-sdk-metadata \
    -o "$TMP/notesdemo-stage.apk" -I "$ANDROID_JAR" \
    --manifest "$HERE/notesdemo/AndroidManifest.xml"
(cd "$TMP" && zip -j -q "$TMP/notesdemo-stage.apk" "$TMP/classes.dex")

cp "$TMP/notesdemo-stage.apk" "$HERE/notesdemo.apk"
echo "built $(ls -l "$HERE/notesdemo.apk" | awk '{print $5}') bytes"
