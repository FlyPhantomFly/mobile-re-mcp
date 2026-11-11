#!/usr/bin/env bash
# Rebuild the frida_scripts/*.js bundles from the raw sources in src/.
#
# frida 17 removed the global `Java`/`ObjC` bridges from script runtimes
# (QuickJS *and* V8): scripts must import them explicitly. Raw sources
# are written against the classic global and cannot work as-is, so every
# Java-hooking script ships as a self-contained bundle with
# frida-java-bridge compiled in. memory_scan is pure-native and ships as
# the raw source.
#
# Prerequisites: node + frida-compile (pipx-installed frida-tools ships
# it) and a checkout of the bridge: `npm install frida-java-bridge`.
#
# Usage:  cd python/src/mobile_re_mcp/frida_scripts && bash build_bundles.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
COMPILE="${FRIDA_COMPILE:-$(command -v frida-compile || echo /home/dragon/.local/bin/frida-compile)}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$WORK"
# The bridge must resolve from the working directory.
if [ ! -d node_modules/frida-java-bridge ]; then
    echo "[*] Installing frida-java-bridge..."
    npm init -y >/dev/null
    npm install frida-java-bridge >/dev/null 2>&1
fi

for f in "$HERE"/src/*.js; do
    name="$(basename "$f" .js)"
    if [ "$name" = "memory_scan" ]; then
        continue  # pure-native: ships as-is
    fi
    {
        echo 'import Java from "frida-java-bridge";'
        cat "$f"
    } > "$name.entry.js"
    "$COMPILE" -S -B iife "$name.entry.js" -o "$HERE/$name.js"
    node --check "$HERE/$name.js"
    echo "[+] bundled $name ($(wc -c < "$HERE/$name.js") bytes)"
done

echo "[*] Verifying config-protocol and bridge markers..."
for out in "$HERE"/*.js; do
    name="$(basename "$out" .js)"
    [ "$name" = "memory_scan" ] && continue
    n_recv=$(grep -c 'recv("config"' "$out" || true)
    n_bridge=$(grep -c "frida-java-bridge" "$out" || true)
    if [ "$n_recv" -lt 2 ] || [ "$n_bridge" -lt 1 ]; then
        echo "[!] $name: recv=$n_recv bridge=$n_bridge — refusing" >&2
        exit 1
    fi
done
echo "[*] All bundles verified."
