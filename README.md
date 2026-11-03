# mobile-re-mcp
[![npm](https://img.shields.io/npm/v/mobile-re-mcp?color=0ea5e9&label=npm)](https://www.npmjs.com/package/mobile-re-mcp) [![PyPI](https://img.shields.io/pypi/v/mobile-re-mcp?color=3776ab&label=pypi)](https://pypi.org/project/mobile-re-mcp/) [![CI](https://img.shields.io/github/actions/workflow/status/FlyPhantomFly/mobile-re-mcp/ci.yml?label=CI)](https://github.com/FlyPhantomFly/mobile-re-mcp/actions) [![MIT](https://img.shields.io/badge/license-MIT-10b981)](LICENSE)

An MCP server that reads Android APKs and iOS IPAs and tells your AI assistant what is inside: permissions, exported components, hardcoded secrets, Firebase config, App Transport Security settings, entitlements and bundled SDKs. You ask in plain language, the assistant calls the right tool, and the findings come back. It only reads files and never runs the app.
This repo also holds a second server for the live side of the work (adb, Frida, mitmproxy and patching on a real device). It is written in Python and described [further down](#the-python-server).

## An example
The sample below is an IPA made for this README: a small notes app with a few deliberate mistakes in it. You ask:
> Check /home/me/apks/NotesDemo.ipa for anything risky.

The assistant runs the manifest analyzer and the secrets scanner. The output is trimmed here, and key values are masked:
```text
=== iOS Info.plist Analysis ===
Bundle ID   : com.example.notes
Version     : 2.3.1 (build 231)
Min iOS     : 15.0
--- URL Schemes (Deep Links) ---
  notesdemo://
  fb1234567890://
--- App Transport Security (ATS) ---
  NSAllowsArbitraryLoads        : true
=== Security Warnings ===
  ⚠ Short/generic URL scheme detected — may be vulnerable to scheme hijacking
  ⚠ NSAllowsArbitraryLoads=true — all HTTP traffic is allowed, bypassing ATS
  ⚠ Background location mode enabled — app can track location when not in foreground
```
```text
=== iOS Secrets Scanner ===
--- Found in Resource Files ---
[CRITICAL] AWS Access Key ID
  → AKIA…DEMO
--- Found in Binary (not in resources) ---
[CRITICAL] Stripe Secret Key — server-side key in client
  → sk_live_…DEMO
⚠ 2 CRITICAL finding(s) — immediate review required.
```
From there you can keep talking: "Which of those warnings matter if the app only talks to my own API?" The assistant already has the findings and can answer.
![Demo recording](docs/demo.gif)

## Install
```bash
npm install -g mobile-re-mcp
```
You need Node 22 or newer. The server speaks MCP over stdio, so register it with your client as a command.
Claude Code:
```bash
claude mcp add mobile-re -- npx -y mobile-re-mcp
```
opencode, in `~/.config/opencode/opencode.json`:
```json
{
  "mcp": {
    "mobile-re": { "type": "local", "command": ["npx", "-y", "mobile-re-mcp"], "enabled": true }
  }
}
```
Claude Desktop, in `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`, Windows: `%APPDATA%\Claude\`):
```json
{
  "mcpServers": {
    "mobile-re": { "command": "npx", "args": ["-y", "mobile-re-mcp"] }
  }
}
```
Other clients work the same way: command `npx`, arguments `-y mobile-re-mcp`. If your client cannot see your shell's PATH (common with nvm), give it the full path to `node` and to `dist/index.js` in the global install instead.
To run from a checkout, use `git clone https://github.com/FlyPhantomFly/mobile-re-mcp.git`, then `npm ci && npm run build`, and point the client at `node /path/to/mobile-re-mcp/dist/index.js`.

## What to ask
- "Which permissions in /path/to/app.apk are dangerous, and why?"
- "Are any components in this APK exported where an attacker could reach them?"
- "What API endpoints does this APK call?"
- "Which Firebase project does this app use, and are its keys in the app?"
- "Scan this IPA for hardcoded keys and tell me where each one was found."
- "Which third-party SDKs does this iOS app bundle, and which of them track users?"

## Tools
Every tool takes the file as an absolute path, `apk_path` for Android or `ipa_path` for iOS.

| Tool | What it reports | Needs |
| --- | --- | --- |
| `apk_manifest_analyzer` | Package info, `debuggable` and `allowBackup` flags, exported components, intent filters | `aapt`, or `apktool` |
| `apk_permissions_checker` | Permissions split into dangerous and normal, with a short reason for each | `aapt` or `aapt2`, or `apktool` |
| `android_api_extractor` | Retrofit endpoints and OkHttp fields from decompiled smali, as text or a Postman collection | `apktool`, or a smali folder you already have |
| `android_google_services` | Firebase and Google Cloud settings from `google-services.json` and `resources.arsc` | `strings` |
| `android_secrets_scanner` | Hardcoded keys and credentials in DEX files, resources and assets | `strings` |
| `ios_manifest_analyzer` | Bundle info, ATS settings, URL schemes, background modes, warnings | `plutil` for binary plists |
| `ios_permissions_checker` | Privacy permission strings ranked HIGH, MEDIUM or LOW | `plutil` for binary plists |
| `ios_entitlements_checker` | Entitlements, with flags like `get-task-allow` and sandbox exceptions | `codesign` (macOS) |
| `ios_binary_strings` | URLs, emails, IPs and key-like strings from the Mach-O binary | `strings` |
| `ios_frameworks_detector` | Bundled frameworks and dylibs, matched against about 60 known SDKs | nothing |
| `ios_google_services` | The contents of `GoogleService-Info.plist` | `plutil` for binary plists |
| `ios_secrets_scanner` | Secrets in resource files and in the binary, with severity | `strings` |

Some tools take extra options. `smali_folder` lets the Android tools reuse an existing decompile. `android_api_extractor` also takes `output_format` (`txt` or `postman`). The scanners take `min_length`, and `ios_binary_strings` takes `filter` (`all`, `url`, `key`, `email` or `ip`).
`aapt`, `apktool`, `strings` and `plutil` need to be on your PATH. `plutil` and `codesign` only exist on macOS. Most real IPAs use binary plists, so on Linux the plist-based iOS tools only work on IPAs with XML plists, and the full iOS set is best run on a Mac. On Windows the tools start without a shell, so `apktool` has to resolve to a real `.exe`, not `apktool.bat`.

## Staying safe
- External programs are started with an argument array, never through a shell, so a crafted path cannot inject a command.
- The file has to exist, be an absolute path and look like a ZIP (`.apk` or `.ipa`).
- To limit where the server may read, set `MOBILE_RE_MCP_ALLOWED_DIRS` (separate folders with `:`, or `;` on Windows). For example, in the Claude Desktop entry add `"env": { "MOBILE_RE_MCP_ALLOWED_DIRS": "/home/me/apks" }`.
- An untrusted app is hostile input for `apktool`, `aapt` and `strings`. Keep them updated, and for samples you do not trust, run the server in a VM or container.
- Findings, including any secrets that were found, go to your AI client and so to its model provider.

## The Python server
The Python server in [`python/`](python) is for the work that needs a running app. It drives adb, Frida, mitmproxy, apktool and jadx against a test phone, so the assistant can decompile an app, hook it, read its traffic, patch it, sign it and install it again. It is Android only, has about 55 tools, and several of them can change your device, which is why they ask for approval first.
```bash
pip install "mobile-re-mcp[all]"
```
The command is `mobile-re-mcp-py`. The setup, tool list and safety notes are in [python/README.md](python/README.md). The usual order is the npm server first, to see what an app asks for and leaks, then the Python server when you need the app running. You can install either one without the other, and both share a version number.

## Working on it
Build with `npm ci && npm run build`. [CONTRIBUTING.md](CONTRIBUTING.md) explains how to add a tool or a detection pattern, [SECURITY.md](SECURITY.md) is for reporting vulnerabilities, and [CHANGELOG.md](CHANGELOG.md) lists what changed.

## License
MIT. The npm server began as a fork of Serhatcck's mobile-security-mcp (© 2025 Serhatcck), with changes © 2026 FlyPhantomFly. The Python server is derived from mobile-security-mcp 0.1.4 on PyPI, see [python/NOTICE.md](python/NOTICE.md).
