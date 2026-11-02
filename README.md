<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/social-preview-dark.svg">
  <img src="docs/social-preview-light.svg" alt="mobile-re-mcp" width="100%">
</picture>

<p align="center">
  <a href="https://www.npmjs.com/package/mobile-re-mcp"><img src="https://img.shields.io/npm/v/mobile-re-mcp?color=0ea5e9&label=npm" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/mobile-re-mcp"><img src="https://img.shields.io/npm/dm/mobile-re-mcp?color=0ea5e9&label=downloads" alt="npm downloads"></a>
  <a href="https://pypi.org/project/mobile-re-mcp/"><img src="https://img.shields.io/pypi/v/mobile-re-mcp?color=3776ab&label=pypi" alt="PyPI version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-10b981" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/TypeScript-5.3-3178c6" alt="TypeScript">
  <img src="https://img.shields.io/badge/MCP-compatible-6366f1" alt="MCP">
  <a href="https://github.com/FlyPhantomFly/mobile-re-mcp/actions"><img src="https://img.shields.io/github/actions/workflow/status/FlyPhantomFly/mobile-re-mcp/ci.yml?label=CI" alt="CI"></a>
</p>

<p align="center">
  <a href="#two-servers-one-name">Two servers</a> ·
  <a href="#features">Features</a> ·
  <a href="#installation">Installation</a> ·
  <a href="#tools">Tools</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#contributing">Contributing</a> ·
  <a href="#security">Security</a>
</p>

---

**mobile-re-mcp** is an [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that gives Claude — and any MCP-compatible AI client — the ability to analyze Android APK and iOS IPA files for security issues through natural language conversation.

Security researchers, mobile pentesters, and app developers can now audit permissions, extract API endpoints, detect hardcoded secrets, inspect Firebase configuration, and enumerate third-party SDKs by simply asking Claude — no scripting required.

---

## Two servers, one name
This repo ships two MCP servers that work together and are released together under one version number.

| | npm `mobile-re-mcp` | pip `mobile-re-mcp` |
|---|---|---|
| What it does | Read-only static analysis of APK and IPA files | Drives a test device: adb, Frida, mitmproxy, apktool, jadx, patching |
| Language | TypeScript (this folder) | Python ([`python/`](python)) |
| Install | `npm install -g mobile-re-mcp` | `pip install "mobile-re-mcp[all]"` |
| Command | `mobile-re-mcp` | `mobile-re-mcp-py` |
| Needs a device | No | For most tools |

Start with the npm server to see what an app asks for and what it leaks, then use the Python server when you need the app running. The rest of this page is about the npm server. The Python server is documented in [python/README.md](python/README.md).

---

## Features

### Android
| Tool | What it does |
|---|---|
| `apk_manifest_analyzer` | Parses `AndroidManifest.xml` — flags `debuggable`, `allowBackup`, exported components, intent filters |
| `apk_permissions_checker` | Categorizes all permissions into **dangerous** vs normal with risk explanations |
| `android_api_extractor` | Decompiles smali bytecode to extract Retrofit HTTP endpoints and OkHttp3 fields |
| `android_google_services` | Extracts Firebase/GCP config from `google-services.json` and `resources.arsc` string values |
| `android_secrets_scanner` | Scans DEX bytecode + `resources.arsc` + assets for hardcoded API keys and credentials |

### iOS
| Tool | What it does |
|---|---|
| `ios_manifest_analyzer` | Parses `Info.plist` — flags ATS misconfigs, URL schemes, background modes |
| `ios_permissions_checker` | Categorizes privacy permission declarations by **HIGH / MEDIUM / LOW** risk |
| `ios_entitlements_checker` | Extracts entitlements via `codesign` — flags `get-task-allow`, sandbox bypass, iCloud containers |
| `ios_binary_strings` | Extracts URLs, emails, IPs, and API key patterns from the Mach-O binary |
| `ios_frameworks_detector` | Lists bundled frameworks, maps ~60 known SDKs (analytics, ads, attribution, crash reporting) |
| `ios_google_services` | Parses `GoogleService-Info.plist` for full Firebase configuration |
| `ios_secrets_scanner` | Scans app binary + resource files for hardcoded secrets and credentials |

### Shared Pattern Registry
All secret and Google service detection patterns live in a single `patterns.ts` — easy to extend, used by both Android and iOS scanners.

---

## Requirements

- **Node.js 22+** (built on the MCP TypeScript SDK v2)
- For Android analysis, any of: `apktool`, `aapt` / `aapt2` (Android build-tools), and the `strings` utility (binutils) on your `PATH`
- Windows: tools are launched without a shell, so `apktool` must resolve to a real executable. The `apktool.bat` wrapper cannot be launched this way; use `apktool.exe` or put a launcher that is a real `.exe` on your `PATH`.

## Security notes

- Tool arguments are never interpolated into a shell command. External programs are started with an argument array (no shell), so a crafted `apk_path` cannot inject commands.
- `apk_path` / `ipa_path` must be absolute paths to existing `.apk` / `.ipa` files (checked for ZIP magic bytes); `smali_folder` must be an existing directory.
- Optional sandbox: set `MOBILE_RE_MCP_ALLOWED_DIRS` (`:`-separated on macOS/Linux, `;` on Windows) to restrict the tools to specific directories, e.g. in your Claude Desktop config:

```json
{
  "mcpServers": {
    "mobile-re-mcp": {
      "command": "npx",
      "args": ["mobile-re-mcp"],
      "env": { "MOBILE_RE_MCP_ALLOWED_DIRS": "/Users/me/apks" }
    }
  }
}
```

- Analyzing untrusted apps means parsing hostile files with `apktool`, `aapt`, and `strings`. Keep them updated, and ideally run this server in a VM or container.
- Findings (including discovered secrets) are returned to your AI client, and therefore to your model provider.

---

## Installation

```bash
npm install -g mobile-re-mcp
```

### Configure Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mobile-re-mcp": {
      "command": "npx",
      "args": ["mobile-re-mcp"]
    }
  }
}
```

**Config file locations:**
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

### Run from source

```bash
git clone https://github.com/FlyPhantomFly/mobile-re-mcp.git
cd mobile-re-mcp
npm install && npm run build
```

```json
{
  "mcpServers": {
    "mobile-re-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/mobile-re-mcp/dist/index.js"]
    }
  }
}
```

---

## Usage

Once configured, restart Claude Desktop and start a conversation:

> *"Analyze the permissions in /path/to/app.apk"*

> *"Check this IPA for hardcoded API keys: /path/to/app.ipa"*

> *"What Firebase services does this APK use?"*

> *"Are there any exported components in this APK that could be an attack surface?"*

> *"Show me all third-party SDKs in this iOS app and flag any privacy risks"*

### Prerequisites

**Android:**
- [`apktool`](https://apktool.org) — required for `android_api_extractor` (`brew install apktool`)
- `aapt` (optional) — speeds up manifest parsing, part of Android SDK build tools

**iOS (macOS only):**
- `codesign`, `plutil`, `strings` — all built into macOS, no install needed

---

## Tools

### `apk_manifest_analyzer`
```
Input:  apk_path (string)
Output: Package info, security flags, components, intent filters, warnings
```

### `apk_permissions_checker`
```
Input:  apk_path (string)
Output: Dangerous permissions (highlighted) + normal permissions + risk summary
```

### `android_api_extractor`
```
Input:  apk_path OR smali_folder (string), output_format (txt|postman)
Output: Retrofit HTTP endpoints or Postman collection JSON
```

### `android_google_services`
```
Input:  apk_path (string), smali_folder (optional)
Output: Firebase project ID, API keys, database URL, storage bucket, OAuth clients
```

### `android_secrets_scanner`
```
Input:  apk_path (string), smali_folder (optional), min_length (default 8)
Output: Hardcoded credentials found in DEX + resources.arsc + assets
```

### `ios_manifest_analyzer`
```
Input:  ipa_path (string)
Output: Bundle info, ATS settings, URL schemes, background modes, warnings
```

### `ios_permissions_checker`
```
Input:  ipa_path (string)
Output: Privacy permissions grouped by HIGH/MEDIUM/LOW risk with usage descriptions
```

### `ios_entitlements_checker`
```
Input:  ipa_path (string)
Output: Entitlements extracted from binary, high-risk flags, simulator detection
```

### `ios_binary_strings`
```
Input:  ipa_path (string), filter (all|url|key|email|ip), min_length (default 6)
Output: Filtered strings from Mach-O binary
```

### `ios_frameworks_detector`
```
Input:  ipa_path (string)
Output: Bundled frameworks grouped by category with privacy risk annotations
```

### `ios_google_services`
```
Input:  ipa_path (string)
Output: Full GoogleService-Info.plist contents + pattern scan of resource files
```

### `ios_secrets_scanner`
```
Input:  ipa_path (string), min_length (default 8)
Output: Secrets found in resource files and binary, split by layer with severity
```

---

## Demo

![demo](docs/demo.gif)

> Regenerate with [VHS](https://github.com/charmbracelet/vhs): `brew install charmbracelet/tap/vhs && vhs docs/demo.tape`

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, how to add new tools, and PR guidelines.

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities privately.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE) © 2026 [FlyPhantomFly](https://github.com/FlyPhantomFly)
