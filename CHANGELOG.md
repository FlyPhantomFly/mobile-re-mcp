# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-11-02

### Added
- Python server in `python/`, published on PyPI as `mobile-re-mcp` (command `mobile-re-mcp-py`). It adds adb, Frida, mitmproxy, apktool/jadx, patching and signing tools. It is derived from `mobile-security-mcp` 0.1.4 (MIT), see `python/NOTICE.md`.
- One release tag now publishes both packages, and CI fails if their versions differ. The npm package has no code changes in this release.

### Security (Python server)
- Every tool call is checked before it runs. File arguments reject a leading `-`, NUL bytes and protected places such as `~/.ssh`, `~/.config/gh` and shell rc files, and they follow `MOBILE_RE_MCP_ALLOWED_DIRS`.
- `native_disasm` no longer lets `;` or `!` reach radare2, which allowed shell commands from a hostile symbol name.
- `search_strings` passes the pattern to ripgrep with `-e` and `--`, so `--pre=...` can no longer run a program.
- SSE listens on 127.0.0.1 only, rejects foreign Host headers, and needs `MOBILE_RE_MCP_TOKEN` for any other address. It used to bind 0.0.0.0 with no authentication.
- mitmproxy listens on 127.0.0.1 only. Use `adb reverse` to reach it from the device.
- Downloads are pinned to a release and checked against a SHA-256. The apktool wrapper script no longer comes from the `master` branch.
- `install_tool` is off unless `MOBILE_RE_MCP_ALLOW_INSTALL=1`. pip installs no longer use `--break-system-packages` and cannot change an installed Frida.
- Scratch files live in a private folder instead of fixed names in `/tmp`, and `frida_server_push` no longer picks up binaries from `/tmp`.
- Target notes are stored under `~/.local/share/mobile-re-mcp` and the package name is validated. It could write into any folder before.

### Changed (Python server)
- Requires `mcp` 1.30 or newer and below 2. SDK 2 removed the handler decorators this server uses, so the port is still to do.
- The heavy tools (frida, androguard, apkid, apkleaks, mitmproxy, quark-engine) are optional extras. `textual`, `rich` and `tomli` are no longer dependencies.
- Settings moved to `~/.config/mobile-re-mcp/config.toml`. Nothing is created or added to `PATH` at import time any more.
- Downloaded tools are apktool 2.12.1, jadx 1.5.6, uber-apk-signer 1.3.0, Il2CppDumper 6.7.46 and scrcpy 5.0.1 (Windows). adb is no longer downloaded because Google only publishes an unversioned build. The smali/baksmali installer is gone because its URLs return 404.

### Fixed (Python server)
- `apk_sign` looked for the signer jar in the current directory while the installer put it in `~/tools/signing`.
- `frida_server_push` ignored a failed `chmod` on the device.
- `frida_list_scripts` listed scripts that are not in the package. It now lists only scripts that exist, and your own go in `~/.local/share/mobile-re-mcp/frida_scripts`.
- The SSE endpoint used a route type that cannot serve the message endpoint.
- mitm helper scripts ran under whatever `python` was on `PATH` and now use the server's interpreter.

## [1.1.2] - 2026-11-02

### Fixed
- Added package-lock.json so npm ci works in CI.
- CI now runs on master.

## [1.1.0] - 2026-11-01

### Security
- No tool builds shell command strings any more. All external programs (`apktool`, `aapt`, `aapt2`, `strings`, `file`, `codesign`, `ldid`, `plutil`) run via `execFileSync` with argument arrays and a timeout, closing a command-injection path through `apk_path` / `smali_folder`.
- Input paths are validated: must be absolute, exist, and resolve (symlinks) to a regular `.apk` / `.ipa` file with ZIP magic bytes, or to a directory for `smali_folder`.
- iOS: `CFBundleExecutable` read from an untrusted `Info.plist` is regex-escaped before matching, and the binary-plist conversion uses a private temp directory instead of a predictable file name.
- New optional `MOBILE_RE_MCP_ALLOWED_DIRS` allow-list for readable locations.
- `secrets-scanner`: smali-folder scan now reads regular files only (no symlink-following).
- `reusable-analyze.yml`: workflow inputs/outputs are passed through `env` instead of being interpolated into shell; random heredoc delimiter for step outputs.

### Changed
- The server reports the version from `package.json` instead of a hard-coded string.
- Renamed project to `mobile-re-mcp` (package, binary, server name, docs) and maintainer/repository owner to `FlyPhantomFly`. The original MIT copyright notice (Serhatcck) is retained in `LICENSE`.
- Migrated to MCP TypeScript SDK v2 (`@modelcontextprotocol/server`, `registerTool`, `serveStdio`); tool schemas are wrapped in `z.object(...)`.
- Dependencies: `zod` 3 -> 4, `adm-zip` -> 0.6 (fixes CVE-2026-39244; ships its own types), `typescript` 5 -> 6, `@types/node` 20 -> 22. Removed `ts-node` and `@types/adm-zip`. `@modelcontextprotocol/sdk` ("latest") replaced by pinned-range `@modelcontextprotocol/server`.
- Requires Node.js 22+. CI and publish workflows use `actions/checkout@v6` and `actions/setup-node@v6`; Dependabot now also tracks GitHub Actions.
- `package-lock.json` removed so it can be regenerated against the new dependency set (`npm install`).

## [1.0.0] - 2025-04-02

### Added

**Android tools**
- `apk_manifest_analyzer` — parses AndroidManifest.xml, flags debuggable/allowBackup/cleartext traffic, exported components, intent filters
- `apk_permissions_checker` — categorizes dangerous vs normal permissions with risk summary
- `android_api_extractor` — decompiles smali bytecode to extract Retrofit HTTP endpoints and OkHttp3 fields; outputs plain text or Postman collection
- `android_google_services` — extracts Firebase/GCP config from `google-services.json` and `resources.arsc` via strings command; supports optional smali_folder for structured output
- `android_secrets_scanner` — scans DEX bytecode + `resources.arsc` + text assets for hardcoded API keys and credentials

**iOS tools**
- `ios_manifest_analyzer` — parses Info.plist, flags ATS misconfigs, URL schemes, background location, queried schemes
- `ios_permissions_checker` — maps all `NS*UsageDescription` keys to HIGH/MEDIUM/LOW risk with explanations
- `ios_entitlements_checker` — extracts entitlements from app binary via codesign/ldid, flags get-task-allow and sandbox bypass, detects simulator builds
- `ios_binary_strings` — extracts URLs, emails, private IPs, and API key patterns from Mach-O binary
- `ios_frameworks_detector` — enumerates bundled .framework and .dylib files, maps ~60 known SDKs across networking, analytics, ads, attribution, crash reporting, fraud detection categories
- `ios_google_services` — parses GoogleService-Info.plist for full Firebase configuration
- `ios_secrets_scanner` — two-layer scan: text resource files (plist/json/strings) + app binary via strings command

**Shared**
- `patterns.ts` — centralized `GOOGLE_PATTERNS` and `SECRET_PATTERNS` registry shared across all scanner tools; `scanText` and `renderResults` utilities
