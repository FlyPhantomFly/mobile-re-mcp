# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
