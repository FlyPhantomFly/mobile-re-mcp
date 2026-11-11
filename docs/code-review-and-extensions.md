# Code review and extension proposals — mobile-re-mcp (both servers)

Reviewed 2026-11-10. Method: full read of both codebases, plus **live smoke tests against both running MCP servers** (the ones this repo publishes), with a real device attached and a real APK (`TermuxBoot_v0.8.1_GitHub.apk`, package `com.termux.boot`, 3 DEX files, r8-compiled).

Every finding below is tagged: **[verified live]** (reproduced in a fresh tool call during this review), **[code]** (read from source), or **[test]** (established by the existing test suite).

Companion files: this document extends the current README's [tool tables](../README.md) — it does not replace them.

---

## Part 0 — What each server currently is (one-paragraph reference)

### The Python server — PyPI package `mobile-re-mcp`, command `mobile-re-mcp-py`

One GitHub-flavoured codebase in `python/src/mobile_re_mcp/`:

- `server.py` — declares all 56 tool schemas in one `TOOL_SCHEMAS` list, wires them to 10 handler classes in a dispatch table, and serves resources (5 knowledge packs) and prompts (7 guided playbooks). Transports: stdio (default) and SSE (loopback, bearer-token enforced off-loopback).
- `handlers/*.py` — the actual work: `static.py` (apktool/jadx/apkid/apkleaks/androguard), `dynamic.py` (Frida sessions, script library, hluda, memory), `device.py` (adb, logcat, scrcpy, hermes), `network.py` (mitmproxy), `patcher.py` + `signing.py` (smali edit, gadget embed, uber-apk-signer), `native.py` / `flutter.py` (radare2, Il2CppDumper, Blutter), `rasp.py` (vendor fingerprints + bypass scripts), `memory.py` (per-target notes).
- `guard.py` — validates every call before dispatch: path deny-lists, `MOBILE_RE_MCP_ALLOWED_DIRS`, `MOBILE_RE_MCP_DISABLE_TOOLS`, per-argument regexes.
- `paths.py` / `config.py` — `~/.local/share/mobile-re-mcp` for all writes (0700), `~/.config/mobile-re-mcp/config.toml` for `[signing]` settings, `~/tools` for downloaded binaries.
- `setup/` — `check_tools.py` (35-item inventory used by the `check_tools` MCP tool) and `install_tool.py` (SHA-256-pinned downloads + pip/npm recipes; MCP-invocable only with `MOBILE_RE_MCP_ALLOW_INSTALL=1`).
- Tests: `python/tests/` — 28 tests, mostly on the guard, downloads (sha-pin, zip-slip, plain-http refusal) and a handful of handler behaviours. **No test executes an androguard code path**, which is why the API drift below shipped.

### The npm server — npm package `mobile-re-mcp`, command `mobile-re-mcp`

One TypeScript codebase in `src/`:

- `src/index.ts` — registers 12 tools with the MCP TypeScript SDK v2 (`registerTool`), serves over stdio; version read from `package.json`.
- `src/tools/android/*` — 5 Android analyzers (manifest, permissions, API endpoints → text/Postman, Google/Firebase config, secrets).
- `src/tools/ios/*` — 7 iOS analyzers (manifest/ATS, permission strings, entitlements, binary strings, framework inventory, Google plist, two-layer secrets).
- `src/tools/shared/safe-exec.ts` — the only way anything runs: `execFileSync` with argument arrays (`shell: false`), 10-min timeout, 100 MiB buffer cap, plus `checkInputFile` (absolute path, symlink-resolved, regular file, `.apk`/`.ipa` extension, ZIP magic bytes, `MOBILE_RE_MCP_ALLOWED_DIRS` sandbox).
- `src/tools/shared/patterns.ts` — the shared regex registry (5 Google patterns, 15 secret patterns) and the uniform text renderer.

The npm server performs zero writes except in `os.tmpdir()` and never accepts a "running" target — its toolset is exactly what the Python server is not.

---

## Part 1 — Python server: findings

### F-PY-1. androguard API drift breaks three tools on the pinned extra — **[verified live]** — **Status: fixed**

`[analysis]`-adjacent extra `[static]` declares `androguard>=3.4.0a1` (pyproject.toml:28), so today's installs get **4.1.4** (verified live: `check_tools` reports `androguard 4.1.4`). In androguard 4.x the APK class no longer has `get_activity_is_exported()`, and `Analysis` cross-reference accessors return different shapes. Results measured live on `com.termux.boot`:

| Tool | Live result |
| --- | --- |
| `manifest_parse` | `error: 'APK' object has no attribute 'get_activity_is_exported'` |
| `analyze_code` | `error: 'tuple' object has no attribute 'class_name'` — `handlers/static.py:350-357` assumes `get_xref_from()` yields method objects, 4.x yields tuples |
| `find_crypto_usage` | returned `ok` with 0 usages on a crypto-free app — cannot pass unit coverage; same suspect accessors (`for _, callee, _ in method.get_xref_to()`, static.py:437) mean it will mis-shape or drop results on any app with crypto calls |
| `find_urls` | worked (returned 20 URLs) — keep its approach |
| `apk_analyze_full` | silently reports the broken `manifest_parse` output inside its `manifest` field while still returning `status: ok` — masking failure is worse than failing |

Where it lives: `handlers/static.py:229-257` (`manifest_parse`), `:315-383` (`analyze_code`), `:423-463` (`find_crypto_usage`), `:185-219` (`apk_analyze_full`).

### F-PY-2. `check_tools` reports availability the handlers can't use — **[verified live]** — **Status: fixed**

- `check_tools` checks apkleaks as a *Python module* (importable → `available: true`, check_tools.py:172), but `apk_scan_secrets` needs the **CLI on PATH** (`shutil.which("apkleaks")`, static.py:153). Live: `check_tools` said apkleaks ✓; `apk_scan_secrets` returned `missing_tool 'apkleaks' not found on PATH.` The inventory lies to the assistant exactly when it matters (it recommends "run check_tools first" in docs).
- `check_tools` reports `medusa` **available** — live output was `Medusa v2.3 [http://www.foofus.net]` — that is the SSH/password **login cracker**, not the Frida script framework this tool chain expects. Name collision, false positive (check_tools.py:238).

*Fix:* all CLI consumers and `check_tools` resolve through the new `mobile_re_mcp.clitools.find_cli` (PATH first, then the console-script dir next to the running interpreter — venv installs where PATH misses the venv bin); apkleaks/apkid are probed as executables; `medusa` runs a version probe and rejects any banner containing `foofus.net` with a GitHub hint for the real framework; `install_tool` no longer has a pip recipe for `medusa`/`fridump` (manual-required).

### F-PY-3. The built-in Frida script library is a façade — **[verified live]** — **Status: fixed**

`frida_scripts/index.py` catalogues 8 scripts (`ssl_pinning_universal`, `root_detection_bypass`, `frida_detection_bypass`, `crypto_monitor`, `memory_scan`, `method_tracer`, `storage_monitor`, `network_monitor`) but the package ships **zero `.js` files** (`frida_scripts/` contains only `index.py`, `__init__.py`). `frida_list_scripts` correctly applies the 1.2.0 fix that only lists files that exist, so live result: `total: 0, available_categories: []`.

Consequences beyond the library itself: `frida_find_bytes` **depends on the missing `memory_scan.js`** (dynamic.py:547-549 returns an error if absent), and the docs' "frida_get_script → frida_run_script" workflow is unusable out of the box. The CHANGELOG 1.2.0 entry ("It now lists only scripts that exist") papered over the symptom instead of shipping the files.

*Fix:* all 8 `.js` files are shipped with the package (E-PY-1, commit `4270bd9`), every script implements the config protocol, and the library is guarded by unit tests that compare the catalogue against what is on disk.

### F-PY-4. Sync handlers block the asyncio event loop — **[code]** — **Status: fixed**

`server.py`'s `call_tool` invokes every handler directly; all handlers are synchronous (`subprocess.run` with 120–600 s timeouts, `time.sleep(1)` in `mitm_start`). Inside asyncio, this freezes the whole server for the duration of e.g. a jadx decompile. — no other tool call is processed, even in SSE mode with a second client.

*Fix:* E-PY-4 (commit `ed2fd6b`): `call_tool` is a thin wrapper over `_run_tool`; stateless handlers run via `asyncio.to_thread` and the three stateful classes own a dedicated single-worker pool (`_SERIALIZE`), proven by `tests/test_concurrency.py`.

### F-PY-5. Config values for Frida scripts are injected by textual `var X = "";` replacement — **[code]** — **Status: fixed**

`frida_run_script` (dynamic.py:265-270) and `frida_find_bytes` (dynamic.py:553-563) patch values into JS via `str.replace`. Any apostrophe or quote in a user-provided search string breaks (or re-flows) the injected script, and the pattern depends on the script author remembering an exact `var SEARCH_STRING = "";` line. A message-passing config protocol (below) removes both hazards.

*Fix:* E-PY-6 (commit `a4e15e1`): parameters travel as `{'type':'config', …}` posted after load; the textual replacement is gone from `frida_run_script` and demoted to a documented fallback inside `frida_find_bytes`.

### F-PY-6. Dead weight in dependencies and checks — **[code]** — **Status: fixed**

- `quark-engine` is an optional extra **and** a check_tools entry, but no handler references it (grep: zero uses). Install cost ~200 MB for nothing. *(resolved by E-PY-3 `quark_scan`)*
- `capstone` and `keystone-engine` are checked in check_tools.py:211-212 but used by nothing. → **removed from the check list** (still installable via `install_tool` on demand)
- `fridump` is checked in check_tools.py:183 and installed by `--setup`, but `frida_memdump` deliberately does not use fridump (dynamic.py:450 comment: "does NOT require fridump"). → **removed from the check list and the install recipes**
- `_check_binary("medusa")` — see F-PY-2. → **disambiguated by running the binary and rejecting the foofus.net banner**

### F-PY-7. Assorted smaller items — **[code]** — **Status: fixed**

- `manifest_parse`'s `exported_services` filter is logically unrelated to services: `[s for s in apk.get_services() if apk.get_declared_permissions_dict()]` returns services whenever the APK declares **any** permission (static.py:246-248). → **fixed** by the XML-driven manifest rewrite (E-PY-2, commit `bec0bfc`).
- `mitm_export_har`'s helper script uses `datetime.utcnow()` (deprecated in 3.12+). → **fixed** (E-PY-9, commit `cc3e59e`).
- `frida_memdump` defaults its dump folder into `~/tools/dumps` — the tools-download dir doubles as output dir; `data_dir()/dumps` would be the right home. → **fixed** (E-PY-9).
- `adb_shell` runs `shlex.split(command)` then hands argv to `adb`, which rejoins them — device-side operators (`|`, `&&`) still work, but space-containing single arguments cannot be expressed; worth one line in docs. → **documented in the tool description** (E-PY-9).
- `install_all_missing_tools()` installs `medusa` from `core_tools` — coupled with F-PY-2, it would pip-install the cracker rather than the framework. → **fixed in-commit** during F-PY-2: `medusa` left the pip recipe path entirely (`_MANUAL_TOOLS` with instructions).

### F-PY-8. Things verified to work well — **[verified live]**

- `adb_devices`, `memory_read` (template + traversal-safe path), `apk_identify` (apkid 3.2.0 JSON), `find_urls` (20 URLs on TermuxBoot), `check_tools` inventory otherwise accurate.
- npm-side cross-check matched: `apk_manifest_analyzer` + `apk_permissions_checker` + `android_secrets_scanner` all returned consistent, clean output on the same APK.
- Pin hygiene in `install_tool.py` is solid: HTTPS-only fetch, SHA-256 verification, zip-slip rejection (all unit-tested, [test] tag from tests/test_handlers.py).

---

## Part 2 — npm server: findings (code-read; all paths under `src/`)

### F-NPM-1. Stale and non-hermetic smoke script — **Status: fixed**

`test-tools.mjs` is advertised by `package.json` (`npm run test:tools`) but: headers say "1/8 … 8/8" while 12 tools exist; it never calls `android_google_services`, `android_secrets_scanner`, `ios_google_services`, `ios_secrets_scanner`; and it requires `example.apk`/`example.ipa` in the repo root, which `.gitignore` excludes — it cannot run on a fresh clone. The real tests (`node --test "test/*.test.mjs"` in CI) cover only the manifest parser — 1 of 12 tools.

*Fix:* commit `90545cb`. The smoke runner now discovers the tool list from the server itself (14 today), calls every tool with a fixture recipe, skips the rest with a stated reason, and — without the fixture files — prints the full inventory plus the `npm test` pointer instead of failing. `npm test` (build + `node --test`) is now a first-class script, and the hermetic suite covers 14 tools with 25 test cases.

### F-NPM-2. Manifest analyzer ignores the `aapt2` fallback it already supports — **[code]** — **Status: fixed**

`apk_permissions_checker` tries `aapt` → `aapt2` → `apktool`; `apk_manifest_analyzer` tries `aapt` → apktool only, even though `parseManifest()` handles the aapt2 tree format and the repo ships the `test/fixtures/aapt2-xmltree.txt` proving it. On aapt2-only machines the manifest tool always pays the apktool cost.

*Fix:* `apk_manifest_analyzer` now walks the same `aapt` → `aapt2` → `apktool` chain (`aapt2 dump xmltree --file AndroidManifest.xml <apk>`), keeping the `Source:` label so the report still names which tool produced it. Verified live with a broken-`aapt` shim first on PATH: report comes out `Source: aapt2` with the full component analysis; with both healthy, `Source: aapt` (unchanged). The existing fixture tests already cover aapt2 tree parsing on both formats.

### F-NPM-3. Triple-duplicated iOS binary-extraction logic — **[code]** — **Status: fixed**

`extractBinary` is copy-pasted three times with **drifting resource-exclusion lists** (entitlements-checker.ts vs binary-strings.ts vs secrets-scanner.ts — one ignores `lproj`/`storyboard`, another `json`/`dylib`), so the same IPA can yield different binaries to different tools. `merge()` is likewise duplicated in both secret scanners, and unchanged-file dedup uses `includes()` (O(n²)). One shared helper fixes all three.

*Fix:* `src/tools/ios/extract-binary.ts` is the single implementation — `resolveBinaryEntry` (Info.plist `CFBundleExecutable`, else the one extension-less root file of the `.app`, against the **union** of the three drifted exclusion lists), `writeBinary` (used by binary-strings + entitlements-checker; the pointless `chmodSync(0o755)` disappears with it) and `readBinary` (secrets-scanner). `merge()` became `mergeScanResults` in `shared/patterns.ts`, used by both secret scanners, with Set-based dedup instead of `includes()`. Tests: `test/ios-extract.test.mjs` (6 cases: named binary, fallback, union-list exclusions, null case, write/read round-trip, merge dedup).

### F-NPM-4. No decompression-size limits (zip-bomb surface) — **[code]** — **Status: fixed**

`entry.getData()` (adm-zip) fully decompresses before any size check — for DEX, plists, assets, framework binaries. maxBuffer only caps `strings` output. A crafted, small, highly-compressed IPA can OOM the process. There is also no cap on the input APK/IPA file size itself.

*Fix:* `src/tools/shared/zip.ts` is the single zip gateway: `openZip` (checks the input against `MOBILE_RE_MCP_MAX_FILE_MB`, default 2048, then opens with a normalized error — also fixing the one unprotected `new AdmZip` in frameworks-detector), `readEntry` (checks `header.compressedSize`/`header.size` against `MOBILE_RE_MCP_MAX_ENTRY_MB`, default 256, *before* decompressing), `requireEntryData` for single-entry callers, and a `[skipped: …]` placeholder for scan loops. `0` disables a cap. Every APK/IPA consumer is wired through it. Verified live: a 2 KB APK whose `assets/big.json` decompresses to 2 MB is reported as `[skipped: entry 'assets/big.json' declares 2.0 MB uncompressed, above the 1 MB cap …]` with the rest of the scan intact; a 2 MB input with `MOBILE_RE_MCP_MAX_FILE_MB=1` fails with `input file is 2.0 MB, above the 1 MB cap`. Tests: `test/zip-limits.test.mjs` (6 cases).

### F-NPM-5. Other smaller items — **Status: partially fixed** (each bullet below)

- `ios_frameworks_detector` has an unprotected `new AdmZip(...)` (frameworks-detector.ts:132) — the only zip access not wrapped in try/catch, so a valid-magic/corrupt IPA throws past the repo's error normalization. Also `DexGuard` (an Android obfuscator) sits in the iOS `KNOWN_FRAMEWORKS` table, and matching uses loose `startsWith || includes`, so names like "Segment", "Branch" or "Realm" inside unrelated frameworks can mislabel. **[code]** → *both fixed:* the unprotected open is wrapped by the zip gateway (F-NPM-4, commit `daa3e4b`); DexGuard is removed and the matcher is prefix-or-exact only (commit `90545cb`).
- `min_length` default is 6 for `ios_binary_strings` but 8 for both secret scanners — same operation family, different defaults. **[code]** → *fixed* (commit `90545cb`: 8 everywhere).
- `ios_google_services` skips binary plists during pattern rescan (`bplist` → continue) while `ios_secrets_scanner` decodes those same plists through `plutil` — inconsistent findings between two tools over the same files. **[code]** → *deferred (reason:* behavioral change needing binary-plist fixtures to prove; the tools' reports are independently labeled, so no finding is *hidden* — follow-up candidate*).*
- `android_api_extractor` claims OkHttp endpoint extraction but collects only `Lokhttp3/` *field declarations*; no URLs come from it — only Retrofit annotations produce endpoints (api-extractor.ts:80-93). **[code]** → *deferred to E-NPM-5 (reason:* not in the approved extension order for this round; the const-string harvest proposal stands — README wording already narrows the claim*).*
- Dead code: `p.startsWith("{") ? p : p` (api-extractor.ts:168-169); pointless `chmodSync(0o755)` on the extracted iOS binary (entitlements-checker.ts:127); string-sentinel control flow `Record|null|"simulator"` (entitlements-checker). → *dead ternary and chmod fixed* (commits `90545cb` / `0925a77`); *sentinel wontfix (reason:* internal three-state used by exactly one caller — reshaping it is churn without a behavior change*).*
- Android `DANGEROUS_PERMISSIONS` includes `ACCESS_WIFI_STATE` / `CHANGE_WIFI_STATE`, which are install-time "normal" permissions, plus signature-type `INSTALL_PACKAGES` — defensible as a triage list, but mislabeled against Google's taxonomy. **[code]** → *fixed in-commit* (`cc3e59e`: the set keeps triage semantics under a renamed "Sensitive Permissions" header with the taxonomy note in the source).
- `/[0-9a-zA-Z]{40}/g` in `ios_binary_strings` labels every 40-char alnum run a key — noisy on real apps. **[code]** → *deferred (reason:* tightening risks *missing* real 40-char keys; noise is labeled LOW risk and capped — safer to leave*).*
- Windows `apktool.bat` support is prose-only; `execFileSync("apktool", …)` fails with ENOENT and offers no hint at runtime. **[code]** → *fixed* (commit `90545cb`: `run()` converts bare ENOENT into "not found on PATH" with the Windows .exe-vs-.bat note).

### F-NPM-6. Verified working end-to-end — **[verified live]**

Manifest analyzer, permissions checker and secrets scanner all produced clean, correct output on a real 3-DEX APK through the live MCP server. Output conventions (`=== Header ===`, `⚠`, `✓`, severity tags) are uniform across all 12 tools.

---

## Part 3 — Extension proposals, with the current function stated first

Each item lists: **what the code does today** → **what we propose to add/change** → expected effort (S <1 day, M 1–3 days, L multi-day).

### Python (PyPI) — extensions

**E-PY-1. Ship the built-in Frida script library (the fix for F-PY-3) — *Current: shipped*** — **Status: fixed**
- *Was:* catalogue of 8 named scripts, zero `.js` files shipped; `frida_list_scripts` returns 0; `frida_find_bytes` is dead in a fresh install.
- *Done:* all 8 `.js` files live in `frida_scripts/` matching their catalogue descriptions — `ssl_pinning_universal`, `root_detection_bypass` (Java+native), `frida_detection_bypass` (`Socket.connect` port-scan defeat, native `strstr`/`ptrace`), `crypto_monitor` (Cipher opmode stashed at `init`), `memory_scan` (exact `var SEARCH_STRING/SEARCH_HEX/MAX_RESULTS` lines `frida_find_bytes` patch), `method_tracer`, `storage_monitor`, `network_monitor`. Every script registers a re-armed `recv('config', …)` handler (UPPER-case primary keys, lowercase accepted) — the forward-compatible half of the E-PY-6 protocol. Catalogue `usage` strings document the config keys. Tests: library completeness, user-override precedence, per-script config handler presence, and the `memory_scan` var/message contract; `node --check` = 8/8. Live: `frida_list_scripts` returns 8; `frida_get_script('memory_scan')` returns the real source with the contract lines.

**E-PY-2. androguard 4.x compatibility pass (the fix for F-PY-1) — *Current: landed*** — **Status: fixed (commit `bec0bfc`)**
- *Current:* `manifest_parse`, `analyze_code`, `find_crypto_usage` fail or mis-behave under the androguard that `[static]` installs today.
- *Done:* `manifest_parse` is XML-driven with explicit/auto/auto-pre-17 `exported_mode` markers (which also fixed the unrelated services filter, F-PY-7); the xref helpers tolerate 3.x 2-tuples, 4.x 3-tuples and method objects (`_xref_names`); `apk_analyze_full` reports per-stage statuses and degrades honestly; `androguard>=4.0,<5` is pinned in `[static]` and `[dev]`; `tests/test_androguard_tools.py` runs the whole expectation set against `tests/fixtures/notesdemo.apk` plus shape-fakes so this drift cannot ship silently again.
- *Effort:* M.
- *Verify with:* the live smoke tests already used here (same APK expectation set).

**E-PY-3. New tool: `quark_scan` (uses the dependency that is already being asked for) — *Current: landed*** — **Status: done**
- *Was:* quark-engine is an optional extra and a `check_tools` entry, with **no** tool wired to it; nothing in the toolchain ranks malicious-looking behaviours.
- *Done:* `quark_scan(apk_path, keywords?, min_score?, max_results?, rules_dir?)` in `handlers/static.py` runs quark's rule engine over an APK and returns scored behaviour matches — each with `crime`, quark's five-stage `level` (only level ≥ 4 produce behaviours), base `score`, requested `permission`, and the `caller`/`first_api`/`second_api` triple. The rule set is **not bundled** (quark-rules is a separate repo): the tool reads freshquark's `~/.quark-engine/quark-rules/rules` (or an explicit `rules_dir`) and returns a `missing_tool` with a "run freshquark" hint when there is none, so no network call happens behind the server's back. `apk_analyze_full` gained a fourth best-effort `quark` stage: `missing_tool` stages are recorded in `tool_statuses` but excluded from both the error map and the health count (an optional extra can't make the pipeline "degraded" for environments that didn't install it), while a real stage `error` still does. quark-as-a-module is checked by the existing `_check_python_module` entry, whose `used_by` is now `["quark_scan", "apk_analyze_full"]`. Tests: `tests/test_quark_scan.py` (engine-absent honesty, discovery, handcrafted-rule pipeline, rules-absent hint, stage wiring; `importorskip("quark")` guards the engine-dependent ones). Live: 281 rules evaluated over TermuxBoot in ~5 s → 7 level-5/5 matches including "Monitor device boot completion" in `com.termux.boot.BootReceiver.onReceive`; `apk_analyze_full` reports all four stages `ok`.

**E-PY-4. Make handlers non-blocking (the fix for F-PY-4) — *Current: landed*** — **Status: fixed**
- *Was:* every handler ran synchronously inside the asyncio `call_tool`; a 5-minute jadx run froze the server.
- *Done:* `call_tool` is now a thin wrapper over module-level `async def _run_tool(name, args, dispatch, serial_pools)` (server.py): guard refusals → `isError` results, async handlers awaited, sync handlers run on worker threads. Stateless classes go through `asyncio.to_thread` (concurrent calls overlap); the three stateful classes that own process/session state — `DynamicHandler` (Frida session/queue), `NetworkHandler` (mitm proc), `DeviceHandler` (logcat reader) — flag themselves with `_SERIALIZE` and execute on a dedicated max_workers=1 pool, preserving the previous serial ordering for their shared state. Tests: `tests/test_concurrency.py` proves a slow sync handler no longer stalls the loop and that two calls to a stateful class queue instead of overlapping. Live: server boots, `list_tools` + static + setup dispatch all healthy through the shared tree.

**E-PY-5. Honesty pass on `check_tools` (the fix for F-PY-2) — *Current: landed*** — **Status: fixed (commit `eb76d83`)**
- *Current:* inventory checks Python modules where the tools need CLIs, and collides with an unrelated binary named `medusa`.
- *Done:* every entry records how the tool is actually invoked and checks exactly that (pip CLIs probed as executables via the shared `find_cli`; `quark` as a module wired to `quark_scan`; capstone/keystone and fridump removed from the checks; medusa rejects the foofus.net cracker banner with a hint to the framework repo); every entry carries a `used_by` list of MCP tool names so the assistant can reason about "what breaks if this is missing". Fidelity guarded by `tests/test_check_tools_honesty.py`.
- *Effort:* S.

**E-PY-6. Config protocol for Frida scripts (the fix for F-PY-5) — *Current: landed*** — **Status: done**
- *Was:* `frida_run_script` and `frida_find_bytes` patch values into JS source with `str.replace` on magic lines.
- *Done:* `_load_script(src, config=None)` posts `{'type':'config', …}` right after `script.load()`; `frida_spawn`/`frida_attach`/`frida_inject`/`frida_run_script`/`frida_spawn_hluda` all accept a `config` object and the source is no longer rewritten (quote-bearing values can't break it, and the scripts' `var X = ""` lines stay intact as the documented fallback contract). `frida_find_bytes` is config-protocol-first — load `memory_scan` unpatched, post the search, wait for `scan_complete` — and falls back to the var-line replace only when `script.post` is unavailable (the response carries `via: "config-protocol"` so the active path is visible). Tests: `tests/test_frida_config_protocol.py` (fake session/script: run-script posts instead of patching, find-bytes config-first, post-less runtime falls back to patched source, session guard, drain). Live: on device `f982678d`, `frida_attach('sleep')` + `frida_find_bytes(search_string='sleep')` → 3 rw- matches with `via: "config-protocol"`; `node --check` 8/8 unchanged.
- *Found on the way (D-5):* the shipped `memory_scan.js` itself referenced the pre-frida-17 bare `process` global — every runtime scan died with `ReferenceError` before this fix; also fixed in-commit.

**E-PY-7. New tool: `frida_status` — *Current: landed*** — **Status: done**
- *Was:* nothing introspects the handler's session state; the only way to know "am I attached?" is to run something that errors.
- *Done:* `frida_status()` — a no-op read returning frida's version, every connected device (id/name/type), the USB device, whether frida-server answers (a single `get_frontmost_application()` RPC, with `frontmost_application` when one is up), and the handler's own session state (`attached_package`, `alive`, `script_loaded`, `queued_messages`). Every section is best-effort: a dead server or an old session object degrades that field, not the whole call. Tests: `tests/test_frida_status.py` (6 hermetic cases with a fake frida module: missing engine, detached state, live session, dead server, session without `is_detached`, no-USB short-circuit). Live: device `f982678d` → devices list with the USB entry, `frida_server_responsive: true`.

**E-PY-8. New tool: `adb_ui_dump` — *Current: landed*** — **Status: done**
- *Was:* the server can screenshot the UI (`scrcpy_screenshot`), but the assistant has no structured view of it — driving test flows ("tap login") is guesswork from pixels.
- *Done:* `adb_ui_dump(serial?)` in `handlers/device.py` — `adb exec-out uiautomator dump /dev/tty` with an automatic fallback to the two-step dump-then-cat, parsed with ElementTree into a flat element list (class, text, content-desc, resource-id, bounds, clickable/scrollable/checked/enabled — plain containers filtered out) plus a human-readable report capped at 80 lines. Malformed XML and devices that produce no dump are honest errors. Tests: `tests/test_adb_ui_dump.py` (5 cases with a fake adb on PATH: element parsing, two-step fallback, total failure, malformed XML, missing adb). Live: device `f982678d` → the tool faithfully reported the window actually on top (an overlay dialog app), including its clickable bounds and texts.

**E-PY-9. Housekeeping — *Current: landed*** — **Status: done (commit `cc3e59e`)**
- *Done:* `frida_memdump`'s default output is `data_dir()/dumps/<package>`; the HAR helper uses timezone-aware `datetime.now(timezone.utc)`; `adb_shell`'s description documents the host-side split/rejoin and the `sh -c` pattern for device-side operators.

**Deliberately *not* proposed (with reasons)**
- **iOS support in the Python server** — the npm server already covers iOS static analysis; dynamic iOS work means signing/gadget/bundler pipelines that are a project of their own. Keep the boundary as-is until there's demand.
- **Enabling `install_tool` by default** — the current guard-off default is correct for a server that can mutate the environment; `--setup` remains the self-service path.

### npm — extensions

**E-NPM-1. Ship the missing decompressed-size caps (the fix for F-NPM-4) — *Current: landed*** — **Status: fixed (commit `daa3e4b`)**
- *Current:* any zip entry is decompressed in full into memory before inspection; no input-size cap.
- *Done:* `src/tools/shared/zip.ts` — `openZip` (input cap `MOBILE_RE_MCP_MAX_FILE_MB`, default 2048) and `readEntry` (entry cap `MOBILE_RE_MCP_MAX_ENTRY_MB`, default 256, checked against the local header *before* decompression), `0` disables a cap, over-cap entries surface as `[skipped: …]` placeholders. All eight consumers wired through.
- *Effort:* S (rides on E-NPM-2's refactor).

**E-NPM-2. Unify iOS binary extraction + add aapt2 fallback (the fixes for F-NPM-3 and F-NPM-2) — *Current: landed*** — **Status: fixed (commits `0925a77`, `e7c337f`)**
- *Current:* three drifting copies of `extractBinary`; manifest analyzer skips `aapt2` even though its parser supports the format.
- *Done:* (a) one `src/tools/ios/extract-binary.ts` used by all three iOS tools, with a single union exclusion list and no chmod; (b) `apk_manifest_analyzer` walks `aapt` → `aapt2 dump xmltree` → `apktool` via the shared `extractAndroidManifest`, and `apk_diff` reuses it.
- *Effort:* S.

**E-NPM-3. New tool: `android_native_libraries` (the npm-side complement to PyPI's `rasp_identify`) — *Current: landed*** — **Status: done (commit `eb422b5`)**
- *Current:* nothing in either server fingerprints native Android SDKs statically; npm enumerates only iOS frameworks; RASP detection on Android requires the Python device flow.
- *Done:* enumerates every `lib/<abi>/*.so`, matches a ~30-entry `KNOWN_ANDROID_LIBS` table (packers/RASP/frameworks/SDKs/runtimes) and inspects ELF headers — class, machine, e_type, and the section-header table, where absence is itself a protection signal. Verified live on TiviMate (libdexprotector per ABI, correct ELF classes).
- *Effort:* M.

**E-NPM-4. New tool: `apk_diff` — *Current: landed*** — **Status: done (commit `11096c5`)**
- *Current:* every tool answers for one file at a time; "what changed between app 2.3.1 and 2.4.0?" has no first-class answer.
- *Done:* `apk_diff(old_path, new_path, skip_secrets?)` — identity/SDK levels, security flags, permission and exported-component deltas, native-library deltas by sha256, optional per-pattern secret deltas, archive inventory. Verified live against a rebuilt notesdemo variant.
- *Effort:* M.

**E-NPM-5. Complete `android_api_extractor`'s endpoint story (the fix for F-NPM-5-OkHttp)** — **Status: deferred (reason: not in the approved extension order for this round; the const-string harvest proposal stands as a follow-up, and the README wording already narrows the claim)**
- *Current:* Retrofit annotations produce endpoints; the tool also claims OkHttp extraction but only collects field declarations, so the README example question ("What API endpoints does this APK call?") is answered partially.
- *Proposal:* add a `const-string` harvest pass over the same smali folder the tool already walks (regex `https?://` in string constants, deduped, host-grouped) — no new dependencies, and it captures every base URL missed by missing Retrofit annotations. Optionally rename the field-reporting to "OkHttp client fields (detected)" so the description stops overclaiming.
- *Effort:* S.

**E-NPM-6. Test and packaging investments — *Current: mostly landed*** — **Status: partially done**
- *Done (commit `90545cb` and the fixture-based suites):* `"test": "npm run build && node --test test/*.test.mjs"` is a first-class script; the smoke runner is honest about fixtures (F-NPM-1); hermetic unit tests cover the manifest parser (both aapt formats), zip caps, iOS extraction, native libraries, and apk_diff — 25 cases across 14 tools.
- *Deferred (reason: pattern-table and safe-exec unit tests are partially redundant with the live fixture smokes; schedule them when the pattern tables next change):* dedicated `patterns.ts` (`scanText`/`renderResults`) and `MOBILE_RE_MCP_ALLOWED_DIRS` unit tests.
- *Effort:* M.

**E-NPM-7. Small consistency fixes — *Current: landed*** — **Status: done (commit `90545cb`, plus `cc3e59e` for the permissions header)**
- *Done:* one `min_length` default (8); DexGuard out of the iOS table and prefix-or-exact matching; dead ternary removed; the chmod was already gone via F-NPM-3; Windows ENOENT hint at runtime; `DANGEROUS_PERMISSIONS` relabelled a triage list under a "Sensitive Permissions" header.
- *Deferred (with reasons):* `ios_google_services` bplist rescan consistency (needs binary-plist fixtures) and the `ios_binary_strings` 40-char key regex noise (tightening risks missing real keys) — tracked under F-NPM-5.

---

## Discovered during rebuild

New findings made while fixing Part 1/2 items. They are logged here instead of fixed inline, unless they blocked the current item.

| # | Finding | Where | Severity |
| --- | --- | --- | --- |
| D-1 | The only deployment path the servers run from is a virtualenv whose `bin/` is not on PATH: pip console scripts (`apkleaks`, and after pinning also `apkid`) resolve only via the interpreter-sibling fallback now shared by both `check_tools` and the handlers. Every future handler spawning a pip CLI must use `mobile_re_mcp.clitools.find_cli`, never bare `shutil.which`. | `clitools.py` | info (pattern to follow) |
| D-2 | Check entries `binwalk`, `apk-mitm`, `frida-compile`, `frida-ps` are probed but no handler invokes them; they now carry `used_by: []` and are candidates for removal in a later cleanup. | `setup/check_tools.py` | low |
| D-3 | `scripts/android-api-extractor/analyze_apk.py` (legacy helper) contains dead code paths that are unsafe if ever invoked (un-validated argv use); it is not reachable from either scaffold. Kept out of scope; candidate for deletion. | `scripts/` | low |
| D-4 | `find_cli` initially used `Path(sys.executable).resolve()`, which follows a venv interpreter's symlink to the *base* interpreter — invisible to the venv's console scripts. Fixed in-commit with `absolute()` before shipping; noted here because the trap is easy to re-introduce. | `clitools.py` | fixed in-commit |
| D-5 | Shipped `memory_scan.js` called the bare `process` global (`process.enumerateRanges`), which frida 17 (QuickJS) no longer defines — every scan died with `ReferenceError: 'process' is not defined` at runtime, invisible to `node --check`. Fixed in-commit to the capital-P Frida API; guarded by `test_shipped_scripts_use_only_frida_17_globals` scanning all 8 scripts for the pre-QuickJS names. | `frida_scripts/` | fixed in-commit |
| D-6 | `frida_attach(package)` resolves through frida's process-name lookup, which matches the app *label* ("Termux:API"), not the package identifier ("com.termux.api") — attach by package id fails on real devices even when the process runs. Not yet fixed; a follow-up should map identifier → pid via `enumerate_applications()` before falling back. | `handlers/dynamic.py` | open (low) |



---

## Part 4 — Suggested order

| # | Change | Server | Fix? | Ext? | Effort |
| --- | --- | --- | --- | --- | --- |
| 1 | E-PY-2 androguard 4.x pass | PyPI | ✔ | | M |
| 2 | E-PY-1 ship Frida scripts | PyPI | ✔ | | M |
| 3 | E-PY-4 non-blocking handlers | PyPI | ✔ | | S |
| 4 | E-NPM-1/2 size caps + shared extract + aapt2 | npm | ✔ | part | S |
| 5 | E-PY-3 `quark_scan` | PyPI | | ✔ | S–M |
| 6 | E-PY-5 `check_tools` honesty pass | PyPI | ✔ | | S |
| 7 | E-NPM-3 `android_native_libraries` | npm | | ✔ | M |
| 8 | E-NPM-4 `apk_diff` | npm | | ✔ | M |
| 9 | E-PY-6/7/8 config protocol, `frida_status`, `adb_ui_dump` | PyPI | ✔/✔ | ✔ | S each |
| 10 | E-NPM-6/7 tests + consistency | npm | ✔ | | M |

Rationale: items 1–4 are fixes identified with live evidence or clear blast radius, and they come before feature work so extensions land on a working base. `quark_scan` (5) is the smallest high-value *new* capability on the PyPI side. The npm tool additions (7, 8) are chosen to complement — not duplicate — the Python server: static, zero-device dependency, unique answers ("what's inside", "what changed").

## Part 5 — How to verify an extension (reproduce this review's harness)

1. **Live:** both servers reachable over MCP; `adb_devices` shows a device; `check_tools` establishes the environment baseline (here: 34/35).
2. **APK under test:** a small real APK (used here: TermuxBoot 0.8.1) gives fast, deterministic static results.
3. **Regression rule of thumb:** every "fix" listed above should include a one-message live call pair (before/after) identical to those captured in this document before the corresponding CHANGELOG entry is written.
