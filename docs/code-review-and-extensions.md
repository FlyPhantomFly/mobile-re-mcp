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

### F-PY-1. androguard API drift breaks three tools on the pinned extra — **[verified live]**

`[analysis]`-adjacent extra `[static]` declares `androguard>=3.4.0a1` (pyproject.toml:28), so today's installs get **4.1.4** (verified live: `check_tools` reports `androguard 4.1.4`). In androguard 4.x the APK class no longer has `get_activity_is_exported()`, and `Analysis` cross-reference accessors return different shapes. Results measured live on `com.termux.boot`:

| Tool | Live result |
| --- | --- |
| `manifest_parse` | `error: 'APK' object has no attribute 'get_activity_is_exported'` |
| `analyze_code` | `error: 'tuple' object has no attribute 'class_name'` — `handlers/static.py:350-357` assumes `get_xref_from()` yields method objects, 4.x yields tuples |
| `find_crypto_usage` | returned `ok` with 0 usages on a crypto-free app — cannot pass unit coverage; same suspect accessors (`for _, callee, _ in method.get_xref_to()`, static.py:437) mean it will mis-shape or drop results on any app with crypto calls |
| `find_urls` | worked (returned 20 URLs) — keep its approach |
| `apk_analyze_full` | silently reports the broken `manifest_parse` output inside its `manifest` field while still returning `status: ok` — masking failure is worse than failing |

Where it lives: `handlers/static.py:229-257` (`manifest_parse`), `:315-383` (`analyze_code`), `:423-463` (`find_crypto_usage`), `:185-219` (`apk_analyze_full`).

### F-PY-2. `check_tools` reports availability the handlers can't use — **[verified live]**

- `check_tools` checks apkleaks as a *Python module* (importable → `available: true`, check_tools.py:172), but `apk_scan_secrets` needs the **CLI on PATH** (`shutil.which("apkleaks")`, static.py:153). Live: `check_tools` said apkleaks ✓; `apk_scan_secrets` returned `missing_tool 'apkleaks' not found on PATH.` The inventory lies to the assistant exactly when it matters (it recommends "run check_tools first" in docs).
- `check_tools` reports `medusa` **available** — live output was `Medusa v2.3 [http://www.foofus.net]` — that is the SSH/password **login cracker**, not the Frida script framework this tool chain expects. Name collision, false positive (check_tools.py:238).

### F-PY-3. The built-in Frida script library is a façade — **[verified live]**

`frida_scripts/index.py` catalogues 8 scripts (`ssl_pinning_universal`, `root_detection_bypass`, `frida_detection_bypass`, `crypto_monitor`, `memory_scan`, `method_tracer`, `storage_monitor`, `network_monitor`) but the package ships **zero `.js` files** (`frida_scripts/` contains only `index.py`, `__init__.py`). `frida_list_scripts` correctly applies the 1.2.0 fix that only lists files that exist, so live result: `total: 0, available_categories: []`.

Consequences beyond the library itself: `frida_find_bytes` **depends on the missing `memory_scan.js`** (dynamic.py:547-549 returns an error if absent), and the docs' "frida_get_script → frida_run_script" workflow is unusable out of the box. The CHANGELOG 1.2.0 entry ("It now lists only scripts that exist") papered over the symptom instead of shipping the files.

### F-PY-4. Sync handlers block the asyncio event loop — **[code]**

`server.py`'s `call_tool` invokes every handler directly; all handlers are synchronous (`subprocess.run` with 120–600 s timeouts, `time.sleep(1)` in `mitm_start`). Inside asyncio, this freezes the whole server for the duration of e.g. a jadx decompile. — no other tool call is processed, even in SSE mode with a second client.

### F-PY-5. Config values for Frida scripts are injected by textual `var X = "";` replacement — **[code]**

`frida_run_script` (dynamic.py:265-270) and `frida_find_bytes` (dynamic.py:553-563) patch values into JS via `str.replace`. Any apostrophe or quote in a user-provided search string breaks (or re-flows) the injected script, and the pattern depends on the script author remembering an exact `var SEARCH_STRING = "";` line. A message-passing config protocol (below) removes both hazards.

### F-PY-6. Dead weight in dependencies and checks — **[code]**

- `quark-engine` is an optional extra **and** a check_tools entry, but no handler references it (grep: zero uses). Install cost ~200 MB for nothing.
- `capstone` and `keystone-engine` are checked in check_tools.py:211-212 but used by nothing.
- `fridump` is checked in check_tools.py:183 and installed by `--setup`, but `frida_memdump` deliberately does not use fridump (dynamic.py:450 comment: "does NOT require fridump").
- `_check_binary("medusa")` — see F-PY-2.

### F-PY-7. Assorted smaller items — **[code]**

- `manifest_parse`'s `exported_services` filter is logically unrelated to services: `[s for s in apk.get_services() if apk.get_declared_permissions_dict()]` returns services whenever the APK declares **any** permission (static.py:246-248).
- `mitm_export_har`'s helper script uses `datetime.utcnow()` (deprecated in 3.12+).
- `frida_memdump` defaults its dump folder into `~/tools/dumps` — the tools-download dir doubles as output dir; `data_dir()/dumps` would be the right home.
- `adb_shell` runs `shlex.split(command)` then hands argv to `adb`, which rejoins them — device-side operators (`|`, `&&`) still work, but space-containing single arguments cannot be expressed; worth one line in docs.
- `install_all_missing_tools()` installs `medusa` from `core_tools` — coupled with F-PY-2, it would pip-install the cracker rather than the framework.

### F-PY-8. Things verified to work well — **[verified live]**

- `adb_devices`, `memory_read` (template + traversal-safe path), `apk_identify` (apkid 3.2.0 JSON), `find_urls` (20 URLs on TermuxBoot), `check_tools` inventory otherwise accurate.
- npm-side cross-check matched: `apk_manifest_analyzer` + `apk_permissions_checker` + `android_secrets_scanner` all returned consistent, clean output on the same APK.
- Pin hygiene in `install_tool.py` is solid: HTTPS-only fetch, SHA-256 verification, zip-slip rejection (all unit-tested, [test] tag from tests/test_handlers.py).

---

## Part 2 — npm server: findings (code-read; all paths under `src/`)

### F-NPM-1. Stale and non-hermetic smoke script

`test-tools.mjs` is advertised by `package.json` (`npm run test:tools`) but: headers say "1/8 … 8/8" while 12 tools exist; it never calls `android_google_services`, `android_secrets_scanner`, `ios_google_services`, `ios_secrets_scanner`; and it requires `example.apk`/`example.ipa` in the repo root, which `.gitignore` excludes — it cannot run on a fresh clone. The real tests (`node --test "test/*.test.mjs"` in CI) cover only the manifest parser — 1 of 12 tools.

### F-NPM-2. Manifest analyzer ignores the `aapt2` fallback it already supports

`apk_permissions_checker` tries `aapt` → `aapt2` → `apktool`; `apk_manifest_analyzer` tries `aapt` → apktool only, even though `parseManifest()` handles the aapt2 tree format and the repo ships the `test/fixtures/aapt2-xmltree.txt` proving it. On aapt2-only machines the manifest tool always pays the apktool cost.

### F-NPM-3. Triple-duplicated iOS binary-extraction logic

`extractBinary` is copy-pasted three times with **drifting resource-exclusion lists** (entitlements-checker.ts vs binary-strings.ts vs secrets-scanner.ts — one ignores `lproj`/`storyboard`, another `json`/`dylib`), so the same IPA can yield different binaries to different tools. `merge()` is likewise duplicated in both secret scanners, and unchanged-file dedup uses `includes()` (O(n²)). One shared helper fixes all three.

### F-NPM-4. No decompression-size limits (zip-bomb surface)

`entry.getData()` (adm-zip) fully decompresses before any size check — for DEX, plists, assets, framework binaries. maxBuffer only caps `strings` output. A crafted, small, highly-compressed IPA can OOM the process. There is also no cap on the input APK/IPA file size itself. Mitigation is cheap: check `entry.header.compressedSize/uncompressedSize` before reading and skip/abort above a cap.

### F-NPM-5. Other smaller items

- `ios_frameworks_detector` has an unprotected `new AdmZip(...)` (frameworks-detector.ts:132) — the only zip access not wrapped in try/catch, so a valid-magic/corrupt IPA throws past the repo's error normalization. Also `DexGuard` (an Android obfuscator) sits in the iOS `KNOWN_FRAMEWORKS` table, and matching uses loose `startsWith || includes`, so names like "Segment", "Branch" or "Realm" inside unrelated frameworks can mislabel. **[code]**
- `min_length` default is 6 for `ios_binary_strings` but 8 for both secret scanners — same operation family, different defaults. **[code]**
- `ios_google_services` skips binary plists during pattern rescan (`bplist` → continue) while `ios_secrets_scanner` decodes those same plists through `plutil` — inconsistent findings between two tools over the same files. **[code]**
- `android_api_extractor` claims OkHttp endpoint extraction but collects only `Lokhttp3/` *field declarations*; no URLs come from it — only Retrofit annotations produce endpoints (api-extractor.ts:80-93). **[code]**
- Dead code: `p.startsWith("{") ? p : p` (api-extractor.ts:168-169); pointless `chmodSync(0o755)` on the extracted iOS binary (entitlements-checker.ts:127); string-sentinel control flow `Record|null|"simulator"` (entitlements-checker).
- Android `DANGEROUS_PERMISSIONS` includes `ACCESS_WIFI_STATE` / `CHANGE_WIFI_STATE`, which are install-time "normal" permissions, plus signature-type `INSTALL_PACKAGES` — defensible as a triage list, but mislabeled against Google's taxonomy. **[code]**
- `/[0-9a-zA-Z]{40}/g` in `ios_binary_strings` labels every 40-char alnum run a key — noisy on real apps. **[code]**
- Windows `apktool.bat` support is prose-only; `execFileSync("apktool", …)` fails with ENOENT and offers no hint at runtime. **[code]**

### F-NPM-6. Verified working end-to-end — **[verified live]**

Manifest analyzer, permissions checker and secrets scanner all produced clean, correct output on a real 3-DEX APK through the live MCP server. Output conventions (`=== Header ===`, `⚠`, `✓`, severity tags) are uniform across all 12 tools.

---

## Part 3 — Extension proposals, with the current function stated first

Each item lists: **what the code does today** → **what we propose to add/change** → expected effort (S <1 day, M 1–3 days, L multi-day).

### Python (PyPI) — extensions

**E-PY-1. Ship the built-in Frida script library (the fix for F-PY-3)**
- *Current:* catalogue of 8 named scripts, zero `.js` files shipped; `frida_list_scripts` returns 0; `frida_find_bytes` is dead in a fresh install.
- *Proposal:* add the 8 `.js` files to `frida_scripts/` (the shipped scripts must match their catalogue descriptions; `memory_scan.js` is the critical one since two tools depend on it), plus a test asserting every catalogue entry resolves to a file on disk. Keep user overrides in `~/.local/share/mobile-re-mcp/frida_scripts` as the primary search path.
- *Effort:* M (writing/curating 8 scripts well).
- *Need shipped first:* none — this unblocks `frida_run_script`, `frida_find_bytes` and the "first session" story in the README.

**E-PY-2. androguard 4.x compatibility pass (the fix for F-PY-1)**
- *Current:* `manifest_parse`, `analyze_code`, `find_crypto_usage` fail or mis-behave under the androguard that `[static]` installs today.
- *Proposal:* port the three tools to the 4.1.x API — derive exported activities/services from the parsed manifest element API instead of `get_activity_is_exported` (this also fixes the unrelated services filter, F-PY-7); consume `get_xref_from()`/`get_xref_to()` tuples correctly in both call-graph tools; while there, make `apk_analyze_full` fail loudly (status reflects child failures) instead of masking. Pin `androguard` to a known-good range after the port and add one integration test using a fixture APK so this class of drift cannot ship again.
- *Effort:* M.
- *Verify with:* the live smoke tests already used here (same APK expectation set).

**E-PY-3. New tool: `quark_scan` (uses the dependency that is already being asked for)**
- *Current:* quark-engine is an optional extra and a `check_tools` entry, with **no** tool wired to it; nothing in the toolchain ranks malicious-looking behaviours.
- *Proposal:* `quark_scan(apk_path, severity_min?, max_results?)` — run quark's rule engine over an APK and return scored behaviour matches (e.g. "load dex from external source", "send SMS"). This turns `apk_analyze_full` into a genuine triage pipeline: apkid (packer) + apkleaks (leaks) + manifest (exposure) + quark (behaviour).
- *Effort:* S–M (quark has a stable Python API; handler pattern already exists in `static.py`).

**E-PY-4. Make handlers non-blocking (the fix for F-PY-4)**
- *Current:* every handler runs synchronously inside the asyncio `call_tool`; a 5-minute jadx run freezes the server.
- *Proposal:* in `server.py` wrap the dispatch in `await asyncio.to_thread(handler, args)` for sync handlers (keep stateful handlers on one worker via a small `ThreadPoolExecutor(max_workers=1)` owned by the handler classes, which preserves current serial semantics while freeing the loop); replace `time.sleep(1)` in `mitm_start` with an awaited sleep. No behavioural change for single-user flows; unblocks SSE multi-client and responsiveness.
- *Effort:* S.

**E-PY-5. Honesty pass on `check_tools` (the fix for F-PY-2)**
- *Current:* inventory checks Python modules where the tools need CLIs, and collides with an unrelated binary named `medusa`.
- *Proposal:* for each entry record *how the tool is invoked* (CLI vs module vs jar) and check exactly that (apkleaks via `shutil.which`; quark via `shutil.which("quark")` once E-PY-3 lands; remove capstone/keystone checks until a tool uses them; drop `fridump` or actually use it; check medusa-framework via `pip show medusa-framework` + its console script, not `medusa`); add a per-entry `used_by` list of MCP tool names so the assistant can reason about "what breaks if this is missing".
- *Effort:* S.

**E-PY-6. Config protocol for Frida scripts (the fix for F-PY-5)**
- *Current:* `frida_run_script` and `frida_find_bytes` patch values into JS source with `str.replace` on magic lines.
- *Proposal:* standard companion protocol for shipped scripts: script registers a handler for `recv('config', …)`; the Python side sends `{'type':'config', …}` post-load. Fallback: `JSON.stringify`-escape values at the injection point. This removes quote-injection fragility and the "author must include exactly `var X = ""`" contract.
- *Effort:* S (with E-PY-1's script set).

**E-PY-7. New tool: `frida_status`**
- *Current:* nothing introspects the handler's session state; the only way to know "am I attached?" is to run something that errors.
- *Proposal:* a no-op read: package, pid, script(s) loaded, output-queue length, device id — makes multi-turn sessions legible and chainable ("status → decide attach vs spawn").
- *Effort:* S.

**E-PY-8. New tool: `adb_ui_dump`**
- *Current:* the server can screenshot the UI (`scrcpy_screenshot`), but the assistant has no structured view of it — driving test flows ("tap login") is guesswork from pixels.
- *Proposal:* `adb_ui_dump()` — `adb shell uiautomator dump`, pull the XML, parse clickable nodes and return text/resource-id/bounds/clickable as JSON. It is the read-only complement to `scrcpy_screenshot`, and it gives the assistant a stable target list for scripted UI flows on rooted *and* unrooted devices.
- *Effort:* S. (Device-side write is limited to the dump file under `/sdcard`; document that.)

**E-PY-9. Housekeeping**
- Move `frida_memdump`'s default output under `data_dir()/dumps` (currently `~/tools/dumps`).
- Deprecate `datetime.utcnow()` in the HAR helper (subprocess script → `datetime.now(timezone.utc)`).
- Document `adb_shell`'s argument re-joining (space-holding single args not expressible) in the tool description.

**Deliberately *not* proposed (with reasons)**
- **iOS support in the Python server** — the npm server already covers iOS static analysis; dynamic iOS work means signing/gadget/bundler pipelines that are a project of their own. Keep the boundary as-is until there's demand.
- **Enabling `install_tool` by default** — the current guard-off default is correct for a server that can mutate the environment; `--setup` remains the self-service path.

### npm — extensions

**E-NPM-1. Ship the missing decompressed-size caps (the fix for F-NPM-4)**
- *Current:* any zip entry is decompressed in full into memory before inspection; no input-size cap.
- *Proposal:* two constants in `safe-exec.ts` — `MAX_INPUT_BYTES` (default e.g. 2 GiB for the package file) and `MAX_ENTRY_BYTES` (default e.g. 256 MiB per decompressed entry) — checked via adm-zip's `header.size` before `getData()`; over-cap entries are reported as skipped `[skipped: too large]` rather than exploding. This is five lines per call site once centralized in a `readEntry(zip, name)` helper (which F-NPM-3 already proposes to create).
- *Effort:* S (rides on E-NPM-2's refactor).

**E-NPM-2. Unify iOS binary extraction + add aapt2 fallback (the fixes for F-NPM-3 and F-NPM-2)**
- *Current:* three drifting copies of `extractBinary`; manifest analyzer skips `aapt2` even though its parser supports the format.
- *Proposal:* (a) one `src/tools/shared/ios-extract.ts` used by all three iOS tools, with a single exclusion list and no chmod; (b) in `apk_manifest_analyzer`, try `aapt` → `aapt2 dump xmltree` → `apktool`, mirroring the permissions checker. Both are pure code-health changes that make findings consistent between tools.
- *Effort:* S.

**E-NPM-3. New tool: `android_native_libraries`** (the npm-side complement to PyPI's `rasp_identify`)
- *Current:* nothing in either server fingerprints native Android SDKs statically; npm enumerates only iOS frameworks; RASP detection on Android requires the Python device flow.
- *Proposal:* mirror `ios_frameworks_detector` for `lib/<abi>/*.so` entries: emit the inventory (name, size, ABI) and match a `KNOWN_ANDROID_LIBS` table — packers/protectors (`libjiagu*`/360, `libexecmain`/ijiami, `libmobisec`/Ali, `libsgmain`/Guardsquare, `libDexGuard`, `libtprt`/Tencent, `libnqshield`/NetEase, `libkwssgmain`…), common analytics/ads/anti-cheat natives. This is pure zip-index reading (no binaries needed) and gives the Python workflow an instant limbic read — "look, the APK ships libsgmain, expect Guardsquare-tier RASP" — before a device is ever attached.
- *Effort:* M (the tool skeleton + fallback chain are proven patterns; the table curation is the work).

**E-NPM-4. New tool: `apk_diff`**
- *Current:* every tool answers for one file at a time; "what changed between app 2.3.1 and 2.4.0?" has no first-class answer.
- *Proposal:* `apk_diff(old_path, new_path)` — diffs manifest flags, exported components, permission sets, and re-runs the secret patterns on both and reports added/removed findings; optional `skip_secrets` for speed. Read-only, no new binary dependencies, direct answer to a question assessors actually ask on every version bump.
- *Effort:* M.

**E-NPM-5. Complete `android_api_extractor`'s endpoint story (the fix for F-NPM-5-OkHttp)**
- *Current:* Retrofit annotations produce endpoints; the tool also claims OkHttp extraction but only collects field declarations, so the README example question ("What API endpoints does this APK call?") is answered partially.
- *Proposal:* add a `const-string` harvest pass over the same smali folder the tool already walks (regex `https?://` in string constants, deduped, host-grouped) — no new dependencies, and it captures every base URL missed by missing Retrofit annotations. Optionally rename the field-reporting to "OkHttp client fields (detected)" so the description stops overclaiming.
- *Effort:* S.

**E-NPM-6. Test and packaging investments**
- *Current:* 1 of 12 tools unit-tested; smoke script unrunnable on a fresh clone; no `npm test` script.
- *Proposal:* (a) add `test/` unit tests for `patterns.ts` (`scanText`, `renderResults`), both secrets scanners (string-asset fixtures, no binaries needed), the frameworks matcher, and `safe-exec` path validation incl. `MOBILE_RE_MCP_ALLOWED_DIRS`; (b) ship tiny committed APK/IPA fixtures or generate them in CI so `test-tools.mjs` is hermetic, fix the 8/12 numbering and add the four missing tools; (c) add `"test": "npm run build && node --test test/*.test.mjs"`.
- *Effort:* M.

**E-NPM-7. Small consistency fixes**
- One `min_length` default (8) for all strings-family tools.
- `ios_google_services`: decode bplists during the rescan like `ios_secrets_scanner` already does (or document why not).
- Remove the dead ternary, the pointless chmod, the `"simulator"` sentinel (return `{type:"simulator"}` shape instead).
- Move `DexGuard` out of the iOS `KNOWN_FRAMEWORKS`; tighten the matcher to prefix-or-exact matches only.
- Fix `DANGEROUS_PERMISSIONS` labels (rename the section header for non-runtime entries rather than reclassifying, keeping the triage utility).
- Optional runtime hint on ENOENT under Windows ("apktool not resolvable — needs a real .exe").

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
