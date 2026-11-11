// Regression tests for apk_diff (extension E-NPM: APK diffing).
//
// Hermetic: two APK-shaped in-memory zips (old vs new). The manifest
// section needs aapt/aapt2 on PATH — the zips here carry a plain-text
// stub manifest, so those sections are expected to report "skipped";
// everything else (native libs, secrets, inventory) is fully checked.
// The manifest path itself is exercised live via the aapt2 chain.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import AdmZip from "adm-zip";

const { apkDiff } = await import("../dist/tools/android/apk-diff.js");

function writeApk(name, build) {
  const z = new AdmZip();
  build(z);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "apk-diff-"));
  const apkPath = path.join(dir, name);
  z.writeZip(apkPath);
  return apkPath;
}

const STUB_MANIFEST = Buffer.from("not a real AXML manifest", "utf8");

test("apk_diff: native lib changes, secret deltas and inventory", async () => {
  const oldApk = writeApk("old.apk", (z) => {
    z.addFile("AndroidManifest.xml", STUB_MANIFEST);
    z.addFile("classes.dex", Buffer.from("old dex", "utf8"));
    z.addFile("lib/arm64-v8a/libnative.so", Buffer.from("version-one-bytes", "utf8"));
    z.addFile("assets/config.json", Buffer.from('{"k": "AKIAIOSFODNN7EXAMPLE"}', "utf8"));
  });
  const newApk = writeApk("new.apk", (z) => {
    z.addFile("AndroidManifest.xml", STUB_MANIFEST);
    z.addFile("classes.dex", Buffer.from("new dex bytes are longer", "utf8"));
    z.addFile("lib/arm64-v8a/libnative.so", Buffer.from("version-two-bytes!!", "utf8"));
    z.addFile("lib/armeabi-v7a/libextra.so", Buffer.from("brand new lib", "utf8"));
    z.addFile("assets/config.json", Buffer.from('{"k": "AIzaSyA1bC2dE3fG4hI5jK6lM7nO8pQ9rStUvWxyz"}', "utf8"));
  });

  const res = await apkDiff.handler({ old_path: oldApk, new_path: newApk });
  const text = res.content[0].text;

  assert.match(text, /--- Manifest: skipped/); // stub manifest is not AXML
  assert.match(text, /--- Native libraries \(1 → 2\) ---/);
  assert.match(text, /~ arm64-v8a\/libnative\.so \(sha256 changed\)/);
  assert.match(text, /\+ armeabi-v7a\/libextra\.so/);
  assert.match(text, /NEW ONLY\s+Google API Key \(HIGH\): AIzaSyA1bC2dE3fG4hI5jK6lM7nO8pQ9rStUvWx/);
  assert.match(text, /OLD ONLY\s+AWS Access Key ID \(CRITICAL\): AKIAIOSFODNN7EXAMPLE/); // the old key disappeared
  assert.match(text, /entries: 4 → 5 \(\+1 \/ -0, 3 changed size\)/);
  fs.rmSync(path.dirname(oldApk), { recursive: true, force: true });
  fs.rmSync(path.dirname(newApk), { recursive: true, force: true });
});

test("apk_diff: identical APKs report all-identical", async () => {
  const apk = writeApk("same.apk", (z) => {
    z.addFile("AndroidManifest.xml", STUB_MANIFEST);
    z.addFile("classes.dex", Buffer.from("dex", "utf8"));
    z.addFile("lib/arm64-v8a/libstable.so", Buffer.from("stable", "utf8"));
  });
  const res = await apkDiff.handler({ old_path: apk, new_path: apk, skip_secrets: true });
  const text = res.content[0].text;
  assert.match(text, /entries: 3 → 3 \(\+0 \/ -0, 0 changed size\)/);
  assert.match(text, /all 1 \.so file\(s\) identical \(sha256\)/);
  assert.match(text, /--- Secrets: skipped \(skip_secrets=true\) ---/);
  fs.rmSync(path.dirname(apk), { recursive: true, force: true });
});

test("apk_diff: rejects a missing or non-zip input", async () => {
  const bad = await apkDiff.handler({ old_path: "/nonexistent/old.apk", new_path: "/tmp/x.apk" });
  assert.match(bad.content[0].text, /old_path not found/);

  const notZip = fs.mkdtempSync(path.join(os.tmpdir(), "apk-diff-"));
  const txt = path.join(notZip, "plain.apk");
  fs.writeFileSync(txt, "definitely not a zip archive");
  const res = await apkDiff.handler({ old_path: txt, new_path: txt });
  assert.match(res.content[0].text, /Error|zip/i);
  fs.rmSync(notZip, { recursive: true, force: true });
});
