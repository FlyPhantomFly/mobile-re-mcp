import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseManifest, analyzeManifest } from "../dist/tools/android/manifest-analyzer.js";

const read = (name) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8");

// aapt-xmltree.txt is real `aapt dump xmltree` output from a small sample APK.
// aapt2-xmltree.txt is the same manifest rewritten in aapt2's attribute syntax.
for (const [label, file] of [["aapt", "aapt-xmltree.txt"], ["aapt2", "aapt2-xmltree.txt"]]) {
  test(`${label}: reads package, flags and components`, () => {
    const root = parseManifest(read(file));
    assert.ok(root, "manifest should parse");
    const report = analyzeManifest(root, label);
    assert.match(report, /Package Name : com\.example\.notes/);
    assert.match(report, /Version Code : 231/);
    assert.match(report, /Version Name : 2\.3\.1/);
    assert.match(report, /debuggable {10}: TRUE/);
    assert.match(report, /allowBackup {9}: TRUE/);
    assert.match(report, /usesCleartextTraffic: TRUE/);
    assert.match(report, /Activities \(2\): com\.example\.notes\.MainActivity, com\.example\.notes\.ShareActivity/);
    assert.match(report, /Services {3}\(1\): com\.example\.notes\.SyncService/);
    assert.match(report, /Receivers {2}\(1\): com\.example\.notes\.BootReceiver/);
    assert.match(report, /Providers {2}\(1\): com\.example\.notes\.NotesProvider/);
    assert.match(report, /5 exported component\(s\)/);
    assert.match(report, /android\.intent\.action\.BOOT_COMPLETED/);
    assert.doesNotMatch(report, /No critical manifest security issues/);
  });
}

test("apktool: reads decoded XML, resolves names and honours exported=false", () => {
  const root = parseManifest(read("apktool-manifest.xml"));
  assert.ok(root);
  const report = analyzeManifest(root, "apktool");
  assert.match(report, /Package Name : org\.sample\.shop/);
  assert.match(report, /debuggable {10}: false/);
  assert.match(report, /networkSecurityConfig: present/);
  assert.match(report, /org\.sample\.shop\.MainActivity/); // ".MainActivity" resolved
  assert.match(report, /org\.sample\.shop\.DeepLinkActivity/); // bare class name resolved
  const exportedSection = report.split("--- Exported Components")[1].split("---")[1] ?? "";
  assert.match(report, /2 exported component\(s\)/); // MainActivity and PushReceiver
  assert.doesNotMatch(exportedSection, /PrivateActivity/);
});

test("an intent filter without android:exported is reported as exported by default", () => {
  const report = analyzeManifest(parseManifest(read("apktool-manifest.xml")), "apktool");
  const section = report.split("--- Exported by default")[1] ?? "";
  assert.match(section, /DeepLinkActivity/);
  assert.doesNotMatch(section.split("---")[0], /PrivateActivity/); // explicit false stays out
});

test("unreadable input gives null instead of a clean bill of health", () => {
  assert.equal(parseManifest("not a manifest"), null);
  assert.equal(parseManifest(""), null);
  assert.equal(parseManifest("<html><body>nope</body></html>"), null);
});
