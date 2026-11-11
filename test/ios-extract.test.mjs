// Regression tests for the deduplicated iOS binary extractor and the
// shared scan-result merge (finding F-NPM-3).
//
// Hermetic: builds IPA-shaped zips in memory with adm-zip — no device,
// no plutil/codesign needed (Info.plist is XML, parsed by the plist pkg).

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import AdmZip from "adm-zip";

const { resolveBinaryEntry, writeBinary, readBinary } = await import(
  "../dist/tools/ios/extract-binary.js"
);
const { mergeScanResults, scanText, SECRET_PATTERNS } = await import(
  "../dist/tools/shared/patterns.js"
);

const PLIST = (exec) => `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>${exec}</string>
</dict></plist>`;

function ipaWithExec(executable, extra = []) {
  const z = new AdmZip();
  z.addFile("Payload/Demo.app/Info.plist", Buffer.from(PLIST(executable)));
  z.addFile(`Payload/Demo.app/${executable}`, Buffer.from("MACH-O-BYTES", "utf8"));
  for (const [name, body] of extra) z.addFile(name, Buffer.from(body, "utf8"));
  return z;
}

test("resolveBinaryEntry: CFBundleExecutable names the binary", () => {
  const z = ipaWithExec("DemoCore", [
    ["Payload/Demo.app/other", "decoy without extension"],
  ]);
  const entry = resolveBinaryEntry(z);
  assert.equal(entry.entryName, "Payload/Demo.app/DemoCore");
});

test("resolveBinaryEntry: falls back to the single extension-less root file", () => {
  const z = new AdmZip();
  z.addFile("Payload/Demo.app/Info.plist", Buffer.from(PLIST("DoesNotExist")));
  z.addFile("Payload/Demo.app/DemoCore", Buffer.from("MACH-O-BYTES", "utf8"));
  const entry = resolveBinaryEntry(z);
  assert.equal(entry.entryName, "Payload/Demo.app/DemoCore");
});

test("resolveBinaryEntry: union exclusion list skips resources", () => {
  // .json/.dylib were excluded only by secrets-scanner's old copy,
  // .lproj/.storyboard only by binary-strings' copy — all must be skipped.
  const z = new AdmZip();
  z.addFile("Payload/Demo.app/Info.plist", Buffer.from(PLIST("DoesNotExist")));
  for (const name of [
    "Payload/Demo.app/assets.json",
    "Payload/Demo.app/libhelper.dylib",
    "Payload/Demo.app/en.lproj",
    "Payload/Demo.app/Credits.storyboard",
    "Payload/Demo.app/Assets.car",
  ]) {
    z.addFile(name, Buffer.from("not a binary", "utf8"));
  }
  z.addFile("Payload/Demo.app/DemoCore", Buffer.from("MACH-O-BYTES", "utf8"));
  const entry = resolveBinaryEntry(z);
  assert.equal(entry.entryName, "Payload/Demo.app/DemoCore");
});

test("resolveBinaryEntry: null when nothing qualifies", () => {
  const z = new AdmZip();
  z.addFile("Payload/Demo.app/Info.plist", Buffer.from(PLIST("X")));
  z.addFile("Payload/Demo.app/X.json", Buffer.from("json, not binary", "utf8"));
  assert.equal(resolveBinaryEntry(z), null);
});

test("writeBinary writes the file; readBinary returns the bytes", () => {
  const z = ipaWithExec("DemoCore");
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "ipa-bin-"));
  const outPath = writeBinary(z, outDir);
  assert.equal(outPath, path.join(outDir, "binary"));
  assert.equal(fs.readFileSync(outPath, "utf8"), "MACH-O-BYTES");
  assert.equal(readBinary(z).toString("utf8"), "MACH-O-BYTES");
  fs.rmSync(outDir, { recursive: true, force: true });
});

test("mergeScanResults dedups across scanners without O(n²) includes()", () => {
  const target = scanText("AKIAIOSFODNN7EXAMPLE", SECRET_PATTERNS);
  const again = scanText(
    "AKIAIOSFODNN7EXAMPLE and AIzaSyA1bC2dE3fG4hI5jK6lM7nO8pQ9rStUvWxyz",
    SECRET_PATTERNS
  );
  mergeScanResults(target, again);
  for (const { matches } of target.values()) {
    assert.equal(new Set(matches).size, matches.length, "no duplicate matches");
  }
  const aws = target.get("AWS Access Key ID");
  assert.equal(aws.matches.length, 1, "same match seen twice → merged once");
  const google = target.get("Google API Key");
  assert.equal(google.matches.length, 1, "new pattern merged in");
});
