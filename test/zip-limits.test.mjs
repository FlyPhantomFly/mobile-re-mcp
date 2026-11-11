// Regression tests for the decompression-size caps (finding F-NPM-4).
//
// Hermetic: builds throwaway zips with adm-zip in a temp dir and drives
// the shared helpers from dist/tools/shared/zip.js. The env caps are
// saved and restored around every test so CI env never leaks.

import { test, before, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import AdmZip from "adm-zip";

const zip = await import("../dist/tools/shared/zip.js");

const savedEnv = {
  MOBILE_RE_MCP_MAX_FILE_MB: process.env.MOBILE_RE_MCP_MAX_FILE_MB,
  MOBILE_RE_MCP_MAX_ENTRY_MB: process.env.MOBILE_RE_MCP_MAX_ENTRY_MB,
};

afterEach(() => {
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

function tmpZipFile(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ziptest-"));
  return path.join(dir, name);
}

function makeZip(filePath, entries) {
  const z = new AdmZip();
  for (const e of entries) {
    z.addFile(e.name, Buffer.alloc(e.bytes, 0x41));
  }
  z.writeZip(filePath);
}

before(() => {
  assert.ok(typeof zip.openZip === "function", "openZip exported");
});

test("envMaxMb: default, explicit, and 0-disables", () => {
  delete process.env.MOBILE_RE_MCP_MAX_FILE_MB;
  assert.equal(zip.maxFileMb(), 2048);
  process.env.MOBILE_RE_MCP_MAX_FILE_MB = "4096";
  assert.equal(zip.maxFileMb(), 4096);
  process.env.MOBILE_RE_MCP_MAX_FILE_MB = "0";
  assert.equal(zip.maxFileMb(), 0);
  process.env.MOBILE_RE_MCP_MAX_FILE_MB = "not-a-number";
  assert.equal(zip.maxFileMb(), 2048); // invalid → default
});

test("checkPayloadSize throws above the input cap with a clear error", () => {
  const p = tmpZipFile("big.apk");
  fs.writeFileSync(p, Buffer.alloc(3 * 1024 * 1024, 0x41)); // 3 MB plain file
  process.env.MOBILE_RE_MCP_MAX_FILE_MB = "1";
  assert.throws(() => zip.checkPayloadSize(p), (err) => {
    assert.equal(err.name, "PayloadTooLargeError");
    assert.match(err.message, /above the 1 MB cap/);
    assert.match(err.message, /MOBILE_RE_MCP_MAX_FILE_MB/);
    return true;
  });
  process.env.MOBILE_RE_MCP_MAX_FILE_MB = "0"; // disabled → no throw
  assert.doesNotThrow(() => zip.checkPayloadSize(p));
});

test("openZip wraps corrupt archives in a normalized error", () => {
  const p = tmpZipFile("broken.ipa");
  fs.writeFileSync(p, "PK\x03\x04but-not-a-zip");
  assert.throws(() => zip.openZip(p), /cannot open .* as a zip archive/);
});

test("readEntry skips an oversized entry without decompressing it", () => {
  const p = tmpZipFile("sample.apk");
  makeZip(p, [
    { name: "small.txt", bytes: 128 },
    { name: "huge.bin", bytes: 4 * 1024 * 1024 }, // 4 MB — above a 1 MB cap
  ]);
  process.env.MOBILE_RE_MCP_MAX_ENTRY_MB = "1";
  const z = zip.openZip(p);
  const entries = Object.fromEntries(z.getEntries().map((e) => [e.entryName, e]));

  const small = zip.readEntry(entries["small.txt"]);
  assert.equal(small.ok, true);
  assert.equal(small.data.length, 128);

  const huge = zip.readEntry(entries["huge.bin"]);
  assert.equal(huge.ok, false);
  assert.equal(huge.skipped, true);
  assert.match(huge.reason, /above the 1 MB cap/);
  assert.match(huge.reason, /huge\.bin/);

  // same entry passes when the cap is raised
  process.env.MOBILE_RE_MCP_MAX_ENTRY_MB = "10";
  const ok = zip.readEntry(entries["huge.bin"]);
  assert.equal(ok.ok, true);
  assert.equal(ok.data.length, 4 * 1024 * 1024);
});

test("requireEntryData throws PayloadTooLargeError on a skip", () => {
  const p = tmpZipFile("sample2.apk");
  makeZip(p, [{ name: "huge.bin", bytes: 2 * 1024 * 1024 }]);
  process.env.MOBILE_RE_MCP_MAX_ENTRY_MB = "1";
  const z = zip.openZip(p);
  const entry = z.getEntry("huge.bin");
  assert.throws(() => zip.requireEntryData(entry), (err) => {
    assert.equal(err.name, "PayloadTooLargeError");
    assert.match(err.message, /huge\.bin/);
    return true;
  });
});

test("skippedPlaceholder renders the agreed marker", () => {
  assert.equal(zip.skippedPlaceholder("reason X"), "[skipped: reason X]");
});
