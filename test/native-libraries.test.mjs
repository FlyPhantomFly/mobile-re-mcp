// Regression tests for android_native_libraries (extension E-NPM: native
// library fingerprinting).
//
// Hermetic: builds APK-shaped zips in memory with adm-zip and crafts
// minimal ELF64 binaries by hand — no device, no NDK needed.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import AdmZip from "adm-zip";

const { androidNativeLibraries, inspectElf, matchKnownLib } = await import(
  "../dist/tools/android/native-libraries.js"
);

const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);

function elfHeader({ is64, machine, eType = 3 }) {
  const buf = Buffer.alloc(64, 0);
  ELF_MAGIC.copy(buf, 0);
  buf[4] = is64 ? 2 : 1; // EI_CLASS
  buf[5] = 1; // EI_DATA little-endian
  buf[6] = 1; // EI_VERSION
  buf.writeUInt16LE(eType, 0x10);
  buf.writeUInt16LE(machine, 0x12);
  buf.writeUInt32LE(1, 0x14); // e_version
  buf.writeUInt16LE(64, 0x34); // e_ehsize
  return buf;
}

/** A crafted ELF64/ARM64 with NO section-header table (packer-shaped). */
function packedElf() {
  const buf = elfHeader({ is64: true, machine: 183 }); // EM_AARCH64
  // e_shoff = 0, e_shnum = 0 (already zeroed) → section table absent.
  return buf;
}

/** A crafted ELF64/ARM64 WITH a section table and a name string table. */
function sectionedElf() {
  const names = Buffer.from(".shstrtab\0.interp\0.text\0", "latin1");
  const shoff = 88; // 64 (ehdr) + 24 (shstrtab bytes)
  const shnum = 4;
  const buf = Buffer.alloc(shoff + shnum * 64, 0);
  elfHeader({ is64: true, machine: 183 }).copy(buf, 0);
  buf.writeBigUInt64LE(BigInt(shoff), 0x28);
  buf.writeUInt16LE(64, 0x3a); // e_shentsize
  buf.writeUInt16LE(shnum, 0x3c);
  buf.writeUInt16LE(3, 0x3e); // e_shstrndx → section 3

  names.copy(buf, 64);
  // sh0: null section (zeros). sh1: .interp (name offset 10). sh2: .text (18).
  buf.writeUInt32LE(10, shoff + 1 * 64 + 0);
  buf.writeUInt32LE(1, shoff + 1 * 64 + 4); // PROGBITS
  buf.writeUInt32LE(18, shoff + 2 * 64 + 0);
  buf.writeUInt32LE(1, shoff + 2 * 64 + 4);
  // sh3: the .shstrtab section itself — name 0, STRTAB, offset 64, size 24.
  buf.writeUInt32LE(3, shoff + 3 * 64 + 4); // SHT_STRTAB
  buf.writeBigUInt64LE(BigInt(64), shoff + 3 * 64 + 0x18); // sh_offset
  buf.writeBigUInt64LE(BigInt(names.length), shoff + 3 * 64 + 0x20); // sh_size
  return buf;
}

test("inspectElf: class, machine and missing section table", () => {
  const packed = inspectElf(packedElf());
  assert.equal(packed.ok, true);
  assert.match(packed.detail, /ELF 64-bit ARM64/);
  assert.equal(packed.shnum, 0);
  assert.match(packed.note, /no section-header table/);

  const junk = inspectElf(Buffer.from("this is not an ELF at all..."));
  assert.equal(junk.ok, false);
  assert.match(junk.detail, /not an ELF/);
});

test("inspectElf: reads section names from a crafted table", () => {
  const info = inspectElf(sectionedElf());
  assert.equal(info.ok, true);
  assert.equal(info.shnum, 4);
  assert.deepEqual(info.sections, [".interp", ".text", ".shstrtab"]);
  assert.equal(info.note, null);
});

test("matchKnownLib: packer, framework and runtime names", () => {
  assert.equal(matchKnownLib("libjiagu.so")?.kind, "packer");
  assert.equal(matchKnownLib("libjiagu_art.so")?.label, "Qihoo 360 Jiagu (加固)");
  assert.equal(matchKnownLib("libDexHelper.so")?.label, "SecNeo");
  assert.equal(matchKnownLib("libflutter.so")?.kind, "framework");
  assert.equal(matchKnownLib("libc++_shared.so")?.kind, "runtime");
  assert.equal(matchKnownLib("libtotally_unknown_vendor.so"), null);
});

test("handler: groups by ABI, flags packer + stripped sections, tolerates non-ELF", async () => {
  const z = new AdmZip();
  z.addFile("AndroidManifest.xml", Buffer.from("stub", "utf8"));
  z.addFile("lib/arm64-v8a/libjiagu.so", packedElf());
  z.addFile("lib/arm64-v8a/libflutter.so", sectionedElf());
  z.addFile("lib/armeabi-v7a/libappmain.so", Buffer.from("not an elf", "utf8"));

  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "native-libs-"));
  const apkPath = path.join(outDir, "fake.apk");
  z.writeZip(apkPath);

  const res = await androidNativeLibraries.handler({ apk_path: apkPath });
  const text = res.content[0].text;
  assert.match(text, /\[arm64-v8a\] 2 library\/libraries/);
  assert.match(text, /libjiagu\.so — Qihoo 360 Jiagu \(加固\) \(packer\)/);
  assert.match(text, /no section-header table/);
  assert.match(text, /libflutter\.so — Flutter engine \(framework\) — ELF 64-bit ARM64.*3 sections/);
  assert.match(text, /libappmain\.so — not an ELF/);
  assert.match(text, /--- Protection signals \(1\)/);
  assert.match(text, /Summary: 3 \.so files across 2 ABI\(s\)/);
  fs.rmSync(outDir, { recursive: true, force: true });
});

test("handler: APK with no native code says so plainly", async () => {
  const z = new AdmZip();
  z.addFile("AndroidManifest.xml", Buffer.from("stub", "utf8"));
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "native-libs-"));
  const apkPath = path.join(outDir, "no-libs.apk");
  z.writeZip(apkPath);

  const res = await androidNativeLibraries.handler({ apk_path: apkPath });
  assert.match(res.content[0].text, /ships no native code/);
  fs.rmSync(outDir, { recursive: true, force: true });
});
