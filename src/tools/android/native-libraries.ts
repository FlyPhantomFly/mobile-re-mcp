import { z } from "zod";
import AdmZip from "adm-zip";
import { checkInputFile, errorResult } from "../shared/safe-exec.js";
import { openZip, readEntry } from "../shared/zip.js";

/**
 * android_native_libraries — enumerate every ELF shared object shipped in
 * an APK's lib/<abi>/ directories and fingerprint it.
 *
 * Two identification layers:
 *   1. A known-library table (packers, RASP/anti-tamper, frameworks, SDKs,
 *      runtimes) matched on the basename.
 *   2. Raw ELF header inspection: class/machine, section-header presence
 *      and section-name list. Packers and protectors routinely strip or
 *      merge sections, so shnum = 0 on an unpacked-looking .so is a
 *      protection signal in its own right.
 */

interface KnownLib {
  pattern: RegExp;
  label: string;
  kind: "packer" | "rasp" | "framework" | "sdk" | "runtime";
}

/** Publicly documented Android native libraries (basename match). */
export const KNOWN_ANDROID_LIBS: KnownLib[] = [
  // ── Packers / protectors (dex-shelling, VMP) ──────────────────────────
  { pattern: /^libjiagu/i, label: "Qihoo 360 Jiagu (加固)", kind: "packer" },
  { pattern: /^libDexHelper/i, label: "SecNeo", kind: "packer" },
  { pattern: /^libexecmain|^libexecs?\./, label: "Ijiami (爱加密)", kind: "packer" },
  { pattern: /^libchaosvmp/, label: "Naga (娜迦) VMP", kind: "packer" },
  { pattern: /^libddiexec/, label: "Naga (娜迦)", kind: "packer" },
  { pattern: /^libnesec/, label: "Naga (娜迦)", kind: "packer" },
  { pattern: /^libshell/, label: "Tencent Legu (乐固)", kind: "packer" },
  { pattern: /^libtup|^libtos\./, label: "Tencent Legu (乐固)", kind: "packer" },
  { pattern: /^libSecShell/i, label: "Bangcle (梆梆安全)", kind: "packer" },
  { pattern: /^libDexProtector/i, label: "DexProtector", kind: "packer" },
  { pattern: /^libmobisec/i, label: "Alibaba Mobisec", kind: "packer" },
  { pattern: /^libkwscmm|^libkwssgmain|^libkwslinker/, label: "KiwiSec (几维安全)", kind: "packer" },

  // ── RASP / anti-tamper / anti-cheat ──────────────────────────────────
  { pattern: /^libAppGuard/i, label: "AppGuard (INKA Entworks)", kind: "rasp" },
  { pattern: /^libsgmain|^libsgsecuritybody/, label: "Alibaba SecurityGuard (聚安全)", kind: "rasp" },
  { pattern: /^libtprt/i, label: "Tencent TP (TenProtect)", kind: "rasp" },
  { pattern: /^libnqshield/i, label: "NetQin (网秦)", kind: "rasp" },

  // ── Frameworks / engines ─────────────────────────────────────────────
  { pattern: /^libflutter/, label: "Flutter engine", kind: "framework" },
  { pattern: /^libreactnativejni/, label: "React Native", kind: "framework" },
  { pattern: /^libunity/, label: "Unity engine", kind: "framework" },
  { pattern: /^libil2cpp/, label: "Unity IL2CPP", kind: "framework" },
  { pattern: /^libxamarin/i, label: "Xamarin", kind: "framework" },
  { pattern: /^libmono/, label: "Mono runtime (Xamarin)", kind: "framework" },
  { pattern: /^libgodot/, label: "Godot engine", kind: "framework" },
  { pattern: /^libQt5/, label: "Qt", kind: "framework" },

  // ── SDKs ─────────────────────────────────────────────────────────────
  { pattern: /^libBugly/i, label: "Tencent Bugly (crash reporting)", kind: "sdk" },
  { pattern: /^libjpush/i, label: "JPush (极光推送)", kind: "sdk" },
  { pattern: /^libgetuiext/i, label: "GeTui (个推)", kind: "sdk" },
  { pattern: /^libumeng/i, label: "Umeng (友盟)", kind: "sdk" },

  // ── Runtimes (benign, useful context) ────────────────────────────────
  { pattern: /^libc\+\+_shared/, label: "NDK libc++ runtime", kind: "runtime" },
  { pattern: /^libhoudini/, label: "Intel ARM translation layer", kind: "runtime" },
  { pattern: /^libRSSupport|^librsjni/, label: "RenderScript support", kind: "runtime" },
];

const ELF_MACHINES: Record<number, string> = {
  3: "x86",
  8: "MIPS",
  40: "ARM",
  62: "x86-64",
  183: "ARM64",
  243: "RISC-V",
};

interface ElfInfo {
  ok: boolean;
  detail: string;
  machine: string | null;
  shnum: number | null;
  sections: string[] | null;
  note: string | null;
}

/**
 * Parse the interesting parts of an ELF header and (when present) the
 * section-name table. Never throws — a non-ELF blob reports ok:false.
 */
export function inspectElf(data: Buffer): ElfInfo {
  if (data.length < 0x34 || !data.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) {
    return { ok: false, detail: "not an ELF (missing \\x7fELF magic)", machine: null, shnum: null, sections: null, note: null };
  }
  const eiClass = data[4];
  const eiData = data[5];
  const is64 = eiClass === 2;
  const le = eiData === 1;
  if (!is64 && eiClass !== 1) {
    return { ok: false, detail: "ELF with unknown EI_CLASS " + eiClass, machine: null, shnum: null, sections: null, note: null };
  }
  if (!le) {
    return { ok: false, detail: "big-endian ELF is not an Android ABI", machine: null, shnum: null, sections: null, note: null };
  }

  const eType = data.readUInt16LE(0x10);
  const eMachine = data.readUInt16LE(0x12);
  const machine = ELF_MACHINES[eMachine] ?? `machine ${eMachine}`;
  const typeNames: Record<number, string> = { 2: "EXEC", 3: "DYN (shared object)" };
  const typeStr = typeNames[eType] ?? `type ${eType}`;

  // Section-header table location differs between ELF32 and ELF64.
  const shoffOff = is64 ? 0x28 : 0x20;
  const shentsizeOff = is64 ? 0x3a : 0x2e;
  const shnumOff = is64 ? 0x3c : 0x30;
  const shstrndxOff = is64 ? 0x3e : 0x32;
  const shoff = is64 ? Number(data.readBigUInt64LE(shoffOff)) : data.readUInt32LE(shoffOff);
  const shentsize = data.readUInt16LE(shentsizeOff);
  const shnum = data.readUInt16LE(shnumOff);
  const shstrndx = data.readUInt16LE(shstrndxOff);

  let sections: string[] | null = null;
  let note: string | null = null;

  if (shoff === 0 || shnum === 0) {
    note = "no section-header table (stripped or packed — common for packer/RASP payloads)";
  } else if (shstrndx === 0 || shstrndx === 0xffff) {
    note = "section headers present but no section-name table";
  } else if (shoff + shnum * shentsize <= data.length) {
    const strHdr = shoff + shstrndx * shentsize;
    const strOff = is64 ? Number(data.readBigUInt64LE(strHdr + 0x18)) : data.readUInt32LE(strHdr + 0x10);
    const strSize = is64 ? Number(data.readBigUInt64LE(strHdr + 0x20)) : data.readUInt32LE(strHdr + 0x14);
    if (strOff + strSize <= data.length) {
      const strtab = data.subarray(strOff, strOff + strSize);
      sections = [];
      for (let i = 0; i < shnum; i++) {
        const shType = data.readUInt32LE(shoff + i * shentsize + 4);
        if (shType === 0) continue; // SHT_NULL carries no real name
        const nameOff = data.readUInt32LE(shoff + i * shentsize);
        const end = strtab.indexOf(0, nameOff);
        const name = end === -1 ? "" : strtab.subarray(nameOff, end).toString("latin1");
        if (name) sections.push(name);
      }
    }
  } else {
    note = `section-header table declares ${shnum} entries beyond the file end (malformed or packed)`;
  }

  return {
    ok: true,
    detail: `ELF ${is64 ? "64" : "32"}-bit ${machine}, ${typeStr}`,
    machine,
    shnum,
    sections,
    note,
  };
}

export function matchKnownLib(basename: string): KnownLib | null {
  for (const lib of KNOWN_ANDROID_LIBS) {
    if (lib.pattern.test(basename)) return lib;
  }
  return null;
}

export const androidNativeLibraries = {
  description:
    "Enumerates every ELF .so shipped in an APK (per ABI), identifies known packer/RASP/framework/SDK libraries by name, and inspects ELF headers for stripped-or-packed section tables.",

  schema: {
    apk_path: z.string().describe("Absolute path to the APK file to inspect"),
  },

  handler: async (args: { apk_path: string }) => {
    const apk = checkInputFile(args.apk_path, "apk_path", [".apk"], { requireZipMagic: true });
    if (!apk.ok) return errorResult(apk.error);

    let zip: AdmZip;
    try {
      zip = openZip(apk.path);
    } catch (e) {
      return errorResult(e instanceof Error ? e.message : String(e));
    }

    const byAbi = new Map<string, { entryName: string; basename: string; size: number }[]>();
    for (const entry of zip.getEntries()) {
      const m = /^lib\/([^/]+)\/([^/]+\.so)$/.exec(entry.entryName);
      if (!m) continue;
      const [, abi, basename] = m;
      const list = byAbi.get(abi) ?? [];
      list.push({ entryName: entry.entryName, basename, size: Number(entry.header.size) || 0 });
      byAbi.set(abi, list);
    }

    if (byAbi.size === 0) {
      return {
        content: [
          {
            type: "text" as const,
            text: `=== Android Native Libraries ===\nAPK: ${apk.path}\nNo lib/<abi>/*.so entries — the APK ships no native code.`,
          },
        ],
      };
    }

    const lines: string[] = ["=== Android Native Libraries ===", `APK: ${apk.path}`, ""];
    const signals: string[] = [];
    let knownCount = 0;

    for (const abi of [...byAbi.keys()].sort()) {
      const libs = byAbi.get(abi)!;
      lines.push(`[${abi}] ${libs.length} library/libraries`);
      for (const lib of libs.sort((a, b) => a.basename.localeCompare(b.basename))) {
        const known = matchKnownLib(lib.basename);
        const read = readEntry(zip.getEntry(lib.entryName)!);
        if (!read.ok) {
          lines.push(`  ${lib.basename} — [skipped: ${read.reason}]`);
          continue;
        }
        const elf = inspectElf(read.data);
        const sectionPart = elf.ok && elf.sections
          ? `, ${elf.sections.length} section${elf.sections.length === 1 ? "" : "s"}`
          : "";
        if (known) {
          knownCount++;
          lines.push(`  ${lib.basename} — ${known.label} (${known.kind}) — ${elf.detail}${sectionPart}`);
        } else {
          lines.push(`  ${lib.basename} — ${elf.detail}${sectionPart} — app-owned / unknown vendor`);
        }
        if (elf.note) {
          lines.push(`      ⚠ ${elf.note}`);
        }
        if (known && (known.kind === "packer" || known.kind === "rasp")) {
          const notePart = elf.note ? ` — ${elf.note}` : "";
          signals.push(`${lib.basename}: ${known.label} (${known.kind})${notePart}`);
        } else if (!known && elf.note) {
          signals.push(`${lib.basename}: unrecognised library with a suspicious ELF layout — ${elf.note}`);
        }
      }
      lines.push("");
    }

    if (signals.length > 0) {
      lines.push(`--- Protection signals (${signals.length}) ---`);
      for (const s of signals) lines.push(`  ⚠ ${s}`);
      lines.push("");
    }

    const allLibs = [...byAbi.values()].flat();
    const kindCount = (kind: KnownLib["kind"]) =>
      allLibs.filter((l) => matchKnownLib(l.basename)?.kind === kind).length;
    lines.push(
      `Summary: ${allLibs.length} .so files across ${byAbi.size} ABI(s); ` +
        `${knownCount} recognised (${kindCount("packer")} packer, ${kindCount("rasp")} RASP, ` +
        `${kindCount("framework")} framework, ${kindCount("sdk")} SDK, ${kindCount("runtime")} runtime).`
    );

    return { content: [{ type: "text" as const, text: lines.join("\n") }] };
  },
};
