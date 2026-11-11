import { z } from "zod";
import { createHash } from "crypto";
import AdmZip from "adm-zip";
import { checkInputFile, errorResult } from "../shared/safe-exec.js";
import { openZip, readEntry } from "../shared/zip.js";
import { extractAndroidManifest } from "./manifest-analyzer.js";
import { collectRawApkSecrets } from "./secrets-scanner.js";
import type { ScanResults } from "../shared/patterns.js";

/**
 * apk_diff — compare two builds of the same app without any external tool
 * beyond what the other readers already need (aapt/aapt2/apktool for the
 * manifest, strings for the optional secret scan).
 *
 * Sections: identity + SDK levels, application flags, permission deltas,
 * exported-component deltas, native-library deltas (sha256), optional
 * secret deltas, and an archive-inventory summary.
 */

const LIST_CAP = 20;

function sha256(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex").slice(0, 16);
}

function cap<T>(items: T[]): { shown: T[]; extra: number } {
  return { shown: items.slice(0, LIST_CAP), extra: Math.max(0, items.length - LIST_CAP) };
}

function fmtSetDelta(label: string, added: string[], removed: string[]): string[] {
  const lines: string[] = [];
  const total = added.length + removed.length;
  if (total === 0) {
    lines.push(`--- ${label}: unchanged ---`);
    return lines;
  }
  lines.push(`--- ${label} (+${added.length} / -${removed.length}) ---`);
  for (const a of cap(added).shown) lines.push(`  + ${a}`);
  if (added.length > LIST_CAP) lines.push(`  … +${added.length - LIST_CAP} more added`);
  for (const r of cap(removed).shown) lines.push(`  - ${r}`);
  if (removed.length > LIST_CAP) lines.push(`  … +${removed.length - LIST_CAP} more removed`);
  return lines;
}

interface LibInfo {
  abi: string;
  basename: string;
  size: number;
  hash: string | null;
}

function nativeLibs(zip: AdmZip, notes: string[]): Map<string, LibInfo> {
  const map = new Map<string, LibInfo>();
  for (const entry of zip.getEntries()) {
    const m = /^lib\/([^/]+)\/([^/]+\.so)$/.exec(entry.entryName);
    if (!m) continue;
    const read = readEntry(entry);
    let hash: string | null = null;
    if (read.ok) hash = sha256(read.data);
    else notes.push(`[skipped: ${read.reason}]`);
    map.set(entry.entryName, { abi: m[1], basename: m[2], size: Number(entry.header.size) || 0, hash });
  }
  return map;
}

function secretDelta(oldS: ScanResults, newS: ScanResults): string[] {
  const lines: string[] = [];
  const names = new Set([...oldS.keys(), ...newS.keys()]);
  const addedPatterns: string[] = [];
  const removedPatterns: string[] = [];
  const changed: string[] = [];
  for (const name of names) {
    const oldEntry = oldS.get(name);
    const newEntry = newS.get(name);
    if (!oldEntry && newEntry) {
      addedPatterns.push(`${name} (${newEntry.def.risk}): ${newEntry.matches.slice(0, 3).join(", ")}`);
    } else if (oldEntry && !newEntry) {
      removedPatterns.push(`${name} (${oldEntry.def.risk}): ${oldEntry.matches.slice(0, 3).join(", ")}`);
    } else if (oldEntry && newEntry) {
      const oldSet = new Set(oldEntry.matches);
      const newSet = new Set(newEntry.matches);
      const gained = newEntry.matches.filter((m) => !oldSet.has(m));
      const lost = oldEntry.matches.filter((m) => !newSet.has(m));
      if (gained.length || lost.length) {
        const parts = [
          gained.length ? `+ ${gained.slice(0, 3).join(", ")}` : null,
          lost.length ? `- ${lost.slice(0, 3).join(", ")}` : null,
        ].filter(Boolean);
        changed.push(`${name}: ${parts.join(" / ")}`);
      }
    }
  }
  if (addedPatterns.length === 0 && removedPatterns.length === 0 && changed.length === 0) {
    lines.push(`--- Secrets: no pattern-level differences ---`);
    return lines;
  }
  lines.push(`--- Secret deltas (new vs old) ---`);
  for (const a of addedPatterns) lines.push(`  NEW ONLY  ${a}`);
  for (const c of changed) lines.push(`  CHANGED   ${c}`);
  for (const r of removedPatterns) lines.push(`  OLD ONLY  ${r}`);
  return lines;
}

export const apkDiff = {
  description:
    "Diffs two builds of the same app (APK vs APK): identity/SDK levels, security flags, permission and exported-component deltas, native-library changes (sha256), optional secret deltas and an archive inventory.",

  schema: {
    old_path: z.string().describe("Absolute path to the older APK"),
    new_path: z.string().describe("Absolute path to the newer APK"),
    skip_secrets: z
      .boolean()
      .optional()
      .describe("Skip the (slower) secret-scan diff; default false"),
  },

  handler: async (args: { old_path: string; new_path: string; skip_secrets?: boolean }) => {
    const oldApk = checkInputFile(args.old_path, "old_path", [".apk"], { requireZipMagic: true });
    if (!oldApk.ok) return errorResult(oldApk.error);
    const newApk = checkInputFile(args.new_path, "new_path", [".apk"], { requireZipMagic: true });
    if (!newApk.ok) return errorResult(newApk.error);

    let oldZip: AdmZip;
    let newZip: AdmZip;
    try {
      oldZip = openZip(oldApk.path);
      newZip = openZip(newApk.path);
    } catch (e) {
      return errorResult(e instanceof Error ? e.message : String(e));
    }

    const lines: string[] = [`=== APK Diff ===`, `old: ${oldApk.path}`, `new: ${newApk.path}`, ""];

    // ── Identity + manifest-derived facts ────────────────────────────────
    const oldM = extractAndroidManifest(oldApk.path);
    const newM = extractAndroidManifest(newApk.path);
    if (oldM && newM) {
      const o = oldM.root;
      const n = newM.root;
      const attr = (root: typeof o, name: string) => root.attrs[name] ?? "(absent)";
      const child = (root: typeof o, tag: string) => root.children.find((c) => c.tag === tag);
      const childAttr = (root: typeof o, tag: string, name: string) =>
        child(root, tag)?.attrs[`android:${name}`] ?? "(absent)";

      lines.push(`--- Identity ---`);
      const pkgO = attr(o, "package");
      const pkgN = attr(n, "package");
      lines.push(`  package: ${pkgO === pkgN ? pkgO : `${pkgO} → ${pkgN}  ⚠ package changed`}`);
      for (const [label, a, b] of [
        ["versionName", attr(o, "android:versionName"), attr(n, "android:versionName")],
        ["versionCode", attr(o, "android:versionCode"), attr(n, "android:versionCode")],
        ["minSdk", childAttr(o, "uses-sdk", "minSdkVersion"), childAttr(n, "uses-sdk", "minSdkVersion")],
        ["targetSdk", childAttr(o, "uses-sdk", "targetSdkVersion"), childAttr(n, "uses-sdk", "targetSdkVersion")],
      ]) {
        if (a !== b) lines.push(`  ${label}: ${a} → ${b}`);
        else lines.push(`  ${label}: ${a} (unchanged)`);
      }

      const flagOf = (root: typeof o, name: string) =>
        (child(root, "application")?.attrs[`android:${name}`] ?? "").toLowerCase() === "true";
      for (const f of ["debuggable", "allowBackup", "usesCleartextTraffic"]) {
        const a = flagOf(o, f);
        const b = flagOf(n, f);
        if (a !== b) lines.push(`  ${f}: ${a} → ${b}${b ? "  ⚠" : ""}`);
      }

      const permsOf = (root: typeof o) =>
        root.children
          .filter((c) => c.tag === "uses-permission")
          .map((c) => c.attrs["android:name"])
          .filter(Boolean) as string[];
      const oldPerms = new Set(permsOf(o));
      const newPerms = new Set(permsOf(n));
      const permAdded = [...newPerms].filter((p) => !oldPerms.has(p)).sort();
      const permRemoved = [...oldPerms].filter((p) => !newPerms.has(p)).sort();
      lines.push("", ...fmtSetDelta(`Permissions (${oldPerms.size} → ${newPerms.size})`, permAdded, permRemoved));

      // Exported components (explicit android:exported="true")
      const exportedOf = (root: typeof o) => {
        const pkg = root.attrs["package"] ?? "";
        const app = child(root, "application");
        const kinds = ["activity", "activity-alias", "service", "receiver", "provider"];
        return (app?.children ?? [])
          .filter((c) => kinds.includes(c.tag))
          .filter((c) => (c.attrs["android:exported"] ?? "").toLowerCase() === "true")
          .map((c) => {
            const raw = c.attrs["android:name"] ?? "(anonymous)";
            const qualified = raw.startsWith(".") ? `${pkg}${raw}` : raw;
            return `${qualified} (${c.tag})`;
          })
          .sort();
      };
      const oldExp = new Set(exportedOf(o));
      const newExp = new Set(exportedOf(n));
      const expAdded = [...newExp].filter((p) => !oldExp.has(p));
      const expRemoved = [...oldExp].filter((p) => !newExp.has(p));
      lines.push("", ...fmtSetDelta(`Exported components (${oldExp.size} → ${newExp.size})`, expAdded, expRemoved));
    } else {
      lines.push(
        `--- Manifest: skipped (aapt/aapt2/apktool could not read ${oldM ? "the new" : "the old"} APK's manifest) ---`
      );
    }

    // ── Native libraries ─────────────────────────────────────────────────
    const notes: string[] = [];
    const oldLibs = nativeLibs(oldZip, notes);
    const newLibs = nativeLibs(newZip, notes);
    const libAdded: string[] = [];
    const libRemoved: string[] = [];
    const libChanged: string[] = [];
    for (const [name, info] of newLibs) {
      const old = oldLibs.get(name);
      if (!old) libAdded.push(`${info.abi}/${info.basename}`);
      else if (old.hash !== info.hash) libChanged.push(`${info.abi}/${info.basename}`);
    }
    for (const [name, info] of oldLibs) {
      if (!newLibs.has(name)) libRemoved.push(`${info.abi}/${info.basename}`);
    }
    lines.push("", `--- Native libraries (${oldLibs.size} → ${newLibs.size}) ---`);
    if (libAdded.length === 0 && libRemoved.length === 0 && libChanged.length === 0) {
      lines.push(`  all ${oldLibs.size} .so file(s) identical (sha256)`);
    } else {
      for (const a of cap(libAdded).shown) lines.push(`  + ${a}`);
      for (const c of cap(libChanged).shown) lines.push(`  ~ ${c} (sha256 changed)`);
      for (const r of cap(libRemoved).shown) lines.push(`  - ${r}`);
      for (const extra of [libAdded, libChanged, libRemoved]) {
        if (extra.length > LIST_CAP) lines.push(`  … +${extra.length - LIST_CAP} more`);
      }
    }

    // ── Secrets (optional) ───────────────────────────────────────────────
    if (args.skip_secrets) {
      lines.push("", `--- Secrets: skipped (skip_secrets=true) ---`);
    } else {
      try {
        const oldSecrets = collectRawApkSecrets(oldZip, 8);
        const newSecrets = collectRawApkSecrets(newZip, 8);
        lines.push("", ...secretDelta(oldSecrets, newSecrets));
      } catch (e) {
        lines.push("", `--- Secrets: scan failed (${e instanceof Error ? e.message : String(e)}) ---`);
      }
    }

    // ── Archive inventory ────────────────────────────────────────────────
    const oldNames = new Set(oldZip.getEntries().filter((e) => !e.isDirectory).map((e) => e.entryName));
    const newEntries = newZip.getEntries().filter((e) => !e.isDirectory);
    const newNames = new Set(newEntries.map((e) => e.entryName));
    const entryAdded = newEntries.filter((e) => !oldNames.has(e.entryName)).length;
    const entryRemoved = [...oldNames].filter((n) => !newNames.has(n)).length;
    let entryChanged = 0;
    for (const e of newEntries) {
      if (!oldNames.has(e.entryName)) continue;
      const old = oldZip.getEntry(e.entryName)!;
      if (Number(old.header.size) !== Number(e.header.size)) entryChanged++;
    }
    lines.push(
      "",
      `--- Archive inventory ---`,
      `  entries: ${oldNames.size} → ${newNames.size} (+${entryAdded} / -${entryRemoved}, ${entryChanged} changed size)`
    );
    if (notes.length > 0) {
      lines.push(`  notes: ${notes.slice(0, 5).join("; ")}`);
    }

    return { content: [{ type: "text" as const, text: lines.join("\n") }] };
  },
};
