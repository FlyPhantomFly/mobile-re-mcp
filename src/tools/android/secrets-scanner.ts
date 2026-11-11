import { z } from "zod";
import { run, checkInputFile, checkInputDir, errorResult } from "../shared/safe-exec.js";
import { openZip, readEntry, skippedPlaceholder } from "../shared/zip.js";
import { SECRET_PATTERNS, scanText, renderResults, mergeScanResults } from "../shared/patterns.js";
import type { ScanResults } from "../shared/patterns.js";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

const TEXT_ASSET_EXTENSIONS = [".json", ".xml", ".txt", ".properties", ".yaml", ".yml", ".plist"];

export const androidSecretsScanner = {
  description:
    "Scans an APK for hardcoded secrets and API keys. " +
    "Without smali_folder: runs strings on classes*.dex and resources.arsc, plus scans text assets inside the APK. " +
    "With smali_folder (apktool output): scans res/values/strings.xml and assets as plain text files.",

  schema: {
    apk_path: z.string().describe("Absolute path to the APK file"),
    smali_folder: z
      .string()
      .optional()
      .describe("Absolute path to apktool decompiled output folder (optional)"),
    min_length: z
      .number()
      .int()
      .min(4)
      .max(100)
      .default(8)
      .describe("Minimum string length for strings command (default 8)"),
  },

  handler: async (args: { apk_path: string; smali_folder?: string; min_length?: number }) => {
    const apk = checkInputFile(args.apk_path, "apk_path", [".apk"], { requireZipMagic: true });
    if (!apk.ok) return errorResult(apk.error);

    let smaliFolder: string | undefined;
    if (args.smali_folder) {
      const dir = checkInputDir(args.smali_folder, "smali_folder");
      if (!dir.ok) return errorResult(dir.error);
      smaliFolder = dir.path;
    }

    // Defense in depth: the schema already enforces an integer in [4, 100], but this
    // value is passed to an external program, so re-validate it here.
    const minLen = Number.isInteger(args.min_length) ? (args.min_length as number) : 8;
    if (minLen < 4 || minLen > 100) return errorResult("min_length must be an integer between 4 and 100.");

    let zip: ReturnType<typeof openZip>;
    try {
      zip = openZip(apk.path);
    } catch (e) {
      return { content: [{ type: "text" as const, text: `Error opening APK: ${e instanceof Error ? e.message : String(e)}` }] };
    }

    const lines: string[] = [`=== Android Secrets Scanner ===\n`];
    const allResults: ScanResults = new Map();

    const merge = (results: ScanResults) => mergeScanResults(allResults, results);

    if (smaliFolder) {
      // ── smali_folder path: plain text files ──────────────────────────────
      lines.push(`Mode: smali folder (${smaliFolder})\n`);

      // res/values/strings.xml
      const stringsXml = path.join(smaliFolder, "res", "values", "strings.xml");
      if (fs.existsSync(stringsXml)) {
        merge(scanText(fs.readFileSync(stringsXml, "utf-8"), SECRET_PATTERNS));
        lines.push(`  Scanned: res/values/strings.xml`);
      }

      // assets/**
      const assetsDir = path.join(smaliFolder, "assets");
      if (fs.existsSync(assetsDir)) {
        const assetFiles = walkDir(assetsDir).filter((f) =>
          TEXT_ASSET_EXTENSIONS.some((ext) => f.endsWith(ext))
        );
        for (const f of assetFiles) {
          try { merge(scanText(fs.readFileSync(f, "utf-8"), SECRET_PATTERNS)); } catch { /* skip */ }
        }
        lines.push(`  Scanned: assets/ (${assetFiles.length} files)`);
      }
      lines.push(``);
    } else {
      // ── Raw APK path: strings on binaries + text assets ───────────────────
      lines.push(`Mode: raw APK (strings on DEX + resources.arsc + text assets)\n`);

      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "apk-sec-"));
      try {
        // DEX files
        const dexEntries = zip.getEntries().filter(
          (e) => !e.isDirectory && /^classes\d*\.dex$/.test(e.entryName)
        );
        for (const entry of dexEntries) {
          const read = readEntry(entry);
          if (!read.ok) {
            lines.push(`  ${skippedPlaceholder(read.reason)}`);
            continue;
          }
          const tmp = path.join(tmpDir, entry.entryName);
          fs.writeFileSync(tmp, read.data);
          try {
            const out = run("strings", ["-a", "-n", String(minLen), tmp], { maxBuffer: 100 * 1024 * 1024 });
            merge(scanText(out, SECRET_PATTERNS));
          } catch { /* strings failed */ }
        }
        lines.push(`  Scanned: ${dexEntries.length} DEX file(s)`);

        // resources.arsc
        const arscEntry = zip.getEntry("resources.arsc");
        if (arscEntry) {
          const arscRead = readEntry(arscEntry);
          if (!arscRead.ok) {
            lines.push(`  ${skippedPlaceholder(arscRead.reason)}`);
          } else {
            const tmp = path.join(tmpDir, "resources.arsc");
            fs.writeFileSync(tmp, arscRead.data);
            try {
              const out = run("strings", ["-a", "-n", String(minLen), tmp], { maxBuffer: 50 * 1024 * 1024 });
              merge(scanText(out, SECRET_PATTERNS));
            } catch { /* strings failed */ }
            lines.push(`  Scanned: resources.arsc`);
          }
        }

        // Text assets inside ZIP
        let assetCount = 0;
        for (const entry of zip.getEntries()) {
          if (entry.isDirectory) continue;
          if (!entry.entryName.startsWith("assets/")) continue;
          if (!TEXT_ASSET_EXTENSIONS.some((ext) => entry.entryName.endsWith(ext))) continue;
          try {
            const read = readEntry(entry);
            if (read.ok) {
              merge(scanText(read.data.toString("utf-8"), SECRET_PATTERNS));
              assetCount++;
            } else {
              lines.push(`  ${skippedPlaceholder(read.reason)}`);
            }
          } catch { /* skip */ }
        }
        if (assetCount > 0) lines.push(`  Scanned: ${assetCount} text asset(s)`);
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
      lines.push(``);
    }

    // ── Results ───────────────────────────────────────────────────────────────
    if (allResults.size === 0) {
      lines.push(`✓ No secrets found.`);
    } else {
      lines.push(`--- Findings (${allResults.size} pattern type(s)) ---\n`);
      for (const line of renderResults(allResults)) lines.push(line);

      const critical = [...allResults.values()].filter((v) => v.def.risk === "CRITICAL");
      if (critical.length > 0) {
        lines.push(`\n⚠ ${critical.length} CRITICAL finding(s) — immediate review required.`);
      }
    }

    return { content: [{ type: "text" as const, text: lines.join("\n") }] };
  },
};

function walkDir(dir: string): string[] {
  const results: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) results.push(...walkDir(full));
    else if (entry.isFile()) results.push(full);
  }
  return results;
}
