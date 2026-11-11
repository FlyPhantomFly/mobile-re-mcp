import * as fs from "fs";
import * as path from "path";
import AdmZip from "adm-zip";
import type { IZipEntry } from "adm-zip";
import { escapeRegExp } from "../shared/safe-exec.js";
import { requireEntryData } from "../shared/zip.js";
import { parsePlistBuffer } from "./manifest-analyzer.js";

/**
 * The single implementation for locating (and optionally writing out) the
 * main executable inside an IPA's Payload/<App>.app directory.
 *
 * Why this exists (F-NPM-3): binary-strings, entitlements-checker and
 * secrets-scanner each carried a copy-pasted extractor whose resource
 * exclusion lists had drifted from each other, so the same IPA could
 * yield a different "binary" to different tools. One canonical list here.
 */

/**
 * Root-of-.app entries that are never the main executable. Union of the
 * three previously drifted lists:
 *   binary-strings:        plist|nib|car|strings|png|jpg|lproj|storyboard
 *   entitlements-checker:  plist|nib|car|strings
 *   secrets-scanner:       plist|nib|car|strings|png|jpg|json|dylib
 */
const NOT_BINARY_SUFFIXES = [
  ".plist", ".nib", ".car", ".strings", ".png", ".jpg", ".json",
  ".dylib", ".lproj", ".storyboard",
];

function looksLikeBinary(entryName: string): boolean {
  const lower = entryName.toLowerCase();
  return !NOT_BINARY_SUFFIXES.some((s) => lower.endsWith(s));
}

function bundleExecutable(entry: IZipEntry | undefined): string | null {
  if (!entry) return null;
  try {
    const parsed = parsePlistBuffer(requireEntryData(entry));
    return (parsed["CFBundleExecutable"] as string | null) ?? null;
  } catch {
    return null;
  }
}

/**
 * Locate the main executable entry: the file named by Info.plist's
 * CFBundleExecutable, else the single extension-less root file of the
 * .app directory. Returns null when neither applies.
 */
export function resolveBinaryEntry(zip: AdmZip): IZipEntry | null {
  const entries = zip.getEntries();

  const plistEntry = entries.find((e) =>
    /^Payload\/[^/]+\.app\/Info\.plist$/.test(e.entryName)
  );
  const executableName = bundleExecutable(plistEntry);

  if (executableName) {
    const named = entries.find((e) =>
      new RegExp(`^Payload/[^/]+\\.app/${escapeRegExp(executableName)}$`).test(e.entryName)
    );
    if (named) return named;
  }

  return (
    entries.find(
      (e) =>
        /^Payload\/[^/]+\.app\/[^/]+$/.test(e.entryName) && looksLikeBinary(e.entryName)
    ) ?? null
  );
}

/** Extract the main executable into outDir as "binary"; returns the path or null. */
export function writeBinary(zip: AdmZip, outDir: string): string | null {
  const binaryEntry = resolveBinaryEntry(zip);
  if (!binaryEntry) return null;
  const outPath = path.join(outDir, "binary");
  fs.writeFileSync(outPath, requireEntryData(binaryEntry));
  return outPath;
}

/** The main executable's bytes, or null when not found. */
export function readBinary(zip: AdmZip): Buffer | null {
  const binaryEntry = resolveBinaryEntry(zip);
  return binaryEntry ? requireEntryData(binaryEntry) : null;
}
