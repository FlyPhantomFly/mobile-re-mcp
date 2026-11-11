import * as fs from "fs";
import AdmZip from "adm-zip";
import type { IZipEntry } from "adm-zip";

/**
 * Size-limited, failure-normalized zip access shared by every APK/IPA tool.
 *
 * Why this exists (F-NPM-4): adm-zip's entry.getData() fully decompresses
 * before any size check — a crafted, small, highly compressed archive can
 * OOM the server. Caps come from env so a user can tune them:
 *
 *   MOBILE_RE_MCP_MAX_FILE_MB   input APK/IPA cap (default 2048)
 *   MOBILE_RE_MCP_MAX_ENTRY_MB  one decompressed entry cap (default 256)
 *
 * A value of 0 disables the corresponding cap.
 */

const DEFAULT_MAX_FILE_MB = 2048;
const DEFAULT_MAX_ENTRY_MB = 256;
const MB = 1024 * 1024;

/** Env override: integer MB, `0` disables, invalid → default. */
export function envMaxMb(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 0) return fallback;
  return parsed;
}

export function maxFileMb(): number {
  return envMaxMb("MOBILE_RE_MCP_MAX_FILE_MB", DEFAULT_MAX_FILE_MB);
}

export function maxEntryMb(): number {
  return envMaxMb("MOBILE_RE_MCP_MAX_ENTRY_MB", DEFAULT_MAX_ENTRY_MB);
}

export class PayloadTooLargeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PayloadTooLargeError";
  }
}

/** Refuse an obviously oversized input APK/IPA before touching the zip. */
export function checkPayloadSize(filePath: string): void {
  const capMb = maxFileMb();
  if (capMb <= 0) return;
  let bytes = 0;
  try {
    bytes = fs.statSync(filePath).size;
  } catch {
    return; // missing file handled by the caller's own checks
  }
  if (bytes > capMb * MB) {
    throw new PayloadTooLargeError(
      `input file is ${(bytes / MB).toFixed(1)} MB, above the ${capMb} MB cap ` +
        `(raise MOBILE_RE_MCP_MAX_FILE_MB, or set it to 0 to disable the cap)`
    );
  }
}

/** Open an APK/IPA with a normalized error message. */
export function openZip(filePath: string): AdmZip {
  checkPayloadSize(filePath);
  try {
    return new AdmZip(filePath);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`cannot open ${filePath} as a zip archive: ${msg}`);
  }
}

export type EntryRead =
  | { ok: true; data: Buffer }
  | { ok: false; skipped: true; reason: string };

/**
 * Decompress one entry under MOBILE_RE_MCP_MAX_ENTRY_MB.
 *
 * The uncompressed size is read from the local entry header BEFORE any
 * decompression. Skipped entries return {ok:false, skipped:true, reason}
 * so a caller scanning many files can substitute visible text like
 * "[skipped: too large]" instead of failing the whole tool; single-entry
 * callers should treat a skip as a hard error.
 */
export function readEntry(entry: IZipEntry): EntryRead {
  const capMb = maxEntryMb();
  if (capMb > 0) {
    const compressed = Number(entry.header.compressedSize) || 0;
    const declared = Number(entry.header.size) || 0; // uncompressed size
    if (compressed > capMb * MB || declared > capMb * MB) {
      return {
        ok: false,
        skipped: true,
        reason:
          `entry '${entry.entryName}' declares ${(
            (declared || compressed) / MB
          ).toFixed(1)} MB uncompressed, above the ${capMb} MB cap ` +
          `(raise MOBILE_RE_MCP_MAX_ENTRY_MB, or set it to 0 to disable the cap)`,
      };
    }
  }
  try {
    return { ok: true, data: entry.getData() };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { ok: false, skipped: true, reason: `entry '${entry.entryName}' could not be read: ${msg}` };
  }
}

/** Unwrap a skip as a thrown error (single-entry callers). */
export function requireEntryData(entry: IZipEntry): Buffer {
  const read = readEntry(entry);
  if (read.ok) return read.data;
  throw new PayloadTooLargeError(read.reason);
}

/** Substitute text a scanning caller embeds for skipped entries. */
export function skippedPlaceholder(reason: string): string {
  return `[skipped: ${reason}]`;
}
