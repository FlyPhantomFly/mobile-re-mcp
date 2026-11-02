import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

/**
 * Safe process execution and input-path validation shared by the tools.
 *
 * Why this exists: tool arguments (apk_path, smali_folder, ...) are chosen by an
 * LLM and can therefore be influenced by prompt injection from the content being
 * analyzed. They must never be interpolated into a shell command line. Everything
 * here uses execFileSync (no shell), and every path is validated before use.
 */

const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;
const DEFAULT_MAX_BUFFER = 100 * 1024 * 1024;

export interface RunOptions {
  maxBuffer?: number;
  timeoutMs?: number;
}

/**
 * Run an external program WITHOUT a shell. Arguments are passed as an array, so
 * shell metacharacters ($(), backticks, quotes, ;, |, &) in any argument have no
 * special meaning. Returns stdout as a string; throws on non-zero exit / timeout.
 */
export function run(command: string, args: string[], options: RunOptions = {}): string {
  return execFileSync(command, args, {
    stdio: ["ignore", "pipe", "pipe"],
    shell: false,
    windowsHide: true,
    encoding: "utf-8",
    maxBuffer: options.maxBuffer ?? DEFAULT_MAX_BUFFER,
    timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
  });
}

export type PathCheck = { ok: true; path: string } | { ok: false; error: string };

/**
 * Optional sandbox: set MOBILE_RE_MCP_ALLOWED_DIRS to a path-delimited list
 * (":" on macOS/Linux, ";" on Windows) and the tools will refuse to read anything
 * outside those directories. Unset = no directory restriction.
 */
function allowedRoots(): string[] | null {
  const raw = process.env.MOBILE_RE_MCP_ALLOWED_DIRS;
  if (!raw) return null;
  const roots: string[] = [];
  for (const part of raw.split(path.delimiter)) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    try {
      roots.push(fs.realpathSync(trimmed));
    } catch {
      roots.push(path.resolve(trimmed));
    }
  }
  return roots.length > 0 ? roots : null;
}

function isInside(root: string, target: string): boolean {
  const rel = path.relative(root, target);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function checkAllowed(realPath: string, label: string): PathCheck | null {
  const roots = allowedRoots();
  if (roots && !roots.some((r) => isInside(r, realPath))) {
    return {
      ok: false,
      error: `${label} is outside the directories allowed by MOBILE_RE_MCP_ALLOWED_DIRS: ${realPath}`,
    };
  }
  return null;
}

function baseChecks(input: string, label: string): PathCheck | null {
  if (input.includes("\0")) {
    return { ok: false, error: `${label} contains an invalid character` };
  }
  if (!path.isAbsolute(input)) {
    return { ok: false, error: `${label} must be an absolute path: ${input}` };
  }
  return null;
}

/**
 * Validate a user-supplied input file: absolute, exists, regular file, expected
 * extension, (optionally) ZIP magic bytes, and inside the allowed directories.
 * Returns the symlink-resolved path, which is what callers should use.
 */
export function checkInputFile(
  input: string,
  label: string,
  extensions: string[],
  options: { requireZipMagic?: boolean } = {}
): PathCheck {
  const early = baseChecks(input, label);
  if (early) return early;

  let real: string;
  try {
    real = fs.realpathSync(input);
  } catch {
    return { ok: false, error: `${label} not found: ${input}` };
  }

  let stat: fs.Stats;
  try {
    stat = fs.statSync(real);
  } catch {
    return { ok: false, error: `${label} not readable: ${input}` };
  }
  if (!stat.isFile()) {
    return { ok: false, error: `${label} is not a regular file: ${input}` };
  }

  const ext = path.extname(real).toLowerCase();
  if (!extensions.includes(ext)) {
    return {
      ok: false,
      error: `${label} must have one of these extensions: ${extensions.join(", ")} (got "${ext || "none"}")`,
    };
  }

  if (options.requireZipMagic) {
    try {
      const fd = fs.openSync(real, "r");
      try {
        const buf = Buffer.alloc(4);
        fs.readSync(fd, buf, 0, 4, 0);
        // "PK\x03\x04" (local file header) or "PK\x05\x06" (empty archive)
        const ok = buf[0] === 0x50 && buf[1] === 0x4b && (buf[2] === 0x03 || buf[2] === 0x05);
        if (!ok) return { ok: false, error: `${label} is not a ZIP/APK archive: ${input}` };
      } finally {
        fs.closeSync(fd);
      }
    } catch {
      return { ok: false, error: `${label} not readable: ${input}` };
    }
  }

  return checkAllowed(real, label) ?? { ok: true, path: real };
}

/** Validate a user-supplied input directory (e.g. an apktool output folder). */
export function checkInputDir(input: string, label: string): PathCheck {
  const early = baseChecks(input, label);
  if (early) return early;

  let real: string;
  try {
    real = fs.realpathSync(input);
  } catch {
    return { ok: false, error: `${label} not found: ${input}` };
  }

  try {
    if (!fs.statSync(real).isDirectory()) {
      return { ok: false, error: `${label} is not a directory: ${input}` };
    }
  } catch {
    return { ok: false, error: `${label} not readable: ${input}` };
  }

  return checkAllowed(real, label) ?? { ok: true, path: real };
}

export function errorResult(message: string) {
  return { content: [{ type: "text" as const, text: `Error: ${message}` }] };
}

/** Escape a string so it matches literally inside a RegExp (for data read from untrusted files). */
export function escapeRegExp(value: string): string {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
