import { z } from "zod";
import { run, checkInputFile, errorResult } from "../shared/safe-exec.js";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

export const apkManifestAnalyzer = {
  description:
    "Parses AndroidManifest.xml from an APK. Extracts package info, activities, services, receivers, intent filters, and highlights security-relevant flags like exported components, debuggable, and allowBackup.",

  schema: {
    apk_path: z
      .string()
      .describe("Absolute path to the APK file to analyze"),
  },

  handler: async (args: { apk_path: string }) => {
    const apk = checkInputFile(args.apk_path, "apk_path", [".apk"], { requireZipMagic: true });
    if (!apk.ok) return errorResult(apk.error);
    const apkPath = apk.path;

    // Try aapt first (faster, no full decompile needed), then aapt2, then
    // apktool. If a tool prints something we cannot read, try the next
    // before giving up — aapt2-only machines no longer pay the apktool cost.
    let source = "aapt";
    let manifestText = extractManifestViaAapt(apkPath);
    let root = manifestText ? parseManifest(manifestText) : null;

    if (!root) {
      source = "aapt2";
      manifestText = extractManifestViaAapt2(apkPath);
      root = manifestText ? parseManifest(manifestText) : null;
    }

    if (!root) {
      source = "apktool";
      manifestText = extractManifestViaApktool(apkPath);
      root = manifestText ? parseManifest(manifestText) : null;
    }

    if (!root) {
      return errorResult(
        "Could not read AndroidManifest.xml. Install aapt/aapt2 (Android build-tools) or apktool and make sure it is on PATH."
      );
    }

    return { content: [{ type: "text" as const, text: analyzeManifest(root, source) }] };
  },
};

function extractManifestViaAapt(apkPath: string): string | null {
  try {
    return run("aapt", ["dump", "xmltree", apkPath, "AndroidManifest.xml"]);
  } catch {
    return null;
  }
}

function extractManifestViaAapt2(apkPath: string): string | null {
  try {
    return run("aapt2", ["dump", "xmltree", "--file", "AndroidManifest.xml", apkPath]);
  } catch {
    return null;
  }
}

function extractManifestViaApktool(apkPath: string): string | null {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "apktool-manifest-"));
  try {
    run("apktool", ["d", apkPath, "-o", tmpDir, "-f"]);
    const manifestPath = path.join(tmpDir, "AndroidManifest.xml");
    if (fs.existsSync(manifestPath)) {
      return fs.readFileSync(manifestPath, "utf-8");
    }
    return null;
  } catch {
    return null;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// Parsing. aapt (v1), aapt2 and apktool all print the manifest differently.
// ---------------------------------------------------------------------------

export interface ManifestNode {
  tag: string;
  attrs: Record<string, string>;
  children: ManifestNode[];
}

/** Turn aapt, aapt2 or apktool output into a tree. Returns null if no <manifest> element is found. */
export function parseManifest(text: string): ManifestNode | null {
  const root = /^\s*E: /m.test(text) ? parseAaptTree(text) : parseXml(text);
  return root && root.tag === "manifest" ? root : null;
}

function normalizeKey(raw: string): string {
  const key = raw.trim();
  const ns = key.match(/^https?:\/\/[^\s]*?\/res\/android:([\w.-]+)$/);
  if (ns) return `android:${ns[1]}`;
  const other = key.match(/^https?:\/\/[^\s]*:([\w.-]+)$/);
  return other ? other[1] : key;
}

function normalizeAaptValue(raw: string): string {
  const value = raw.trim();
  const quoted = value.match(/^"((?:[^"\\]|\\.)*)"/);
  if (quoted) return quoted[1];
  const typed = value.match(/^\(type (0x[0-9a-fA-F]+)\)(0x[0-9a-fA-F]+)/);
  if (typed) {
    const [, type, hex] = typed;
    const n = parseInt(hex, 16);
    if (type === "0x12") return n === 0 ? "false" : "true"; // boolean, true is 0xffffffff
    if (type === "0x10") return String(n); // decimal integer
    if (type === "0x1") return `@${hex}`; // resource reference
    return hex;
  }
  return value.replace(/\s+\(Raw:.*\)$/, "");
}

function parseAaptTree(text: string): ManifestNode | null {
  const stack: { node: ManifestNode; indent: number }[] = [];
  let root: ManifestNode | null = null;
  for (const line of text.split(/\r?\n/)) {
    const element = line.match(/^(\s*)E: ([\w:.-]+)/);
    if (element) {
      const node: ManifestNode = { tag: element[2], attrs: {}, children: [] };
      const indent = element[1].length;
      while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop();
      if (stack.length) stack[stack.length - 1].node.children.push(node);
      else if (!root) root = node;
      stack.push({ node, indent });
      continue;
    }
    const attr = line.match(/^\s*A: ([^=(]+?)(?:\(0x[0-9a-fA-F]+\))?=(.*)$/);
    if (attr && stack.length) {
      stack[stack.length - 1].node.attrs[normalizeKey(attr[1])] = normalizeAaptValue(attr[2]);
    }
  }
  return root;
}

function parseXml(text: string): ManifestNode | null {
  const stack: ManifestNode[] = [];
  let root: ManifestNode | null = null;
  const tagPattern = /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<(\/?)([\w:.-]+)((?:\s+[\w:.-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>/g;
  for (const m of text.matchAll(tagPattern)) {
    if (!m[2]) continue; // comment or declaration
    if (m[1]) {
      stack.pop();
      continue;
    }
    const attrs: Record<string, string> = {};
    for (const a of m[3].matchAll(/([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) {
      attrs[a[1]] = a[2] ?? a[3];
    }
    const node: ManifestNode = { tag: m[2], attrs, children: [] };
    if (stack.length) stack[stack.length - 1].children.push(node);
    else if (!root) root = node;
    if (!m[4]) stack.push(node);
  }
  return root;
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

const COMPONENT_TAGS = ["activity", "activity-alias", "service", "receiver", "provider"] as const;

function fullName(name: string | undefined, pkg: string): string {
  if (!name) return "(unnamed)";
  if (name.startsWith(".")) return pkg + name;
  if (!name.includes(".")) return pkg ? `${pkg}.${name}` : name;
  return name;
}

function listNames(names: string[]): string {
  const shown = names.slice(0, 5).join(", ");
  return names.length > 5 ? `${shown} … +${names.length - 5} more` : shown;
}

export function analyzeManifest(root: ManifestNode, source: string): string {
  const lines: string[] = [];
  const warnings: string[] = [];
  const pkg = root.attrs["package"] ?? "";

  lines.push(`=== Android Manifest Analysis ===`);
  lines.push(`Source: ${source}\n`);

  if (pkg) lines.push(`Package Name : ${pkg}`);
  const versionCode = root.attrs["android:versionCode"];
  const versionName = root.attrs["android:versionName"];
  if (versionCode) lines.push(`Version Code : ${versionCode}`);
  if (versionName) lines.push(`Version Name : ${versionName}`);

  // Security flags on <application>
  const app = root.children.find((c) => c.tag === "application");
  const flag = (name: string) => (app?.attrs[`android:${name}`] ?? "").toLowerCase() === "true";
  const debuggable = flag("debuggable");
  const allowBackup = flag("allowBackup");
  const cleartext = flag("usesCleartextTraffic");
  const networkSecurity = Boolean(app?.attrs["android:networkSecurityConfig"]);

  lines.push(`\n--- Security Flags ---`);
  lines.push(`  debuggable          : ${debuggable ? "TRUE  ⚠ DANGER" : "false"}`);
  lines.push(`  allowBackup         : ${allowBackup ? "TRUE  ⚠ WARNING" : "false"}`);
  lines.push(`  usesCleartextTraffic: ${cleartext ? "TRUE  ⚠ DANGER" : "false"}`);
  lines.push(`  networkSecurityConfig: ${networkSecurity ? "present" : "not set"}`);

  if (debuggable) warnings.push("debuggable=true — app can be attached with a debugger in production");
  if (allowBackup) warnings.push("allowBackup=true — app data can be extracted via adb backup without root");
  if (cleartext) warnings.push("usesCleartextTraffic=true — app allows unencrypted HTTP traffic");

  // Components
  const components = (app?.children ?? []).filter((c) => (COMPONENT_TAGS as readonly string[]).includes(c.tag));
  const named = (tags: string[]) =>
    components.filter((c) => tags.includes(c.tag)).map((c) => fullName(c.attrs["android:name"], pkg));
  const activities = named(["activity", "activity-alias"]);
  const services = named(["service"]);
  const receivers = named(["receiver"]);
  const providers = named(["provider"]);

  lines.push(`\n--- Components ---`);
  lines.push(`  Activities (${activities.length}): ${listNames(activities)}`);
  lines.push(`  Services   (${services.length}): ${listNames(services)}`);
  lines.push(`  Receivers  (${receivers.length}): ${listNames(receivers)}`);
  lines.push(`  Providers  (${providers.length}): ${listNames(providers)}`);

  // Exported components: explicit android:exported="true"
  const hasIntentFilter = (c: ManifestNode) => c.children.some((x) => x.tag === "intent-filter");
  const exported = components.filter((c) => (c.attrs["android:exported"] ?? "").toLowerCase() === "true");
  // Exported by default: an intent filter and no android:exported attribute (apps targeting Android 11 or lower)
  const exportedByDefault = components.filter(
    (c) => c.attrs["android:exported"] === undefined && hasIntentFilter(c) && c.tag !== "provider"
  );

  lines.push(`\n--- Exported Components (android:exported="true") ---`);
  if (exported.length === 0) {
    lines.push(`  None detected`);
  } else {
    lines.push(`  ⚠ ${exported.length} exported component(s):`);
    for (const c of exported) lines.push(`    - ${fullName(c.attrs["android:name"], pkg)} (${c.tag})`);
    warnings.push(`${exported.length} component(s) with android:exported="true" — potential attack surface`);
  }

  if (exportedByDefault.length > 0) {
    lines.push(`\n--- Exported by default (intent filter, no android:exported) ---`);
    for (const c of exportedByDefault) lines.push(`    - ${fullName(c.attrs["android:name"], pkg)} (${c.tag})`);
    warnings.push(
      `${exportedByDefault.length} component(s) have an intent filter and no android:exported, so they are exported on apps targeting Android 11 or lower`
    );
  }

  // Intent filter actions
  const actions: string[] = [];
  for (const c of components) {
    for (const f of c.children.filter((x) => x.tag === "intent-filter")) {
      for (const a of f.children.filter((x) => x.tag === "action")) {
        if (a.attrs["android:name"]) actions.push(a.attrs["android:name"]);
      }
    }
  }
  if (actions.length > 0) {
    lines.push(`\n--- Intent Filters (${actions.length} actions) ---`);
    for (const action of [...new Set(actions)].slice(0, 15)) lines.push(`    - ${action}`);
  }

  // Summary
  if (warnings.length > 0) {
    lines.push(`\n=== Security Warnings ===`);
    for (const w of warnings) lines.push(`  ⚠ ${w}`);
  } else {
    lines.push(`\n✓ No critical manifest security issues detected.`);
  }

  return lines.join("\n");
}
