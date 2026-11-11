#!/usr/bin/env node
/**
 * Interactive smoke runner — calls every file-reading tool against
 * example.apk / example.ipa in the repo root.
 *
 * The committed regression suite is `npm test` (node --test, hermetic,
 * no fixtures needed). This script is the human-readable companion:
 * without the fixture files it prints the full tool inventory and exits
 * cleanly; with them it runs every tool that has a matching fixture.
 */
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { existsSync } from "fs";
import { fileURLToPath } from "url";
import path from "path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.join(__dirname, "dist/index.js");
const APK = path.join(__dirname, "example.apk");
const IPA = path.join(__dirname, "example.ipa");

const SEP = "═".repeat(70);

function header(title) {
  console.log(`\n${SEP}`);
  console.log(`  ${title}`);
  console.log(SEP);
}

function result(text) {
  const lines = String(text).split("\n");
  console.log(lines.slice(0, 60).join("\n"));
  if (lines.length > 60) console.log(`\n  … [${lines.length - 60} more lines truncated]`);
}

// Which fixture each tool needs. Tools not listed here (e.g. apk_diff,
// which needs TWO fixtures) run when their fixture(s) exist.
const TOOL_FIXTURES = {
  android_api_extractor: { apk_path: APK },
  apk_manifest_analyzer: { apk_path: APK },
  apk_permissions_checker: { apk_path: APK },
  android_google_services: { apk_path: APK },
  android_secrets_scanner: { apk_path: APK },
  android_native_libraries: { apk_path: APK },
  ios_manifest_analyzer: { ipa_path: IPA },
  ios_permissions_checker: { ipa_path: IPA },
  ios_entitlements_checker: { ipa_path: IPA },
  ios_binary_strings: { ipa_path: IPA },
  ios_frameworks_detector: { ipa_path: IPA },
  ios_google_services: { ipa_path: IPA },
  ios_secrets_scanner: { ipa_path: IPA },
};

const EXTRA_CALLS = [
  ["android_api_extractor (postman)", "android_api_extractor",
   { apk_path: APK, output_format: "postman" }],
  ["ios_binary_strings (filter: url)", "ios_binary_strings",
   { ipa_path: IPA, filter: "url", min_length: 8 }],
];

async function main() {
  header("mobile-re-mcp smoke");
  console.log("Connecting to the npm server…");

  const transport = new StdioClientTransport({ command: "node", args: [SERVER] });
  const client = new Client({ name: "smoke-client", version: "1.0.0" });
  await client.connect(transport);

  const { tools } = await client.listTools();
  console.log(`\nServer started. ${tools.length} tools registered:`);
  for (const t of tools) console.log(`  • ${t.name}`);

  const call = async (name, args) => {
    try {
      const res = await client.callTool({ name, arguments: args });
      return res.content?.[0]?.text ?? JSON.stringify(res);
    } catch (e) {
      return `ERROR: ${e.message}`;
    }
  };

  const missingFixtures = [
    !existsSync(APK) && APK,
    !existsSync(IPA) && IPA,
  ].filter(Boolean);

  if (missingFixtures.length > 0) {
    console.log(
      `\nSkipping per-tool calls — fixture file(s) not present:\n` +
      missingFixtures.map((f) => `  ${f}`).join("\n") +
      `\n\nDrop an example.apk / example.ipa in the repo root to smoke-run ` +
      `every tool, or use the hermetic suite: npm test`
    );
    await client.close();
    return;
  }

  let ran = 0;
  for (const t of tools) {
    const args = TOOL_FIXTURES[t.name];
    if (!args) {
      console.log(`\n[skip] ${t.name} — no fixture recipe in this script`);
      continue;
    }
    header(t.name);
    result(await call(t.name, args));
    ran++;
  }
  for (const [label, name, args] of EXTRA_CALLS) {
    header(label);
    result(await call(name, args));
  }

  console.log(`\n${SEP}`);
  console.log(`  Smoke done: ${ran}/${tools.length} tools called against real fixtures.`);
  console.log(SEP);

  await client.close();
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
