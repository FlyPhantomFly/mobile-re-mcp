#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { z } from "zod";
import { createRequire } from "node:module";

import { androidApiExtractor } from "./tools/android/api-extractor.js";
import { apkManifestAnalyzer } from "./tools/android/manifest-analyzer.js";
import { apkPermissionsChecker } from "./tools/android/permissions-checker.js";
import { androidGoogleServices } from "./tools/android/google-services.js";
import { androidSecretsScanner } from "./tools/android/secrets-scanner.js";
import { iosManifestAnalyzer } from "./tools/ios/manifest-analyzer.js";
import { iosPermissionsChecker } from "./tools/ios/permissions-checker.js";
import { iosEntitlementsChecker } from "./tools/ios/entitlements-checker.js";
import { iosBinaryStrings } from "./tools/ios/binary-strings.js";
import { iosFrameworksDetector } from "./tools/ios/frameworks-detector.js";
import { iosGoogleServices } from "./tools/ios/google-services.js";
import { iosSecretsScanner } from "./tools/ios/secrets-scanner.js";

// Single source of truth for the version: package.json (always shipped in the npm package).
const { version } = createRequire(import.meta.url)("../package.json") as { version: string };

// MCP SDK v2: tool input schemas are full schema objects (z.object), not raw shapes.
// Each tool module still exports a raw shape in `schema`; it is wrapped here.
function createServer(): McpServer {
  const server = new McpServer({
    name: "mobile-re-mcp",
    version,
  });

  // Android tools
  server.registerTool(
    "android_api_extractor",
    {
      description: androidApiExtractor.description,
      inputSchema: z.object(androidApiExtractor.schema),
    },
    androidApiExtractor.handler
  );

  server.registerTool(
    "apk_manifest_analyzer",
    {
      description: apkManifestAnalyzer.description,
      inputSchema: z.object(apkManifestAnalyzer.schema),
    },
    apkManifestAnalyzer.handler
  );

  server.registerTool(
    "apk_permissions_checker",
    {
      description: apkPermissionsChecker.description,
      inputSchema: z.object(apkPermissionsChecker.schema),
    },
    apkPermissionsChecker.handler
  );

  server.registerTool(
    "android_google_services",
    {
      description: androidGoogleServices.description,
      inputSchema: z.object(androidGoogleServices.schema),
    },
    androidGoogleServices.handler
  );

  server.registerTool(
    "android_secrets_scanner",
    {
      description: androidSecretsScanner.description,
      inputSchema: z.object(androidSecretsScanner.schema),
    },
    androidSecretsScanner.handler
  );

  // iOS tools
  server.registerTool(
    "ios_manifest_analyzer",
    {
      description: iosManifestAnalyzer.description,
      inputSchema: z.object(iosManifestAnalyzer.schema),
    },
    iosManifestAnalyzer.handler
  );

  server.registerTool(
    "ios_permissions_checker",
    {
      description: iosPermissionsChecker.description,
      inputSchema: z.object(iosPermissionsChecker.schema),
    },
    iosPermissionsChecker.handler
  );

  server.registerTool(
    "ios_entitlements_checker",
    {
      description: iosEntitlementsChecker.description,
      inputSchema: z.object(iosEntitlementsChecker.schema),
    },
    iosEntitlementsChecker.handler
  );

  server.registerTool(
    "ios_binary_strings",
    {
      description: iosBinaryStrings.description,
      inputSchema: z.object(iosBinaryStrings.schema),
    },
    iosBinaryStrings.handler
  );

  server.registerTool(
    "ios_frameworks_detector",
    {
      description: iosFrameworksDetector.description,
      inputSchema: z.object(iosFrameworksDetector.schema),
    },
    iosFrameworksDetector.handler
  );

  server.registerTool(
    "ios_google_services",
    {
      description: iosGoogleServices.description,
      inputSchema: z.object(iosGoogleServices.schema),
    },
    iosGoogleServices.handler
  );

  server.registerTool(
    "ios_secrets_scanner",
    {
      description: iosSecretsScanner.description,
      inputSchema: z.object(iosSecretsScanner.schema),
    },
    iosSecretsScanner.handler
  );

  return server;
}

// stdout is the JSON-RPC channel: log to stderr only.
const handle = serveStdio(() => createServer());

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    void handle.close().finally(() => process.exit(0));
  });
}
