import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { packageScriptRunsFromCi } from "./ci-script-coverage.mjs";

const frontendRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(frontendRoot, "..");

const removedGenericIpcBindings = ["InvokeBackendJSON", "InvokeBackendBlob", "InvokeBackendText"];
const removedAdapterTokens = ["createIpcBackendTransport"];

const requiredPackageScripts = {
  "desktop-generic-ipc-post-removal:check": "node scripts/check-desktop-generic-ipc-post-removal-monitor.mjs",
};

const requiredReadmeTokens = ["typed IPC", "generic_ipc_disabled", "browser-dev HTTP/SSE", "Wails runtime events"];

export function findDesktopGenericIpcPostRemovalMonitorViolations({
  rootDir = repoRoot,
  frontendDir = resolve(rootDir, "frontend"),
  trackerPath = resolve(rootDir, "docs/desktop-ipc-iteration-status.json"),
  packagePath = resolve(frontendDir, "package.json"),
  readmePath = resolve(rootDir, "README.md"),
} = {}) {
  const violations = [];
  validateProductionSource(rootDir, frontendDir, violations);
  validateReadme(readmePath, violations);
  validateTracker(trackerPath, violations);
  validatePackageScripts(packagePath, violations);
  return violations;
}

function validateProductionSource(rootDir, frontendDir, violations) {
  const removedAdapterPath = resolve(frontendDir, "src/app/integrations/ipcBackendTransport.ts");
  if (existsSync(removedAdapterPath)) {
    violations.push(
      "frontend/src/app/integrations/ipcBackendTransport.ts: legacy generic IPC adapter file must remain deleted",
    );
  }

  for (const file of collectProductionFiles(rootDir, frontendDir)) {
    const relativePath = relative(rootDir, file).replaceAll("\\", "/");
    const body = readFileSync(file, "utf8");
    for (const token of removedGenericIpcBindings) {
      if (containsToken(body, token)) {
        violations.push(`${relativePath}: removed generic IPC binding token ${token} must not reappear`);
      }
    }
    for (const token of removedAdapterTokens) {
      if (containsToken(body, token)) {
        violations.push(`${relativePath}: removed generic IPC adapter token ${token} must not reappear`);
      }
    }
  }
}

function collectProductionFiles(rootDir, frontendDir) {
  const files = [
    resolve(rootDir, "desktop_backend_proxy.go"),
    resolve(frontendDir, "wailsjs/go/main/DesktopApp.d.ts"),
    resolve(frontendDir, "wailsjs/go/main/DesktopApp.js"),
    ...listFiles(resolve(frontendDir, "src/app/integrations"), (entry) => {
      return entry.endsWith(".ts") && !entry.endsWith(".test.ts");
    }),
  ];
  return files.filter((file) => existsSync(file));
}

function listFiles(dir, predicate) {
  const files = [];
  if (!existsSync(dir)) {
    return files;
  }
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listFiles(path, predicate));
    } else if (entry.isFile() && predicate(path)) {
      files.push(path);
    }
  }
  return files;
}

function validateReadme(readmePath, violations) {
  if (!existsSync(readmePath)) {
    violations.push("README.md: missing current desktop IPC description");
    return;
  }
  const body = readFileSync(readmePath, "utf8");
  for (const token of removedGenericIpcBindings) {
    if (body.includes(token)) {
      violations.push(`README.md: stale removed binding reference ${token}`);
    }
  }
  for (const token of requiredReadmeTokens) {
    if (!body.includes(token)) {
      violations.push(`README.md: missing post-removal desktop IPC token ${token}`);
    }
  }
}

function validateTracker(trackerPath, violations) {
  const tracker = readJson(trackerPath, "docs/desktop-ipc-iteration-status.json", violations);
  if (!tracker) {
    return;
  }
  if (!Array.isArray(tracker.openBlockers) || tracker.openBlockers.length !== 0) {
    violations.push("docs/desktop-ipc-iteration-status.json: openBlockers must be an empty array");
  }

  const removal = tracker?.domains?.genericIpcAdapterRemovalPreflight;
  if (!removal) {
    violations.push("docs/desktop-ipc-iteration-status.json: missing genericIpcAdapterRemovalPreflight");
  } else {
    requireField(removal.status, "deletion-completed", "genericIpcAdapterRemovalPreflight.status", violations);
    requireField(removal.adapterRemoved, true, "genericIpcAdapterRemovalPreflight.adapterRemoved", violations);
    requireField(
      removal.frontendAdapterConstructionRemoved,
      true,
      "genericIpcAdapterRemovalPreflight.frontendAdapterConstructionRemoved",
      violations,
    );
    requireField(
      removal.backendGeneratedBindingsRemoved,
      true,
      "genericIpcAdapterRemovalPreflight.backendGeneratedBindingsRemoved",
      violations,
    );
  }

  const cleanup = tracker?.domains?.genericIpcBackendGeneratedBindingCleanupPreflight;
  if (!cleanup) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: missing genericIpcBackendGeneratedBindingCleanupPreflight",
    );
    return;
  }
  requireField(
    cleanup.status,
    "deletion-completed",
    "genericIpcBackendGeneratedBindingCleanupPreflight.status",
    violations,
  );
  requireField(
    cleanup.deletionReady,
    true,
    "genericIpcBackendGeneratedBindingCleanupPreflight.deletionReady",
    violations,
  );
  requireField(
    cleanup.backendGeneratedBindingsRemoved,
    true,
    "genericIpcBackendGeneratedBindingCleanupPreflight.backendGeneratedBindingsRemoved",
    violations,
  );

  const audit = cleanup.postRemovalAudit;
  if (!audit) {
    violations.push("docs/desktop-ipc-iteration-status.json: missing postRemovalAudit evidence");
    return;
  }
  requireField(audit.status, "completed", "postRemovalAudit.status", violations);
  requireField(audit.fullGatesRun, true, "postRemovalAudit.fullGatesRun", violations);
  requireField(audit.desktopWebviewSmokeRun, true, "postRemovalAudit.desktopWebviewSmokeRun", violations);
  requireField(audit.browserDevSmokeRun, true, "postRemovalAudit.browserDevSmokeRun", violations);

  const evidence = audit.evidence ?? {};
  requireField(
    evidence.directBackendApiRequestCount,
    0,
    "postRemovalAudit.evidence.directBackendApiRequestCount",
    violations,
  );
  requireField(
    evidence.totalInstrumentedNetworkRequests,
    0,
    "postRemovalAudit.evidence.totalInstrumentedNetworkRequests",
    violations,
  );
  requireField(evidence.genericIpcPolicy, "disabled", "postRemovalAudit.evidence.genericIpcPolicy", violations);
  requireField(
    evidence.genericIpcDisableExperimentBuildFlag,
    true,
    "postRemovalAudit.evidence.genericIpcDisableExperimentBuildFlag",
    violations,
  );
  requireField(evidence.browserDevOk, true, "postRemovalAudit.evidence.browserDevOk", violations);
}

function validatePackageScripts(packagePath, violations) {
  const manifest = readJson(packagePath, "frontend/package.json", violations);
  if (!manifest) {
    return;
  }
  for (const [name, command] of Object.entries(requiredPackageScripts)) {
    if (manifest.scripts?.[name] !== command) {
      violations.push(`frontend/package.json: missing script ${name} = ${command}`);
    }
  }
  const ci = String(manifest.scripts?.ci ?? "");
  for (const scriptName of Object.keys(requiredPackageScripts)) {
    if (!ci.includes(`pnpm run ${scriptName}`) && !packageScriptRunsFromCi(manifest, scriptName)) {
      violations.push(`frontend/package.json: ci must run ${scriptName}`);
    }
  }
}

function requireField(actual, expected, label, violations) {
  if (actual !== expected) {
    violations.push(`docs/desktop-ipc-iteration-status.json: ${label} must be ${JSON.stringify(expected)}`);
  }
}

function containsToken(body, token) {
  return new RegExp(`\\b${escapeRegex(token)}\\b`).test(body);
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function readJson(path, label, violations) {
  if (!existsSync(path)) {
    violations.push(`${label}: missing JSON source`);
    return undefined;
  }
  try {
    return JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, ""));
  } catch (error) {
    violations.push(`${label}: invalid JSON (${error instanceof Error ? error.message : String(error)})`);
    return undefined;
  }
}

function runCli() {
  const violations = findDesktopGenericIpcPostRemovalMonitorViolations();
  if (violations.length === 0) {
    console.log("Desktop generic IPC post-removal monitor check passed.");
    return;
  }
  console.error("Desktop generic IPC post-removal monitor violations:");
  for (const violation of violations) {
    console.error(`- ${violation}`);
  }
  process.exit(1);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli();
}
