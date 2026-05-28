import { existsSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const frontendRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(frontendRoot, "..");

const genericMethods = ["InvokeBackendJSON", "InvokeBackendBlob", "InvokeBackendText"];

const requiredPackageScripts = {
  "desktop-generic-ipc-binding-cleanup-preflight:check":
    "node scripts/check-desktop-generic-ipc-binding-cleanup-preflight.mjs",
};

const requiredPlanTokens = [
  "backend/generated generic IPC binding cleanup",
  "deletionReady = true",
  "typed helper reuse",
  "check-wails-bindings",
  "removed InvokeBackendJSON",
  "removed InvokeBackendBlob",
  "removed InvokeBackendText",
  "desktopDisabledGenericIpcTransport.ts",
];

export function findDesktopGenericIpcBindingCleanupPreflightViolations({
  rootDir = repoRoot,
  frontendDir = resolve(rootDir, "frontend"),
  trackerPath = resolve(rootDir, "docs/desktop-ipc-iteration-status.json"),
  migrationPlanPath = resolve(rootDir, "docs/desktop-ipc-migration-plan.md"),
  exitPlanPath = resolve(rootDir, "docs/desktop-ipc-old-binding-exit-plan.md"),
  packagePath = resolve(frontendDir, "package.json"),
} = {}) {
  const violations = [];
  const facts = collectBindingCleanupFacts({ rootDir, frontendDir, violations });
  validateTracker(trackerPath, facts, violations);
  validatePlanTokens(migrationPlanPath, "docs/desktop-ipc-migration-plan.md", violations);
  validatePlanTokens(exitPlanPath, "docs/desktop-ipc-old-binding-exit-plan.md", violations);
  validatePackageScripts(packagePath, violations);
  return violations;
}

export function collectBindingCleanupFacts({ rootDir = repoRoot, frontendDir = resolve(rootDir, "frontend") } = {}) {
  const backendPath = resolve(rootDir, "desktop_backend_proxy.go");
  const backendTestPath = resolve(rootDir, "desktop_backend_proxy_test.go");
  const generatedDtsPath = resolve(frontendDir, "wailsjs/go/main/DesktopApp.d.ts");
  const generatedJsPath = resolve(frontendDir, "wailsjs/go/main/DesktopApp.js");
  const bindingShellPath = resolve(frontendDir, "src/app/integrations/desktopTransportBindingShell.ts");
  const ipcTransportPath = resolve(frontendDir, "src/app/integrations/ipcBackendTransport.ts");
  const disabledTransportPath = resolve(frontendDir, "src/app/integrations/desktopDisabledGenericIpcTransport.ts");
  const controlsPath = resolve(frontendDir, "src/app/integrations/desktopIpcControls.ts");
  const desktopBridgePath = resolve(frontendDir, "src/app/integrations/desktopBridge.ts");
  const wailsBindingCheckPath = resolve(frontendDir, "scripts/check-wails-bindings.mjs");
  const oldBindingCompatPath = resolve(frontendDir, "scripts/check-desktop-old-binding-compat.mjs");

  const backendBody = readText(backendPath);
  const backendTestBody = readText(backendTestPath);
  const generatedDts = readText(generatedDtsPath);
  const generatedJs = readText(generatedJsPath);
  const bindingShell = readText(bindingShellPath);
  const ipcTransport = readText(ipcTransportPath);
  const disabledTransport = readText(disabledTransportPath);
  const controls = readText(controlsPath);
  const desktopBridge = readText(desktopBridgePath);
  const wailsBindingCheck = readText(wailsBindingCheckPath);
  const oldBindingCompat = readText(oldBindingCompatPath);

  return {
    backendExportedMethods: genericMethods.filter((method) =>
      new RegExp(`func \\(a \\*DesktopApp\\) ${method}\\b`).test(backendBody),
    ),
    typedHelperReuse: extractTypedHelperReuse(backendBody),
    backendProxyTestsDirectHelpers: extractDirectHelperTestUses(backendTestBody),
    generatedBindings: [
      ...extractGeneratedBindings(generatedDts, generatedDtsPath, rootDir),
      ...extractGeneratedBindings(generatedJs, generatedJsPath, rootDir),
    ],
    frontendBindingSurfaces: [
      ...extractShellBindingFields(bindingShell, bindingShellPath, rootDir),
      ...extractIpcTransportSurface(ipcTransport, ipcTransportPath, rootDir),
      ...extractDisabledTransportSurface(disabledTransport, disabledTransportPath, rootDir),
      ...extractControlsSurface(controls, controlsPath, rootDir),
    ],
    guardrailDependencies: extractGuardrailDependencies({
      wailsBindingCheck,
      oldBindingCompat,
      wailsBindingCheckPath,
      oldBindingCompatPath,
      rootDir,
    }),
    desktopBridgeAdapterConstructionRemoved:
      !/\bcreateIpcBackendTransport\s*\(/.test(desktopBridge) &&
      !/\bdesktopApp\.InvokeBackendJSON\b/.test(desktopBridge),
  };
}

function validateTracker(trackerPath, facts, violations) {
  const tracker = readJson(trackerPath, "docs/desktop-ipc-iteration-status.json", violations);
  if (!tracker) {
    return;
  }

  const preflight = tracker?.domains?.genericIpcBackendGeneratedBindingCleanupPreflight;
  if (!preflight) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: missing genericIpcBackendGeneratedBindingCleanupPreflight record",
    );
    return;
  }
  if (!["preflight-completed", "deletion-completed"].includes(preflight.status)) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: genericIpcBackendGeneratedBindingCleanupPreflight.status must be preflight-completed or deletion-completed",
    );
  }

  const blockers = deriveDeletionBlockers(facts);
  if (blockers.length === 0 && preflight.status !== "deletion-completed") {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: genericIpcBackendGeneratedBindingCleanupPreflight.status must be deletion-completed after blockers are cleared",
    );
  }
  if (preflight.deletionReady !== (blockers.length === 0)) {
    violations.push(
      `docs/desktop-ipc-iteration-status.json: genericIpcBackendGeneratedBindingCleanupPreflight.deletionReady must be ${
        blockers.length === 0
      } for current code facts`,
    );
  }
  const generatedBindingsRemoved = facts.backendExportedMethods.length === 0 && facts.generatedBindings.length === 0;
  if (preflight.backendGeneratedBindingsRemoved !== generatedBindingsRemoved) {
    violations.push(
      `docs/desktop-ipc-iteration-status.json: genericIpcBackendGeneratedBindingCleanupPreflight.backendGeneratedBindingsRemoved must be ${generatedBindingsRemoved} for current code facts`,
    );
  }
  if (preflight.frontendAdapterConstructionRemoved !== true) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: genericIpcBackendGeneratedBindingCleanupPreflight.frontendAdapterConstructionRemoved must be true after Round 29",
    );
  }
  if (facts.desktopBridgeAdapterConstructionRemoved !== true) {
    violations.push(
      "frontend/src/app/integrations/desktopBridge.ts: generic IPC adapter construction must remain removed",
    );
  }

  validateTrackerList(
    preflight.inventory?.backendExportedMethods,
    facts.backendExportedMethods.map((method) => `DesktopApp.${method}`),
    "inventory.backendExportedMethods",
    violations,
  );
  validateTrackerList(
    preflight.inventory?.typedHelperReuse,
    facts.typedHelperReuse.map((item) => `${item.method} -> ${item.helper}`),
    "inventory.typedHelperReuse",
    violations,
  );
  validateTrackerList(
    preflight.inventory?.generatedBindings,
    facts.generatedBindings,
    "inventory.generatedBindings",
    violations,
  );
  validateTrackerList(
    preflight.inventory?.frontendBindingSurfaces,
    facts.frontendBindingSurfaces,
    "inventory.frontendBindingSurfaces",
    violations,
  );
  validateTrackerList(
    preflight.inventory?.guardrailDependencies,
    facts.guardrailDependencies,
    "inventory.guardrailDependencies",
    violations,
  );
  validateTrackerList(preflight.blockers, blockers, "blockers", violations);
  if (blockers.length > 0) {
    validateNonEmptyList(
      preflight.nextDeletionPrerequisites,
      "genericIpcBackendGeneratedBindingCleanupPreflight.nextDeletionPrerequisites",
      violations,
    );
  }
}

function deriveDeletionBlockers(facts) {
  const blockers = [];
  if (facts.typedHelperReuse.length > 0) {
    blockers.push("typed helper reuse still calls DesktopApp.InvokeBackendBlob/Text from typed methods");
  }
  if (facts.backendProxyTestsDirectHelpers.length > 0) {
    blockers.push(
      `desktop_backend_proxy_test.go still directly tests exported generic helpers: ${facts.backendProxyTestsDirectHelpers.join(", ")}`,
    );
  }
  if (facts.guardrailDependencies.includes("frontend/scripts/check-wails-bindings.mjs requires generic-ipc group")) {
    blockers.push("check-wails-bindings generic-ipc group still requires generated InvokeBackend* bindings");
  }
  if (
    facts.frontendBindingSurfaces.includes(
      "frontend/src/app/integrations/ipcBackendTransport.ts exports createIpcBackendTransport",
    )
  ) {
    blockers.push("ipcBackendTransport still contains unreachable adapter implementation");
  }
  return blockers;
}

function validateTrackerList(actual, expected, label, violations) {
  if (!Array.isArray(actual)) {
    violations.push(
      `docs/desktop-ipc-iteration-status.json: genericIpcBackendGeneratedBindingCleanupPreflight.${label} must be an array`,
    );
    return;
  }
  const missing = expected.filter((entry) => !actual.includes(entry));
  const unexpected = actual.filter((entry) => !expected.includes(entry));
  for (const entry of missing) {
    violations.push(
      `docs/desktop-ipc-iteration-status.json: genericIpcBackendGeneratedBindingCleanupPreflight.${label} missing ${entry}`,
    );
  }
  for (const entry of unexpected) {
    violations.push(
      `docs/desktop-ipc-iteration-status.json: genericIpcBackendGeneratedBindingCleanupPreflight.${label} has stale entry ${entry}`,
    );
  }
}

function validateNonEmptyList(value, label, violations) {
  if (!Array.isArray(value) || value.length === 0 || value.some((entry) => typeof entry !== "string" || !entry)) {
    violations.push(`docs/desktop-ipc-iteration-status.json: ${label} must be a non-empty string array`);
  }
}

function extractTypedHelperReuse(body) {
  const reuses = [];
  let currentMethod = "";
  const lines = body.split(/\r\n|\r|\n/);
  lines.forEach((line, index) => {
    const methodMatch = line.match(/^\s*func \(a \*DesktopApp\) ([A-Z][A-Za-z0-9_]*)\s*\(/);
    if (methodMatch) {
      currentMethod = methodMatch[1] ?? "";
    }
    for (const helperMatch of line.matchAll(/\ba\.InvokeBackend(JSON|Blob|Text)\s*\(/g)) {
      const helper = `InvokeBackend${helperMatch[1] ?? ""}`;
      if (currentMethod && currentMethod !== helper) {
        reuses.push({ method: currentMethod, helper, line: index + 1 });
      }
    }
  });
  return reuses;
}

function extractDirectHelperTestUses(body) {
  const observed = new Set();
  const lines = body.split(/\r\n|\r|\n/);
  lines.forEach((line) => {
    for (const method of genericMethods) {
      if (new RegExp(`\\bapp\\.${method}\\s*\\(`).test(line)) {
        observed.add(`desktop_backend_proxy_test.go -> ${method}`);
      }
    }
  });
  return [...observed].sort();
}

function extractGeneratedBindings(body, filePath, rootDir) {
  const relativePath = relative(rootDir, filePath).replaceAll("\\", "/");
  return genericMethods
    .filter((method) => new RegExp(`export function ${method}\\b`).test(body))
    .map((method) => `${relativePath} exports ${method}`);
}

function extractShellBindingFields(body, filePath, rootDir) {
  const relativePath = relative(rootDir, filePath).replaceAll("\\", "/");
  return genericMethods
    .filter((method) => new RegExp(`${method}\\?\\s*:`).test(body))
    .map((method) => `${relativePath} declares ${method}`);
}

function extractIpcTransportSurface(body, filePath, rootDir) {
  const relativePath = relative(rootDir, filePath).replaceAll("\\", "/");
  const surface = [];
  if (/\bexport function createIpcBackendTransport\b/.test(body)) {
    surface.push(`${relativePath} exports createIpcBackendTransport`);
  }
  for (const method of genericMethods) {
    if (body.includes(method)) {
      surface.push(`${relativePath} calls ${method}`);
    }
  }
  return surface;
}

function extractDisabledTransportSurface(body, filePath, rootDir) {
  const relativePath = relative(rootDir, filePath).replaceAll("\\", "/");
  const surface = [];
  if (/\bexport function createDisabledGenericIpcBackendTransport\b/.test(body)) {
    surface.push(`${relativePath} exports createDisabledGenericIpcBackendTransport`);
  }
  if (body.includes("generic_ipc_disabled")) {
    surface.push(`${relativePath} reports generic_ipc_disabled`);
  }
  return surface;
}

function extractControlsSurface(body, filePath, rootDir) {
  const relativePath = relative(rootDir, filePath).replaceAll("\\", "/");
  const requiredTokens = [
    "DesktopIpcRequestError",
    "IpcBackendTransport",
    "withDesktopIpcControls",
    "DESKTOP_IPC_BLOB_MAX_BYTES",
  ];
  if (requiredTokens.every((token) => body.includes(token))) {
    return [
      `${relativePath} exports DesktopIpcRequestError, IpcBackendTransport, withDesktopIpcControls, and blob limit checks`,
    ];
  }
  return [];
}

function extractGuardrailDependencies({
  wailsBindingCheck,
  oldBindingCompat,
  wailsBindingCheckPath,
  oldBindingCompatPath,
  rootDir,
}) {
  const dependencies = [];
  const wailsPath = relative(rootDir, wailsBindingCheckPath).replaceAll("\\", "/");
  const oldBindingPath = relative(rootDir, oldBindingCompatPath).replaceAll("\\", "/");
  if (
    /"generic-ipc"\s*:\s*\[[^\]]*InvokeBackendJSON[^\]]*InvokeBackendBlob[^\]]*InvokeBackendText/s.test(
      wailsBindingCheck,
    )
  ) {
    dependencies.push(`${wailsPath} requires generic-ipc group`);
  }
  if (
    /forbiddenGeneratedBindings[\s\S]*InvokeBackendJSON[\s\S]*InvokeBackendBlob[\s\S]*InvokeBackendText/s.test(
      wailsBindingCheck,
    )
  ) {
    dependencies.push(`${wailsPath} forbids removed InvokeBackend* bindings`);
  }
  if (
    /"src\/app\/integrations\/ipcBackendTransport\.ts"\s*:\s*\[[^\]]*InvokeBackendJSON[^\]]*InvokeBackendBlob[^\]]*InvokeBackendText/s.test(
      oldBindingCompat,
    )
  ) {
    dependencies.push(`${oldBindingPath} allows ipcBackendTransport InvokeBackend* inventory`);
  }
  if (
    /extractDesktopBindingUses/.test(oldBindingCompat) &&
    !/"src\/app\/integrations\/ipcBackendTransport\.ts"\s*:\s*\[[^\]]*InvokeBackendJSON/s.test(oldBindingCompat)
  ) {
    dependencies.push(`${oldBindingPath} rejects unapproved InvokeBackend* inventory`);
  }
  return dependencies;
}

function validatePlanTokens(path, label, violations) {
  if (!existsSync(path)) {
    violations.push(`${label}: missing backend/generated binding cleanup preflight plan source`);
    return;
  }
  const body = readFileSync(path, "utf8");
  for (const token of requiredPlanTokens) {
    if (!body.includes(token)) {
      violations.push(`${label}: missing backend/generated binding cleanup preflight token ${token}`);
    }
  }
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
    if (!ci.includes(`pnpm run ${scriptName}`)) {
      violations.push(`frontend/package.json: ci must run ${scriptName}`);
    }
  }
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

function readText(path) {
  return existsSync(path) ? readFileSync(path, "utf8") : "";
}

function runCli() {
  const violations = findDesktopGenericIpcBindingCleanupPreflightViolations();
  if (violations.length === 0) {
    console.log("Desktop generic IPC backend/generated binding cleanup preflight check passed.");
    return;
  }
  console.error("Desktop generic IPC backend/generated binding cleanup preflight violations:");
  for (const violation of violations) {
    console.error(`- ${violation}`);
  }
  process.exit(1);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli();
}
