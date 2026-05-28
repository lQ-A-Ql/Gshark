import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const frontendRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(frontendRoot, "..");

const adapterTokens = ["InvokeBackendJSON", "InvokeBackendBlob", "InvokeBackendText", "createIpcBackendTransport"];

const adapterInventoryAllowlist = new Map();

const requiredPackageScripts = {
  "desktop-generic-ipc-removal-preflight:check": "node scripts/check-desktop-generic-ipc-removal-preflight.mjs",
};

const requiredPreflightPlanTokens = [
  "adapter removal preflight",
  "removed InvokeBackendJSON",
  "removed InvokeBackendBlob",
  "removed InvokeBackendText",
  "createIpcBackendTransport",
  "VITE_DESKTOP_GENERIC_IPC_POLICY=compat",
  "browser-dev HTTP/SSE",
  "reversible deletion plan",
];

export function findDesktopGenericIpcRemovalPreflightViolations({
  rootDir = repoRoot,
  frontendDir = resolve(rootDir, "frontend"),
  trackerPath = resolve(rootDir, "docs/desktop-ipc-iteration-status.json"),
  migrationPlanPath = resolve(rootDir, "docs/desktop-ipc-migration-plan.md"),
  exitPlanPath = resolve(rootDir, "docs/desktop-ipc-old-binding-exit-plan.md"),
  packagePath = resolve(frontendDir, "package.json"),
} = {}) {
  const violations = [];
  validateTracker(trackerPath, violations);
  validateAdapterInventory(rootDir, violations);
  validatePlanTokens(migrationPlanPath, "docs/desktop-ipc-migration-plan.md", violations);
  validatePlanTokens(exitPlanPath, "docs/desktop-ipc-old-binding-exit-plan.md", violations);
  validatePackageScripts(packagePath, violations);
  return violations;
}

function validateTracker(trackerPath, violations) {
  const tracker = readJson(trackerPath, "docs/desktop-ipc-iteration-status.json", violations);
  if (!tracker) {
    return;
  }

  const releaseCandidate = tracker?.domains?.genericIpcAdapterDefaultDisabledReleaseCandidate;
  const observation = releaseCandidate?.observation;
  if (releaseCandidate?.adapterRemoved !== false) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: genericIpcAdapterDefaultDisabledReleaseCandidate.adapterRemoved must remain false during removal preflight",
    );
  }
  if (observation?.requiredConsecutiveGreenRoundsBeforeRemoval !== 3) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: removal preflight requires three configured default-disabled observation rounds",
    );
  }
  if (observation?.currentConsecutiveGreenRounds !== 3) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: removal preflight requires currentConsecutiveGreenRounds = 3",
    );
  }
  if (observation?.removalAllowed !== true) {
    violations.push("docs/desktop-ipc-iteration-status.json: removal preflight requires removalAllowed = true");
  }
  const countedRounds = Array.isArray(observation?.rounds) ? observation.rounds.slice(-3) : [];
  if (countedRounds.length !== 3) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: removal preflight requires evidence for exactly three counted observation rounds",
    );
  }
  for (const round of countedRounds) {
    validateObservationRound(round ?? {}, violations);
  }

  const preflight = tracker?.domains?.genericIpcAdapterRemovalPreflight;
  if (!preflight) {
    violations.push("docs/desktop-ipc-iteration-status.json: missing genericIpcAdapterRemovalPreflight record");
    return;
  }
  if (!["preflight-completed", "candidate-completed", "deletion-completed"].includes(preflight.status)) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: genericIpcAdapterRemovalPreflight.status must be preflight-completed, candidate-completed, or deletion-completed",
    );
  }
  const bindingCleanup = tracker?.domains?.genericIpcBackendGeneratedBindingCleanupPreflight;
  const backendGeneratedRemoved = bindingCleanup?.backendGeneratedBindingsRemoved === true;
  const adapterRemoved = preflight.adapterRemoved === true;
  if (backendGeneratedRemoved && !adapterRemoved) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: genericIpcAdapterRemovalPreflight.adapterRemoved must be true after backend/generated cleanup deletion",
    );
  }
  if (!backendGeneratedRemoved && preflight.adapterRemoved !== false) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: genericIpcAdapterRemovalPreflight.adapterRemoved must remain false before backend/generated cleanup deletion",
    );
  }
  if (preflight?.status === "candidate-completed" && preflight?.frontendAdapterConstructionRemoved !== true) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: genericIpcAdapterRemovalPreflight.frontendAdapterConstructionRemoved must be true after candidate completion",
    );
  }
  validatePreflightList(preflight.inventory?.productionSource, "productionSource", violations);
  validatePreflightList(preflight.inventory?.generatedBindings, "generatedBindings", violations);
  validatePreflightList(preflight.rollbackRequirements, "rollbackRequirements", violations);
  validatePreflightList(preflight.reversibleDeletionPlan, "reversibleDeletionPlan", violations);
}

function validateObservationRound(round, violations) {
  const label = typeof round.id === "string" && round.id.trim() ? round.id : "(unknown)";
  if (round.genericIpcPolicy !== "disabled") {
    violations.push(`docs/desktop-ipc-iteration-status.json: observation round ${label} must be default-disabled`);
  }
  if (round.compatRollbackPolicy !== "compat") {
    violations.push(`docs/desktop-ipc-iteration-status.json: observation round ${label} must keep compat rollback`);
  }
  if (round.directBackendApiRequestCount !== 0) {
    violations.push(
      `docs/desktop-ipc-iteration-status.json: observation round ${label} directBackendApiRequestCount must remain 0`,
    );
  }
  if (round.browserDevOk !== true) {
    violations.push(`docs/desktop-ipc-iteration-status.json: observation round ${label} browserDevOk must be true`);
  }
  if (round.adapterRemoved !== false) {
    violations.push(`docs/desktop-ipc-iteration-status.json: observation round ${label} adapterRemoved must be false`);
  }
}

function validatePreflightList(value, label, violations) {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((entry) => typeof entry !== "string" || !entry.trim())
  ) {
    violations.push(
      `docs/desktop-ipc-iteration-status.json: genericIpcAdapterRemovalPreflight.${label} must be non-empty`,
    );
  }
}

function validateAdapterInventory(rootDir, violations) {
  const files = [
    ...listFiles(resolve(rootDir, "frontend/src/app/integrations"), (entry) => entry.endsWith(".ts")),
    resolve(rootDir, "frontend/wailsjs/go/main/DesktopApp.d.ts"),
    resolve(rootDir, "frontend/wailsjs/go/main/DesktopApp.js"),
  ];
  const observed = new Map();
  for (const file of files) {
    if (!existsSync(file) || /\.test\.ts$/.test(file)) {
      continue;
    }
    const relativePath = relative(rootDir, file).replaceAll("\\", "/");
    const body = readFileSync(file, "utf8");
    for (const token of adapterTokens) {
      if (!body.includes(token)) {
        continue;
      }
      const allowedTokens = adapterInventoryAllowlist.get(relativePath);
      if (!allowedTokens?.has(token)) {
        violations.push(`${relativePath}: unexpected generic IPC adapter token ${token}`);
      }
      const observedTokens = observed.get(relativePath) ?? new Set();
      observedTokens.add(token);
      observed.set(relativePath, observedTokens);
    }
  }
  const bridgePath = resolve(rootDir, "frontend/src/app/integrations/desktopBridge.ts");
  const bridgeBody = existsSync(bridgePath) ? readFileSync(bridgePath, "utf8") : "";
  if (/\bcreateIpcBackendTransport\s*\(/.test(bridgeBody) || /\bdesktopApp\.InvokeBackendJSON\b/.test(bridgeBody)) {
    violations.push(
      "frontend/src/app/integrations/desktopBridge.ts: generic IPC adapter construction must be removed for the candidate",
    );
  }
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

function validatePlanTokens(path, label, violations) {
  if (!existsSync(path)) {
    violations.push(`${label}: missing removal preflight plan source`);
    return;
  }
  const body = readFileSync(path, "utf8");
  for (const token of requiredPreflightPlanTokens) {
    if (!body.includes(token)) {
      violations.push(`${label}: missing removal preflight token ${token}`);
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

function runCli() {
  const violations = findDesktopGenericIpcRemovalPreflightViolations();
  if (violations.length === 0) {
    console.log("Desktop generic IPC removal preflight check passed.");
    return;
  }
  console.error("Desktop generic IPC removal preflight violations:");
  for (const violation of violations) {
    console.error(`- ${violation}`);
  }
  process.exit(1);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli();
}
