import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { packageScriptRunsFromCi } from "./ci-script-coverage.mjs";

const frontendRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(frontendRoot, "..");

const requiredSourceTokens = {
  "frontend/src/app/integrations/desktopBridge.ts": [
    "VITE_DESKTOP_DISABLE_GENERIC_IPC",
    "isDesktopGenericIpcDisabled",
    "isDesktopGenericIpcDisableExperimentEnabled",
    "createDisabledGenericIpcBackendTransport",
  ],
  "frontend/src/app/integrations/desktopGenericIpcPolicy.ts": [
    "resolveDesktopGenericIpcPolicy",
    "VITE_DESKTOP_GENERIC_IPC_POLICY",
    "VITE_DESKTOP_DISABLE_GENERIC_IPC",
    '"disabled"',
    '"compat"',
    'explicitPolicy === "compat"',
    'return "compat"',
    'return "disabled"',
    "return true",
  ],
  "frontend/src/app/integrations/desktopDisabledGenericIpcTransport.ts": [
    "generic_ipc_disabled",
    "createDisabledGenericIpcBackendTransport",
    "subscribeDesktopEvents",
  ],
  "scripts/check-desktop-ipc-smoke.ps1": [
    "DisableGenericIpcAdapterExperiment",
    "MEOW_TRAFFIC_DESKTOP_DISABLE_GENERIC_IPC_EXPERIMENT",
    "genericIpcPolicy",
    "genericIpcDisableExperimentRequested",
    "genericIpcDisableExperimentBuildFlag",
  ],
  "docs/desktop-ipc-old-binding-exit-plan.md": [
    "VITE_DESKTOP_GENERIC_IPC_POLICY=disabled",
    "VITE_DESKTOP_GENERIC_IPC_POLICY=compat",
    "VITE_DESKTOP_DISABLE_GENERIC_IPC=1",
    "three consecutive default-disabled observation rounds",
    "DisableGenericIpcAdapterExperiment",
    "genericIpcDisableExperimentBuildFlag = true",
    "Do not remove browser-dev HTTP/SSE debugging",
  ],
};

const requiredPackageScripts = {
  "desktop-generic-ipc-retirement:check": "node scripts/check-desktop-generic-ipc-retirement-readiness.mjs",
};

export function findDesktopGenericIpcRetirementReadinessViolations({
  rootDir = repoRoot,
  frontendDir = resolve(rootDir, "frontend"),
  trackerPath = resolve(rootDir, "docs/desktop-ipc-iteration-status.json"),
  packagePath = resolve(frontendDir, "package.json"),
} = {}) {
  const violations = [];
  validateSourceTokens(rootDir, violations);
  validateDefaultDisabledReleaseCandidate(rootDir, violations);
  validateTracker(trackerPath, violations);
  validatePackageScripts(packagePath, violations);
  return violations;
}

function validateSourceTokens(rootDir, violations) {
  for (const [relativePath, tokens] of Object.entries(requiredSourceTokens)) {
    const path = resolve(rootDir, relativePath);
    if (!existsSync(path)) {
      violations.push(`${relativePath}: missing retirement readiness source`);
      continue;
    }
    const body = readFileSync(path, "utf8");
    for (const token of tokens) {
      if (!body.includes(token)) {
        violations.push(`${relativePath}: missing retirement readiness token ${token}`);
      }
    }
  }
}

function validateDefaultDisabledReleaseCandidate(rootDir, violations) {
  const bridgePath = resolve(rootDir, "frontend/src/app/integrations/desktopBridge.ts");
  const policyPath = resolve(rootDir, "frontend/src/app/integrations/desktopGenericIpcPolicy.ts");
  const policyBody = existsSync(policyPath) ? readFileSync(policyPath, "utf8") : "";
  const bridgeBody = existsSync(bridgePath) ? readFileSync(bridgePath, "utf8") : "";
  if (/VITE_DESKTOP_DISABLE_GENERIC_IPC[^?;\n]*(?:\?\?|===?)\s*["']1["']/.test(bridgeBody + "\n" + policyBody)) {
    violations.push(
      "frontend/src/app/integrations/desktopBridge.ts: do not promote the legacy VITE_DESKTOP_DISABLE_GENERIC_IPC alias to the default; use the policy resolver default instead",
    );
  }
  const returnLiterals = [...policyBody.matchAll(/return\s+["'](compat|disabled)["']\s*;/g)].map((match) => match[1]);
  if (returnLiterals.at(-1) !== "disabled") {
    violations.push(
      "frontend/src/app/integrations/desktopGenericIpcPolicy.ts: Round 24 release candidate must default to disabled when no explicit compat policy is set",
    );
  }
  if (!/explicitPolicy\s*===\s*["']compat["'][\s\S]*?return\s+["']compat["']\s*;/.test(policyBody)) {
    violations.push(
      "frontend/src/app/integrations/desktopGenericIpcPolicy.ts: explicit VITE_DESKTOP_GENERIC_IPC_POLICY=compat policy value must remain recognizable",
    );
  }
  if (!/isDesktopGenericIpcDisabled[\s\S]*?return\s+true\s*;/.test(policyBody)) {
    violations.push(
      "frontend/src/app/integrations/desktopGenericIpcPolicy.ts: after adapter removal candidate, compat must remain a documented no-op and generic IPC must stay disabled",
    );
  }
  if (/\bcreateIpcBackendTransport\s*\(/.test(bridgeBody)) {
    violations.push(
      "frontend/src/app/integrations/desktopBridge.ts: generic IPC adapter construction must stay removed after the removal candidate",
    );
  }
}

function validateTracker(trackerPath, violations) {
  if (!existsSync(trackerPath)) {
    violations.push("docs/desktop-ipc-iteration-status.json: missing IPC iteration tracker");
    return;
  }
  let tracker;
  try {
    tracker = JSON.parse(readFileSync(trackerPath, "utf8"));
  } catch (error) {
    violations.push(
      `docs/desktop-ipc-iteration-status.json: tracker is not valid JSON (${error instanceof Error ? error.message : String(error)})`,
    );
    return;
  }

  const experiment = tracker?.domains?.genericIpcAdapterDisableExperiment;
  if (!experiment) {
    violations.push("docs/desktop-ipc-iteration-status.json: missing domains.genericIpcAdapterDisableExperiment");
    return;
  }
  if (experiment.status !== "release-candidate-default-disabled") {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: genericIpcAdapterDisableExperiment.status must be release-candidate-default-disabled",
    );
  }
  if (experiment.flag !== "VITE_DESKTOP_DISABLE_GENERIC_IPC=1") {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: genericIpcAdapterDisableExperiment.flag must be VITE_DESKTOP_DISABLE_GENERIC_IPC=1",
    );
  }
  if (experiment.failureCode !== "generic_ipc_disabled") {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: genericIpcAdapterDisableExperiment.failureCode must be generic_ipc_disabled",
    );
  }
  const smoke = experiment.lastExperimentSmoke ?? {};
  if (smoke.genericIpcDisableExperimentBuildFlag !== true) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: lastExperimentSmoke.genericIpcDisableExperimentBuildFlag must record true evidence",
    );
  }
  if (smoke.desktopWebviewDirectBackendApiRequestCount !== 0) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: lastExperimentSmoke.desktopWebviewDirectBackendApiRequestCount must remain 0",
    );
  }
  if (smoke.browserDevOk !== true) {
    violations.push("docs/desktop-ipc-iteration-status.json: lastExperimentSmoke.browserDevOk must remain true");
  }

  const releaseCandidate = tracker?.domains?.genericIpcAdapterDefaultDisabledReleaseCandidate;
  const rollback = releaseCandidate?.rollbackPolicy;
  if (rollback !== "VITE_DESKTOP_GENERIC_IPC_POLICY=compat") {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: genericIpcAdapterDefaultDisabledReleaseCandidate.rollbackPolicy must preserve the VITE_DESKTOP_GENERIC_IPC_POLICY=compat policy value",
    );
  }
  const observation = releaseCandidate?.observation;
  if (!observation) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: genericIpcAdapterDefaultDisabledReleaseCandidate.observation must record default-disabled observation state",
    );
    return;
  }
  if (observation.requiredConsecutiveGreenRoundsBeforeRemoval !== 3) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: observation.requiredConsecutiveGreenRoundsBeforeRemoval must be 3",
    );
  }
  const currentRounds = Number(observation.currentConsecutiveGreenRounds ?? 0);
  if (!Number.isInteger(currentRounds) || currentRounds < 1) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: observation.currentConsecutiveGreenRounds must be at least 1 after Round 25",
    );
  }
  if (releaseCandidate?.adapterRemoved === true && currentRounds < 3) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: generic IPC adapter removal is blocked until three consecutive green default-disabled observation rounds",
    );
  }
  const rounds = Array.isArray(observation.rounds) ? observation.rounds : [];
  if (rounds.length < currentRounds) {
    violations.push(
      "docs/desktop-ipc-iteration-status.json: observation.rounds must contain evidence for each counted green observation round",
    );
  }
  const countedRounds = rounds.slice(-currentRounds);
  for (const [index, round] of countedRounds.entries()) {
    const fallbackIndex = rounds.length - countedRounds.length + index + 1;
    const label = typeof round?.id === "string" && round.id.trim() ? round.id : `#${fallbackIndex}`;
    validateObservationRoundEvidence(round ?? {}, label, violations);
  }
}

function validateObservationRoundEvidence(round, label, violations) {
  if (round.genericIpcPolicy !== "disabled") {
    violations.push(
      `docs/desktop-ipc-iteration-status.json: observation round ${label} must record genericIpcPolicy disabled`,
    );
  }
  if (round.compatRollbackPolicy !== "compat") {
    violations.push(
      `docs/desktop-ipc-iteration-status.json: observation round ${label} must record compat rollback smoke`,
    );
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

function validatePackageScripts(packagePath, violations) {
  if (!existsSync(packagePath)) {
    violations.push("frontend/package.json: missing package manifest");
    return;
  }
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(packagePath, "utf8"));
  } catch (error) {
    violations.push(
      `frontend/package.json: package manifest is not valid JSON (${error instanceof Error ? error.message : String(error)})`,
    );
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

function runCli() {
  const violations = findDesktopGenericIpcRetirementReadinessViolations();
  if (violations.length === 0) {
    console.log("Desktop generic IPC retirement readiness check passed.");
    return;
  }
  console.error("Desktop generic IPC retirement readiness violations:");
  for (const violation of violations) {
    console.error(`- ${violation}`);
  }
  process.exit(1);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli();
}
