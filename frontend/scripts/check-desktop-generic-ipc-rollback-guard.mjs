import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const frontendRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(frontendRoot, "..");

const requiredSourceTokens = {
  "frontend/src/app/integrations/desktopGenericIpcPolicy.ts": [
    "resolveDesktopGenericIpcPolicy",
    "VITE_DESKTOP_GENERIC_IPC_POLICY",
    "VITE_DESKTOP_DISABLE_GENERIC_IPC",
    'explicitPolicy === "compat"',
    'return "compat"',
    'return "disabled"',
  ],
  "frontend/src/app/integrations/desktopGenericIpcPolicy.test.ts": [
    "lets an explicit compat policy override the legacy disable alias",
    'VITE_DESKTOP_GENERIC_IPC_POLICY: "compat"',
    'VITE_DESKTOP_DISABLE_GENERIC_IPC: "1"',
  ],
  "frontend/src/app/integrations/desktopBridge.test.ts": [
    "keeps explicit compat policy adapter-enabled even when the legacy disable alias is set",
    'vi.stubEnv("VITE_DESKTOP_GENERIC_IPC_POLICY", "compat")',
    'vi.stubEnv("VITE_DESKTOP_DISABLE_GENERIC_IPC", "1")',
  ],
  "docs/desktop-ipc-old-binding-exit-plan.md": [
    "VITE_DESKTOP_GENERIC_IPC_POLICY=disabled",
    "VITE_DESKTOP_GENERIC_IPC_POLICY=compat",
    "rollback",
    "Do not remove browser-dev HTTP/SSE debugging",
  ],
};

const requiredPackageScripts = {
  "desktop-generic-ipc-rollback:check": "node scripts/check-desktop-generic-ipc-rollback-guard.mjs",
};

export function findDesktopGenericIpcRollbackGuardViolations({
  rootDir = repoRoot,
  frontendDir = resolve(rootDir, "frontend"),
  packagePath = resolve(frontendDir, "package.json"),
} = {}) {
  const violations = [];
  validateSourceTokens(rootDir, violations);
  validatePackageScripts(packagePath, violations);
  return violations;
}

function validateSourceTokens(rootDir, violations) {
  for (const [relativePath, tokens] of Object.entries(requiredSourceTokens)) {
    const path = resolve(rootDir, relativePath);
    if (!existsSync(path)) {
      violations.push(`${relativePath}: missing rollback guard source`);
      continue;
    }
    const body = readFileSync(path, "utf8");
    for (const token of tokens) {
      if (!body.includes(token)) {
        violations.push(`${relativePath}: missing rollback guard token ${token}`);
      }
    }
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
    if (!ci.includes(`pnpm run ${scriptName}`)) {
      violations.push(`frontend/package.json: ci must run ${scriptName}`);
    }
  }
}

function runCli() {
  const violations = findDesktopGenericIpcRollbackGuardViolations();
  if (violations.length === 0) {
    console.log("Desktop generic IPC rollback guard check passed.");
    return;
  }
  console.error("Desktop generic IPC rollback guard violations:");
  for (const violation of violations) {
    console.error(`- ${violation}`);
  }
  process.exit(1);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli();
}
