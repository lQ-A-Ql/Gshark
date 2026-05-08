import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export function findPackageManagerFailures({
  frontendRoot = resolve(dirname(fileURLToPath(import.meta.url)), ".."),
  workspaceRoot = resolve(frontendRoot, ".."),
} = {}) {
  const packageJsonPath = resolve(frontendRoot, "package.json");
  const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
  const failures = [];

  if (!String(packageJson.packageManager ?? "").startsWith("pnpm@")) {
    failures.push("frontend/package.json must declare packageManager as pnpm@...");
  }

  if (!existsSync(resolve(frontendRoot, "pnpm-lock.yaml"))) {
    failures.push("frontend/pnpm-lock.yaml is required as the only maintained frontend lockfile.");
  }

  const forbiddenLockfiles = [
    resolve(frontendRoot, "package-lock.json"),
    resolve(frontendRoot, "npm-shrinkwrap.json"),
    resolve(frontendRoot, "yarn.lock"),
    resolve(workspaceRoot, "package-lock.json"),
    resolve(workspaceRoot, "npm-shrinkwrap.json"),
    resolve(workspaceRoot, "yarn.lock"),
  ];

  for (const lockfile of forbiddenLockfiles) {
    if (existsSync(lockfile)) {
      failures.push(`Remove unsupported lockfile: ${lockfile}`);
    }
  }

  return failures;
}

function runCli() {
  const failures = findPackageManagerFailures();

  if (failures.length > 0) {
    console.error("Frontend package manager check failed:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }

  console.log("Frontend package manager check passed.");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli();
}
