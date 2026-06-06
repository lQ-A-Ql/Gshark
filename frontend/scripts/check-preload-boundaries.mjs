import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, extname, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourceExtensions = new Set([".ts", ".tsx"]);
const importPattern = /import\s+(?:type\s+)?(?:[^'"()]+?\s+from\s+)?["']([^"']+)["']/g;

export function findPreloadBoundaryViolations({ frontendRoot = root } = {}) {
  const appRoot = resolve(frontendRoot, "src/app");
  const violations = [];
  for (const file of sourceFiles(appRoot)) {
    const source = relative(frontendRoot, file).replaceAll("\\", "/");
    const body = readFileSync(file, "utf8");
    for (const specifier of importSpecifiers(body)) {
      const target = resolveSourceImport(frontendRoot, appRoot, file, specifier);
      if (source.startsWith("src/app/preload/")) {
        if (
          /integrations\/(?:desktopBridge|httpBridge|bridgeFactory|bridgeDomains|bridgeTypes|desktopTypedBridge|wailsBridge)/.test(
            target,
          )
        ) {
          violations.push(`${source} imports ${specifier}; preload must not import bridge internals`);
        }
        if (target.startsWith("src/app/pages/")) {
          violations.push(`${source} imports page module ${specifier}; preload must not create route side effects`);
        }
      }
      if (source.startsWith("src/app/pages/") && target.startsWith("src/app/preload/")) {
        violations.push(`${source} imports preload internal ${specifier}; pages must use feature hooks/contracts`);
      }
      if (source.startsWith("src/app/features/") && target === "src/app/routeModuleLoaders.ts") {
        violations.push(`${source} imports route module registry ${specifier}; route registry is code-preload only`);
      }
    }
  }
  return violations;
}

function runCli() {
  const violations = findPreloadBoundaryViolations();
  if (violations.length === 0) {
    console.log("Preload boundary check passed.");
    return;
  }
  console.error("Preload boundary violations:");
  for (const violation of violations) console.error(`- ${violation}`);
  process.exit(1);
}

function sourceFiles(dir) {
  const files = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = resolve(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...sourceFiles(path));
    } else if (
      sourceExtensions.has(extname(entry.name)) &&
      !entry.name.endsWith(".test.ts") &&
      !entry.name.endsWith(".test.tsx")
    ) {
      files.push(path);
    }
  }
  return files;
}

function importSpecifiers(body) {
  return Array.from(body.matchAll(importPattern), (match) => match[1]);
}

function resolveSourceImport(frontendRoot, appRoot, file, specifier) {
  if (specifier.startsWith("@/")) {
    return normalizeIfSource(frontendRoot, appRoot, resolve(frontendRoot, "src", specifier.slice(2)));
  }
  if (specifier.startsWith(".")) {
    return normalizeIfSource(frontendRoot, appRoot, resolve(dirname(file), specifier));
  }
  return "";
}

function normalizeIfSource(frontendRoot, appRoot, pathWithoutExt) {
  const candidates = [
    pathWithoutExt,
    `${pathWithoutExt}.ts`,
    `${pathWithoutExt}.tsx`,
    resolve(pathWithoutExt, "index.ts"),
    resolve(pathWithoutExt, "index.tsx"),
  ];
  const target = candidates.find((candidate) => existsSync(candidate));
  if (!target || !target.startsWith(appRoot)) return "";
  return relative(frontendRoot, target).replaceAll("\\", "/");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli();
}
