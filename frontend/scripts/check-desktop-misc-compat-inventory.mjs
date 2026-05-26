import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(root, "..");

const sourceDirs = ["src/app/integrations"];
const migratedMiscRoutes = new Set([
  "/api/tools/misc/modules",
  "/api/tools/misc/import",
  "/api/tools/misc/packages/*",
  "/api/tools/misc/packages/*/invoke",
]);
const allowedMiscRoutes = new Set([...migratedMiscRoutes]);
const requiredMigratedRoutes = [...migratedMiscRoutes];
const requiredCompatibilityRoutes = [];
const requiredMiscRoutes = [...requiredMigratedRoutes, ...requiredCompatibilityRoutes];
const requiredDesignTokens = [
  "ListMiscModules",
  "ImportMiscModulePackageFromPath",
  "ImportMiscModulePackageFromPath(path string",
  "DeleteMiscModulePackage",
  "DeleteMiscModulePackage(id string)",
  "RunMiscModulePackage",
  "RunMiscModulePackage(id string",
  "ListMiscModules()",
  "runtime-complete; list-import-delete-run-typed",
];

export function findDesktopMiscCompatInventoryViolations({
  frontendRoot = root,
  designPath = resolve(repoRoot, "docs/desktop-ipc-misc-native-binding-design.md"),
} = {}) {
  const violations = [];
  const seenRoutes = new Set();

  for (const file of listIntegrationSourceFiles(frontendRoot)) {
    const relativeFile = relative(frontendRoot, file).replaceAll("\\", "/");
    if (relativeFile.endsWith(".test.ts")) {
      continue;
    }
    const body = readFileSync(file, "utf8");
    for (const candidate of extractMiscRouteCandidates(body)) {
      seenRoutes.add(candidate.path);
      if (!allowedMiscRoutes.has(candidate.path)) {
        violations.push(
          `${relativeFile}:${candidate.line}: unclassified MISC desktop route ${candidate.path}; add a typed DesktopApp binding or update the native binding design before expanding MISC transport`,
        );
      }
    }
  }

  for (const route of requiredMiscRoutes) {
    if (!seenRoutes.has(route)) {
      const routeClass = migratedMiscRoutes.has(route) ? "migrated typed route" : "compatibility route";
      violations.push(`MISC inventory missing current ${routeClass} ${route}`);
    }
  }

  if (!existsSync(designPath)) {
    violations.push("docs/desktop-ipc-misc-native-binding-design.md: missing MISC native binding design");
    return violations;
  }
  const design = readFileSync(designPath, "utf8");
  for (const token of requiredDesignTokens) {
    if (!design.includes(token)) {
      violations.push(`docs/desktop-ipc-misc-native-binding-design.md: missing design token ${token}`);
    }
  }

  return violations;
}

function listIntegrationSourceFiles(frontendRoot) {
  const files = [];
  for (const dir of sourceDirs) {
    const absoluteDir = resolve(frontendRoot, dir);
    if (existsSync(absoluteDir)) {
      collectTsFiles(absoluteDir, files);
    }
  }
  return files;
}

function collectTsFiles(dir, files) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      collectTsFiles(path, files);
    } else if (entry.isFile() && entry.name.endsWith(".ts")) {
      files.push(path);
    }
  }
}

function extractMiscRouteCandidates(body) {
  const candidates = [];
  const stringPattern = /(["'`])([^"'`]*\/api\/tools\/misc\/[^"'`]*)\1/g;
  for (const match of body.matchAll(stringPattern)) {
    if (isCommentOnlyLine(body, match.index ?? 0)) {
      continue;
    }
    const raw = String(match[2] ?? "");
    const start = raw.indexOf("/api/tools/misc/");
    if (start < 0) {
      continue;
    }
    candidates.push({
      path: normalizeCandidatePath(raw.slice(start)),
      line: lineNumberAt(body, match.index ?? 0),
    });
  }
  return candidates;
}

function normalizeCandidatePath(path) {
  return path.replace(/\$\{[^}]*\}/g, "*").replace(/`/g, "");
}

function isCommentOnlyLine(body, index) {
  const lineStart = body.lastIndexOf("\n", index) + 1;
  return body.slice(lineStart, index).trimStart().startsWith("//");
}

function lineNumberAt(body, index) {
  return body.slice(0, index).split(/\r\n|\r|\n/).length;
}

function runCli() {
  const violations = findDesktopMiscCompatInventoryViolations();
  if (violations.length === 0) {
    console.log("Desktop MISC transport inventory check passed; no MISC desktop compatibility routes remain.");
    return;
  }
  console.error("Desktop MISC transport inventory violations:");
  for (const violation of violations) {
    console.error(`- ${violation}`);
  }
  process.exit(1);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli();
}
