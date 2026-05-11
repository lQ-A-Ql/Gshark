import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, extname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const appRoot = resolve(root, "src/app");
const sourceExtensions = new Set([".ts", ".tsx"]);
const importPattern = /import\s+(?:type\s+)?(?:[^'"()]+?\s+from\s+)?["']([^"']+)["']/g;

const violations = [];

for (const file of sourceFiles(appRoot)) {
  const source = relative(root, file).replaceAll("\\", "/");
  const body = readFileSync(file, "utf8");
  for (const specifier of importSpecifiers(body)) {
    const target = resolveSourceImport(file, specifier);
    recordViolation(source, specifier, target);
  }
}

if (violations.length > 0) {
  console.error("Frontend boundary violations:");
  for (const violation of violations) {
    console.error(`- ${violation}`);
  }
  process.exit(1);
}

console.log("Frontend boundary check passed.");

function sourceFiles(dir) {
  const files = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = resolve(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...sourceFiles(path));
      continue;
    }
    if (
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
  const specifiers = [];
  for (const match of body.matchAll(importPattern)) {
    specifiers.push(match[1]);
  }
  return specifiers;
}

function resolveSourceImport(file, specifier) {
  if (specifier === "react") {
    return "react";
  }
  if (specifier.startsWith("@/")) {
    return normalizeIfSource(resolve(root, "src", specifier.slice(2)));
  }
  if (specifier.startsWith(".")) {
    return normalizeIfSource(resolve(dirname(file), specifier));
  }
  return "";
}

function normalizeIfSource(pathWithoutExt) {
  const candidates = [
    pathWithoutExt,
    `${pathWithoutExt}.ts`,
    `${pathWithoutExt}.tsx`,
    resolve(pathWithoutExt, "index.ts"),
    resolve(pathWithoutExt, "index.tsx"),
  ];
  const target = candidates.find((candidate) => existsSync(candidate));
  if (!target || !target.startsWith(appRoot)) {
    return "";
  }
  return relative(root, target).replaceAll("\\", "/");
}

function recordViolation(source, specifier, target) {
  if (source.startsWith("src/app/pages/") && target.startsWith("src/app/integrations/mappers/")) {
    violations.push(`${source} imports mapper ${specifier}; pages must consume feature/core view models instead`);
  }

  if (source.startsWith("src/app/integrations/mappers/")) {
    if (specifier === "react") {
      violations.push(`${source} imports React; mappers must stay UI-free`);
    }
    if (target.startsWith("src/app/pages/") || target.startsWith("src/app/components/")) {
      violations.push(`${source} imports UI layer ${specifier}; mappers must only normalize wire fields`);
    }
    if (target.startsWith("src/app/features/") && /rules?/i.test(target)) {
      violations.push(`${source} imports feature rules ${specifier}; feature decisions must not flow into mappers`);
    }
  }

  if (source.startsWith("src/app/integrations/clients/")) {
    if (
      target.startsWith("src/app/pages/") ||
      target.startsWith("src/app/components/") ||
      target.startsWith("src/app/features/")
    ) {
      violations.push(`${source} imports ${specifier}; clients must stay transport-only`);
    }
  }

  if (source.startsWith("src/app/components/ui/")) {
    if (
      target.startsWith("src/app/features/") ||
      target.startsWith("src/app/pages/") ||
      target.startsWith("src/app/state/") ||
      target.startsWith("src/app/integrations/")
    ) {
      violations.push(`${source} imports domain layer ${specifier}; ui primitives must stay domain-free`);
    }
  }
}
