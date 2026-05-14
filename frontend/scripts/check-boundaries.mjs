// Frontend module-boundary enforcement.
//
// This script fails CI when the import graph violates any of the following
// layering invariants (validated via frontend/scripts/check-boundaries.test.mjs):
//
// 1. No production code may import ./integrations/wailsBridge — it's a
//    test-only escape hatch. Use integrations/backendClients instead.
// 2. Only the integrations/ layer itself may reach inside bridgeTypes,
//    bridgeFactory, httpBridge, desktopBridge, or bridgeDomains. App code
//    (pages, features, state) MUST consume the curated domain projections
//    from integrations/backendClients.
// 3. State code (src/app/state/**) may not import UI components (pages/
//    or components/). State stays UI-free.
// 4. Pages may not import mappers directly or reach through the legacy
//    evidenceSchema shim; pages consume feature- or core-level view models.
// 5. Pages may not add new direct dependencies on aggregate backendClients.
//    Existing page edges are baselined while they migrate into feature hooks.
// 6. Features may not import from other features (cross-feature coupling
//    must route through core/, shared components/analysis, or integrations/).
//    This is the rule flagged in the 2026-05-12 engineering report.
// 7. Mappers (integrations/mappers/**) stay UI-free and decision-free:
//    no React imports, no pages/components imports, no feature "rules"
//    imports.
// 8. Clients (integrations/clients/**) stay transport-only: no pages,
//    components, or features imports.
// 9. UI primitives (components/ui/**) stay domain-free.
// 10. Shared analysis components (components/analysis/**) stay
//    domain-neutral — no features/ imports.
//
// The allowlist `allowedFeatureCrossImports` lets us grandfather specific
// cross-feature edges during a refactor. It currently contains zero
// entries; adding to it requires explicit justification in the PR.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, extname, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourceExtensions = new Set([".ts", ".tsx"]);
const importPattern = /import\s+(?:type\s+)?(?:[^'"()]+?\s+from\s+)?["']([^"']+)["']/g;
const allowedFeatureCrossImports = new Set([]);
const allowedPageBackendClientImports = new Set([
  "src/app/pages/MiscTools.tsx",
  "src/app/pages/ObjectExport.tsx",
  "src/app/pages/ThreatHunting.tsx",
]);

export function findBoundaryViolations({ frontendRoot = root } = {}) {
  const appRoot = resolve(frontendRoot, "src/app");
  const violations = [];

  for (const file of sourceFiles(appRoot)) {
    const source = relative(frontendRoot, file).replaceAll("\\", "/");
    const body = readFileSync(file, "utf8");
    for (const specifier of importSpecifiers(body)) {
      recordWailsBridgeImport(violations, source, specifier);
      recordBridgeTypesImport(violations, source, specifier);
      const target = resolveSourceImport(frontendRoot, appRoot, file, specifier);
      recordViolation(violations, source, specifier, target);
    }
  }

  return violations;
}

function runCli() {
  const violations = findBoundaryViolations();
  if (violations.length === 0) {
    console.log("Frontend boundary check passed.");
    return;
  }

  console.error("Frontend boundary violations:");
  for (const violation of violations) {
    console.error(`- ${violation}`);
  }
  process.exit(1);
}

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

function resolveSourceImport(frontendRoot, appRoot, file, specifier) {
  if (specifier === "react") {
    return "react";
  }
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
  if (!target || !target.startsWith(appRoot)) {
    return "";
  }
  return relative(frontendRoot, target).replaceAll("\\", "/");
}

function recordViolation(violations, source, specifier, target) {
  if (!source.startsWith("src/app/integrations/")) {
    if (
      source.startsWith("src/app/pages/") &&
      target === "src/app/integrations/backendClients.ts" &&
      !allowedPageBackendClientImports.has(source)
    ) {
      violations.push(
        `${source} imports aggregate backendClients via ${specifier}; move backend calls into a feature hook or a domain client wrapper`,
      );
      return;
    }
    if (target === "src/app/integrations/backendClients.ts") {
      return;
    }
    if (
      target === "src/app/integrations/bridgeFactory.ts" ||
      target === "src/app/integrations/httpBridge.ts" ||
      target === "src/app/integrations/desktopBridge.ts" ||
      target === "src/app/integrations/bridgeDomains.ts"
    ) {
      violations.push(`${source} imports ${specifier}; app code must depend on backendClients domain projections`);
    }
  }

  if (
    source.startsWith("src/app/state/") &&
    (target.startsWith("src/app/pages/") || target.startsWith("src/app/components/"))
  ) {
    violations.push(`${source} imports UI layer ${specifier}; state code must stay UI-free`);
  }

  if (source.startsWith("src/app/pages/") && target.startsWith("src/app/integrations/mappers/")) {
    violations.push(`${source} imports mapper ${specifier}; pages must consume feature/core view models instead`);
  }
  if (source.startsWith("src/app/pages/") && target === "src/app/features/evidence/evidenceSchema.ts") {
    violations.push(`${source} imports evidence schema shim ${specifier}; pages must use core evidence contracts`);
  }
  recordFeatureBoundaryViolation(violations, source, specifier, target);

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

  if (source.startsWith("src/app/components/analysis/") && target.startsWith("src/app/features/")) {
    violations.push(
      `${source} imports feature layer ${specifier}; shared analysis components must stay domain-neutral`,
    );
  }
}

function recordFeatureBoundaryViolation(violations, source, specifier, target) {
  const sourceDomain = featureDomain(source);
  const targetDomain = featureDomain(target);
  if (!sourceDomain || !targetDomain || sourceDomain === targetDomain) {
    return;
  }
  const baselineKey = `${source} -> ${target}`;
  if (allowedFeatureCrossImports.has(baselineKey)) {
    return;
  }
  violations.push(
    `${source} imports feature domain ${targetDomain} via ${specifier}; cross-domain feature logic must move to core or shared analysis modules`,
  );
}

function featureDomain(path) {
  const match = path.match(/^src\/app\/features\/([^/]+)\//);
  return match?.[1] ?? "";
}

function recordWailsBridgeImport(violations, source, specifier) {
  if (specifier.includes("wailsBridge")) {
    violations.push(
      `${source} imports ${specifier}; production code must use integrations/backendClients or bridgeTypes`,
    );
  }
}

function recordBridgeTypesImport(violations, source, specifier) {
  if (!source.startsWith("src/app/integrations/") && specifier.includes("integrations/bridgeTypes")) {
    violations.push(`${source} imports ${specifier}; use concrete client type modules instead`);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli();
}
