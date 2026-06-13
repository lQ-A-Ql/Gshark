import { mkdirSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const recordWideAllowlist = new Set([
  "src/app/integrations/wire/aptWireDtos.ts",
  "src/app/integrations/wire/c2DecryptWireDtos.ts",
  "src/app/integrations/wire/capturePageWireDtos.ts",
  "src/app/integrations/wire/captureStatusWireDtos.ts",
  "src/app/integrations/wire/c2SampleWireDtos.ts",
  "src/app/integrations/wire/evidenceRecordWireDtos.ts",
  "src/app/integrations/wire/huntingWireDtos.ts",
  "src/app/integrations/wire/industrialWireDtos.ts",
  "src/app/integrations/wire/mcpWireDtos.ts",
  "src/app/integrations/wire/mediaWireDtos.ts",
  "src/app/integrations/wire/miscModuleWireDtos.ts",
  "src/app/integrations/wire/objectEvidenceWireDtos.ts",
  "src/app/integrations/wire/packetWireDtos.ts",
  "src/app/integrations/wire/protocolToolWireDtos.ts",
  "src/app/integrations/wire/reportWireDtos.ts",
  "src/app/integrations/wire/runtimeWireDtos.ts",
  "src/app/integrations/wire/sessionMaterialWireDtos.ts",
  "src/app/integrations/wire/shiroWireDtos.ts",
  "src/app/integrations/wire/streamDecodeWireDtos.ts",
  "src/app/integrations/wire/streamPayloadSourceWireDtos.ts",
  "src/app/integrations/wire/streamPayloadWireDtos.ts",
  "src/app/integrations/wire/streamWireDtos.ts",
  "src/app/integrations/wire/toolWireDtos.ts",
  "src/app/integrations/wire/trafficProtocolWireDtos.ts",
  "src/app/integrations/wire/usbWireDtos.ts",
  "src/app/integrations/wire/vehicleWireDtos.ts",
]);

const coreStringUnionAllowlist = new Set(["src/app/core/types/evidence.ts"]);

export function findTypeGovernanceViolations({ frontendRoot = root } = {}) {
  return [
    ...findProductionIntegrationAnyViolations(frontendRoot),
    ...findCoreOpenStringUnionViolations(frontendRoot),
    ...findWireWideRecordViolations(frontendRoot),
  ];
}

function findProductionIntegrationAnyViolations(frontendRoot) {
  const integrationsDir = resolve(frontendRoot, "src/app/integrations");
  const violations = [];
  for (const file of sourceFiles(integrationsDir)) {
    violations.push(
      ...lineViolations(
        frontendRoot,
        file,
        /\bas\s+any\b/,
        "production integrations must use typed normalizers, not raw as any",
      ),
    );
  }
  return violations;
}

function findCoreOpenStringUnionViolations(frontendRoot) {
  const coreDir = resolve(frontendRoot, "src/app/core/types");
  const violations = [];
  for (const file of sourceFiles(coreDir)) {
    const relPath = normalize(frontendRoot, file);
    if (coreStringUnionAllowlist.has(relPath)) {
      continue;
    }
    violations.push(
      ...lineViolations(frontendRoot, file, /\|\s*string\b/, "core enum widening must use KnownOrUnknown<T>"),
    );
  }
  return violations;
}

function findWireWideRecordViolations(frontendRoot) {
  const wireDir = resolve(frontendRoot, "src/app/integrations/wire");
  const violations = [];
  for (const file of sourceFiles(wireDir)) {
    const relPath = normalize(frontendRoot, file);
    if (recordWideAllowlist.has(relPath)) {
      continue;
    }
    violations.push(
      ...lineViolations(
        frontendRoot,
        file,
        /extends\s+Record<string,\s*unknown>/,
        "new wire DTOs must declare explicit fields",
      ),
    );
  }
  return violations;
}

function lineViolations(frontendRoot, file, pattern, reason) {
  const source = readFileSync(file, "utf8");
  return source
    .split(/\r\n|\r|\n/)
    .flatMap((line, index) =>
      pattern.test(line) ? [{ path: normalize(frontendRoot, file), line: index + 1, reason, text: line.trim() }] : [],
    );
}

function sourceFiles(dir) {
  mkdirSync(dir, { recursive: true });
  const files = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = resolve(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...sourceFiles(path));
      continue;
    }
    if (!entry.isFile() || extname(entry.name) !== ".ts" || entry.name.endsWith(".test.ts")) {
      continue;
    }
    if (statSync(path).isFile()) {
      files.push(path);
    }
  }
  return files;
}

function normalize(frontendRoot, file) {
  return relative(frontendRoot, file).replaceAll("\\", "/");
}

function runCli() {
  const violations = findTypeGovernanceViolations();
  if (violations.length === 0) {
    console.log("Frontend type governance check passed.");
    return;
  }

  console.error("Frontend type governance violations:");
  for (const violation of violations) {
    console.error(`- ${violation.path}:${violation.line}: ${violation.reason}: ${violation.text}`);
  }
  process.exit(1);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli();
}
