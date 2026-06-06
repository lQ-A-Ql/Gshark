import { pathToFileURL } from "node:url";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export function findPreloadBudgetViolations({
  preloadTargetsPath = resolve(root, "src/app/preload/preloadTargets.ts"),
} = {}) {
  const source = readFileSync(preloadTargetsPath, "utf8");
  const violations = [];
  const objectBodies = extractTargetObjects(source);
  for (const body of objectBodies) {
    const targetId = stringProp(body, "targetId") ?? "<unknown>";
    const cost = stringProp(body, "cost");
    const kind = stringProp(body, "kind");
    const enabledByDefault = booleanProp(body, "enabledByDefault");
    const timeoutMs = propExpression(body, "timeoutMs");
    const featureFlag = stringProp(body, "featureFlag");

    for (const required of [
      "targetId",
      "routePath",
      "kind",
      "cost",
      "enabledByDefault",
      "triggers",
      "requiresCapture",
      "timeoutMs",
      "canAbort",
    ]) {
      if (!new RegExp(`\\b${required}\\s*(?::|,)`).test(body)) {
        violations.push(`${targetId}: missing ${required}`);
      }
    }
    if ((kind === "light-data" || kind === "heavy-analysis" || cost === "medium" || cost === "high") && !timeoutMs) {
      violations.push(`${targetId}: timeoutMs is required for ${kind ?? cost}`);
    }
    if (cost === "high" && enabledByDefault === true) {
      violations.push(`${targetId}: HIGH target must be default off`);
    }
    if ((cost === "high" || kind === "heavy-analysis") && !featureFlag) {
      violations.push(`${targetId}: heavy target requires featureFlag`);
    }
  }
  if (!source.includes("PRELOAD_TARGETS")) {
    violations.push("PRELOAD_TARGETS export missing");
  }
  return violations;
}

function extractTargetObjects(source) {
  const bodies = [];
  for (const block of ["lightTargets", "heavyTargets"]) {
    const start = source.indexOf(`const ${block}`);
    if (start < 0) continue;
    const arrayStart = source.indexOf("[", start);
    const arrayEnd = source.indexOf("];", arrayStart);
    if (arrayStart < 0 || arrayEnd < 0) continue;
    bodies.push(...extractObjectLiterals(source.slice(arrayStart, arrayEnd + 1)));
  }
  const mapStart = source.indexOf("NAV_ROUTE_PATHS.map");
  if (mapStart >= 0) {
    const mapEnd = source.indexOf("));", mapStart);
    const mapBodies = extractObjectLiterals(source.slice(mapStart, mapEnd + 2));
    if (mapBodies[0]) bodies.push(mapBodies[0]);
  }
  return bodies;
}

function extractObjectLiterals(source) {
  const out = [];
  let depth = 0;
  let start = -1;
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (char === "{") {
      if (depth === 0) start = index;
      depth += 1;
    } else if (char === "}") {
      depth -= 1;
      if (depth === 0 && start >= 0) {
        out.push(source.slice(start, index + 1));
        start = -1;
      }
    }
  }
  return out;
}

function stringProp(body, name) {
  return body.match(new RegExp(`\\b${name}\\s*:\\s*["']([^"']+)["']`))?.[1];
}

function booleanProp(body, name) {
  const value = body.match(new RegExp(`\\b${name}\\s*:\\s*(true|false)`))?.[1];
  return value === undefined ? undefined : value === "true";
}

function propExpression(body, name) {
  return body.match(new RegExp(`\\b${name}\\s*:\\s*([^,\\n}]+)`))?.[1]?.trim();
}

function runCli() {
  const violations = findPreloadBudgetViolations();
  if (violations.length === 0) {
    console.log("Preload budget check passed.");
    return;
  }
  console.error("Preload budget violations:");
  for (const violation of violations) console.error(`- ${violation}`);
  process.exit(1);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli();
}
