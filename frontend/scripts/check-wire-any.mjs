import { mkdirSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const wireAnyPattern = /\bany\b/;

export function findWireAnyViolations({ frontendRoot = root } = {}) {
  const wireDir = resolve(frontendRoot, "src/app/integrations/wire");
  const violations = [];
  for (const file of sourceFiles(wireDir)) {
    const source = readFileSync(file, "utf8");
    const lines = source.split(/\r\n|\r|\n/);
    lines.forEach((line, index) => {
      if (wireAnyPattern.test(line)) {
        violations.push({
          path: relative(frontendRoot, file).replaceAll("\\", "/"),
          line: index + 1,
          text: line.trim(),
        });
      }
    });
  }
  return violations;
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

function runCli() {
  const violations = findWireAnyViolations();
  if (violations.length === 0) {
    console.log("Frontend wire any check passed.");
    return;
  }

  console.error("Frontend wire raw any violations:");
  for (const violation of violations) {
    console.error(`- ${violation.path}:${violation.line}: ${violation.text}`);
  }
  process.exit(1);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli();
}
