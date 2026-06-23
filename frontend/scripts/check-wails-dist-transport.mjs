import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const frontendRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const distRoot = join(frontendRoot, "dist");

const forbiddenPatterns = [
  { label: "loopback backend port", pattern: /127\.0\.0\.1:17891/ },
  { label: "backend events endpoint", pattern: /\/api\/events/ },
  { label: "SSE content type", pattern: /text\/event-stream/ },
  { label: "browser EventSource constructor", pattern: /\bEventSource\b/ },
  { label: "HTTP fallback marker", pattern: /http-fallback/ },
];

function collectFiles(dir) {
  if (!existsSync(dir)) {
    return [];
  }
  const files = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    const stats = statSync(path);
    if (stats.isDirectory()) {
      files.push(...collectFiles(path));
      continue;
    }
    if (/\.(?:js|html|css|json|map)$/i.test(name)) {
      files.push(path);
    }
  }
  return files;
}

const violations = [];
for (const file of collectFiles(distRoot)) {
  const body = readFileSync(file, "utf8");
  for (const { label, pattern } of forbiddenPatterns) {
    if (pattern.test(body)) {
      violations.push(`${file.replace(frontendRoot + "\\", "").replaceAll("\\", "/")}: ${label}`);
    }
  }
}

if (violations.length > 0) {
  console.error(
    "Wails dist transport check failed; packaged desktop assets must not contain browser HTTP/SSE fallback:",
  );
  for (const violation of violations) {
    console.error(`- ${violation}`);
  }
  process.exit(1);
}

console.log("Wails dist transport check passed.");
