import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const clientSourceDirs = ["src/app/integrations/clients"];

const migratedTypedRoutePatterns = [
  /^\/api\/tools\/runtime-config(?:\?|$)/,
  /^\/api\/tools\/tshark(?:\?|$)/,
  /^\/api\/tools\/tshark\/allow-dir(?:\?|$)/,
  /^\/api\/tools\/tshark\/allowed-dirs(?:\?|$)/,
  /^\/api\/tools\/tshark\/allowed-dirs\/remove(?:\?|$)/,
  /^\/api\/tools\/allow-dir(?:\?|$)/,
  /^\/api\/tools\/allowed-dirs(?:\?|$)/,
  /^\/api\/tools\/allowed-dirs\/remove(?:\?|$)/,
  /^\/api\/mcp\/config(?:\?|$)/,
  /^\/api\/capture\/(?:start|stop|prepare-replacement|close|status)(?:\?|$)/,
  /^\/api\/packets(?:\?|$)/,
  /^\/api\/packets\/(?:page|locate)(?:\?|$)/,
  /^\/api\/packet(?:\?|$)/,
  /^\/api\/packet\/(?:raw|layers)(?:\?|$)/,
  /^\/api\/hunting(?:\?|$)/,
  /^\/api\/hunting\/config(?:\?|$)/,
  /^\/api\/playbooks(?:\?|$)/,
  /^\/api\/playbooks\/[^/]+(?:\?|$)/,
  /^\/api\/playbooks\/[^/]+\/(?:run|last-run)(?:\?|$)/,
  /^\/api\/hunting\/saved-searches(?:\?|$)/,
  /^\/api\/hunting\/saved-searches\/[^/]+(?:\?|$)/,
  /^\/api\/hunting\/saved-searches\/[^/]+\/execute(?:\?|$)/,
  /^\/api\/hunting\/hypotheses(?:\*|\?|$)/,
  /^\/api\/hunting\/hypotheses\/[^/]+(?:\?|$)/,
  /^\/api\/hunting\/hypotheses\/[^/]+\/(?:evidence|status)(?:\?|$)/,
  /^\/api\/rules\/(?:status|pack\/toggle|check-updates|download|config|conflicts|validate)(?:\?|$)/,
  /^\/api\/analysis\/vehicle\/dbc(?:\?|$)/,
  /^\/api\/vehicle\/dbc\/(?:profiles|add|remove)(?:\?|$)/,
  /^\/api\/security\/tls-config(?:\?|$)/,
  /^\/api\/tools\/misc\/modules(?:\?|$)/,
  /^\/api\/tools\/misc\/import(?:\?|$)/,
  /^\/api\/tools\/misc\/packages\/[^/]+(?:\?|$)/,
  /^\/api\/tools\/misc\/packages\/[^/]+\/invoke(?:\?|$)/,
  /^\/api\/tls(?:\?|$)/,
  /^\/api\/streams\/(?:http|raw|raw\/page|decode|inspect|payload-sources|index|payloads)(?:\?|$)/,
  /^\/api\/objects(?:\?|$)/,
  /^\/api\/objects\/download(?:\?|$)/,
  /^\/api\/tools\/(?:winrm-decrypt|smb3-session-candidates|smb3-random-session-key|ntlm-sessions)(?:\?|$)/,
  /^\/api\/tools\/winrm-decrypt\/export(?:\?|$)/,
  /^\/api\/tools\/(?:http-login-analysis|smtp-analysis|mysql-analysis|shiro-rememberme)(?:\?|$)/,
  /^\/api\/tools\/(?:udp-tunnel|bruteforce)(?:\?|$)/,
  /^\/api\/stats\/traffic\/global(?:\?|$)/,
  /^\/api\/analysis\/(?:industrial|vehicle|media|usb)(?:\?|$)/,
  /^\/api\/analysis\/media\/(?:transcribe|transcribe\/batch|transcribe\/batch\/cancel|transcribe\/batch\/export|export|play)(?:\?|$)/,
  /^\/api\/c2-analysis(?:\?|$)/,
  /^\/api\/c2-analysis\/decrypt(?:\?|$)/,
  /^\/api\/apt-analysis(?:\?|$)/,
  /^\/api\/evidence(?:\?|$)/,
];

const explicitCompatibilityRoutePatterns = [
  /^\/api\/runtime\/identity(?:\?|$)/,
  /^\/api\/capture\/upload(?:\?|$)/,
  /^\/api\/events(?:\?|$)/,
  /^\/api\/tools\/(?:ffmpeg|speech-to-text)(?:\?|$)/,
  /^\/health$/,
];

export function findDesktopGenericIpcAllowlistViolations({ frontendRoot = root } = {}) {
  const violations = [];
  for (const file of listClientSourceFiles(frontendRoot)) {
    const body = readFileSync(file, "utf8");
    for (const candidate of extractRouteCandidates(body)) {
      if (isKnownTypedRoute(candidate.path) || isExplicitCompatibilityRoute(candidate.path)) {
        continue;
      }
      violations.push(
        `${relative(frontendRoot, file).replaceAll("\\", "/")}:${candidate.line}: unclassified backend route ${candidate.path}; add a typed DesktopApp binding or explicit compatibility entry`,
      );
    }
  }
  return violations;
}

function listClientSourceFiles(frontendRoot) {
  const files = [];
  for (const dir of clientSourceDirs) {
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
    } else if (entry.isFile() && entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) {
      files.push(path);
    }
  }
}

function extractRouteCandidates(body) {
  const candidates = [];
  const stringPattern = /(["'`])([^"'`]*(?:\/api\/|\/health)[^"'`]*)\1/g;
  for (const match of body.matchAll(stringPattern)) {
    const raw = String(match[2] ?? "");
    const start = raw.includes("/api/") ? raw.indexOf("/api/") : raw.indexOf("/health");
    if (start < 0) {
      continue;
    }
    const path = normalizeCandidatePath(raw.slice(start));
    candidates.push({ path, line: lineNumberAt(body, match.index ?? 0) });
  }
  return candidates;
}

function normalizeCandidatePath(path) {
  return path.replace(/\$\{[^}]*\}/g, "*").replace(/`/g, "");
}

function isKnownTypedRoute(path) {
  return migratedTypedRoutePatterns.some((pattern) => pattern.test(path));
}

function isExplicitCompatibilityRoute(path) {
  return explicitCompatibilityRoutePatterns.some((pattern) => pattern.test(path));
}

function lineNumberAt(body, index) {
  return body.slice(0, index).split(/\r\n|\r|\n/).length;
}

function runCli() {
  const violations = findDesktopGenericIpcAllowlistViolations();
  if (violations.length === 0) {
    console.log("Desktop generic IPC allowlist check passed.");
    return;
  }
  console.error("Desktop generic IPC allowlist violations:");
  for (const violation of violations) {
    console.error(`- ${violation}`);
  }
  process.exit(1);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli();
}
