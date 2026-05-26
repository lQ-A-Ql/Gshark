import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(root, "..");

const sourceDirs = ["src/app/integrations"];

const ignoredSourcePatterns = [
  /^src\/app\/integrations\/desktopBridge\.ts$/,
  /^src\/app\/integrations\/desktopTransportBinding\.ts$/,
  /^src\/app\/integrations\/desktopTypedBridge[A-Za-z0-9]*\.ts$/,
  /\.test\.ts$/,
];

const allowedOldBindingMethodsByFile = {
  "src/app/integrations/backendClients.ts": ["DesktopApp"],
  "src/app/integrations/httpBridge.ts": ["GetBackendAuthToken"],
  "src/app/integrations/ipcBackendTransport.ts": ["InvokeBackendJSON", "InvokeBackendBlob", "InvokeBackendText"],
  "src/app/integrations/clients/captureClient.ts": ["OpenCaptureDialog"],
  "src/app/integrations/clients/desktopClient.ts": [
    "BackendStatus",
    "CheckAppUpdate",
    "InstallAppUpdate",
    "OpenDBCDialog",
  ],
};

const exitPlanTokens = [
  "status: guarded",
  "InvokeBackendJSON",
  "InvokeBackendBlob",
  "InvokeBackendText",
  "typed_binding_required",
  "Three consecutive green rounds",
  "desktopWebviewTyped.directBackendApiRequestCount = 0",
  "VITE_DESKTOP_DISABLE_GENERIC_IPC=1",
  "DisableGenericIpcAdapterExperiment",
  "genericIpcDisableExperimentBuildFlag = true",
  "Browser-dev HTTP/SSE remains green",
  "Do not remove browser-dev HTTP/SSE debugging",
];

export function findDesktopOldBindingCompatViolations({
  frontendRoot = root,
  exitPlanPath = resolve(repoRoot, "docs/desktop-ipc-old-binding-exit-plan.md"),
} = {}) {
  const violations = [];
  for (const file of listIntegrationSourceFiles(frontendRoot)) {
    const relativeFile = relative(frontendRoot, file).replaceAll("\\", "/");
    if (ignoredSourcePatterns.some((pattern) => pattern.test(relativeFile))) {
      continue;
    }
    const allowedMethods = new Set(allowedOldBindingMethodsByFile[relativeFile] ?? []);
    for (const candidate of extractDesktopBindingUses(readFileSync(file, "utf8"))) {
      if (allowedMethods.has(candidate.method)) {
        continue;
      }
      violations.push(
        `${relativeFile}:${candidate.line}: old generated DesktopApp binding ${candidate.method} is not an approved compatibility use; route desktop data-plane work through desktopBridge or add a typed override`,
      );
    }
  }
  validateExitPlan(exitPlanPath, violations);
  return violations;
}

function validateExitPlan(exitPlanPath, violations) {
  if (!existsSync(exitPlanPath)) {
    violations.push("docs/desktop-ipc-old-binding-exit-plan.md: missing old generated binding exit plan");
    return;
  }
  const plan = readFileSync(exitPlanPath, "utf8");
  for (const token of exitPlanTokens) {
    if (!plan.includes(token)) {
      violations.push(`docs/desktop-ipc-old-binding-exit-plan.md: missing exit-plan token ${token}`);
    }
  }
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

function extractDesktopBindingUses(body) {
  const candidates = [];
  const patterns = [
    /\bdesktopApp\s*(?:\?\.|\.)\s*([A-Z][A-Za-z0-9_]*)/g,
    /\bgetDesktopAppBinding\(\)\s*\?\.\s*([A-Z][A-Za-z0-9_]*)/g,
    /\bgo\s*\?\.\s*main\s*\?\.\s*(DesktopApp)\b/g,
  ];
  for (const pattern of patterns) {
    for (const match of body.matchAll(pattern)) {
      if (isCommentOnlyLine(body, match.index ?? 0)) {
        continue;
      }
      candidates.push({
        method: String(match[1] ?? ""),
        line: lineNumberAt(body, match.index ?? 0),
      });
    }
  }
  return candidates;
}

function isCommentOnlyLine(body, index) {
  const lineStart = body.lastIndexOf("\n", index) + 1;
  return body.slice(lineStart, index).trimStart().startsWith("//");
}

function lineNumberAt(body, index) {
  return body.slice(0, index).split(/\r\n|\r|\n/).length;
}

function runCli() {
  const violations = findDesktopOldBindingCompatViolations();
  if (violations.length === 0) {
    console.log("Desktop old binding compatibility check passed.");
    return;
  }
  console.error("Desktop old binding compatibility violations:");
  for (const violation of violations) {
    console.error(`- ${violation}`);
  }
  process.exit(1);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  runCli();
}
