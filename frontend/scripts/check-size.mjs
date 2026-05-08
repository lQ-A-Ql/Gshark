import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const budgets = [
  {
    path: "src/app/integrations/wailsBridge.ts",
    maxLines: 575,
    reason: "bridge facade should keep shrinking as domain clients move out",
  },
  {
    path: "src/app/state/SentinelContext.tsx",
    maxLines: 1630,
    reason: "provider remains oversized and should not absorb new state domains",
  },
  {
    path: "src/app/pages/C2Analysis.tsx",
    maxLines: 1330,
    reason: "C2 page should move forms, tables, and result panels into feature components",
  },
  {
    path: "src/app/pages/UsbAnalysis.tsx",
    maxLines: 1060,
    reason: "USB page is near the large-page threshold",
  },
  {
    path: "src/app/pages/MediaAnalysis.tsx",
    maxLines: 990,
    reason: "media page is near the large-page threshold",
  },
];

function countLines(text) {
  if (text.length === 0) {
    return 0;
  }
  return text.split(/\r\n|\r|\n/).length;
}

const failures = [];

for (const budget of budgets) {
  const absolutePath = resolve(root, budget.path);
  const lines = countLines(readFileSync(absolutePath, "utf8"));
  if (lines > budget.maxLines) {
    failures.push({ ...budget, lines });
  }
}

if (failures.length > 0) {
  console.error("Frontend size budget exceeded:");
  for (const failure of failures) {
    console.error(`- ${failure.path}: ${failure.lines}/${failure.maxLines} lines. ${failure.reason}`);
  }
  process.exit(1);
}

console.log("Frontend size budget passed.");
