import { PRELOAD_BUDGET, type PreloadCost, type PreloadKind, type PreloadTrigger } from "./preloadBudget";

export type PreloadTarget = {
  targetId: string;
  routePath: string;
  kind: PreloadKind;
  cost: PreloadCost;
  enabledByDefault: boolean;
  triggers: PreloadTrigger[];
  requiresCapture: boolean;
  timeoutMs: number;
  canAbort: boolean;
  featureFlag?: string;
};

const NAV_ROUTE_PATHS = [
  "/",
  "/analysis-cockpit",
  "/c2-analysis",
  "/apt-analysis",
  "/evidence",
  "/traffic-graph",
  "/industrial-analysis",
  "/vehicle-analysis",
  "/media-analysis",
  "/usb-analysis",
  "/hunting",
  "/objects",
  "/misc",
  "/updates",
  "/rules",
] as const;

const codeTargets: PreloadTarget[] = NAV_ROUTE_PATHS.map((routePath) => ({
  targetId: `code:${routePath}`,
  routePath,
  kind: "code",
  cost: "low",
  enabledByDefault: true,
  triggers: ["hover", "focus", "idle"],
  requiresCapture: false,
  timeoutMs: 0,
  canAbort: false,
}));

const lightTargets: PreloadTarget[] = [
  {
    targetId: "light:/traffic-graph",
    routePath: "/traffic-graph",
    kind: "light-data",
    cost: "medium",
    enabledByDefault: false,
    triggers: ["capture-ready", "route-enter"],
    requiresCapture: true,
    timeoutMs: PRELOAD_BUDGET.lightDataTimeoutMs,
    canAbort: true,
    featureFlag: "VITE_PRELOAD_LIGHT_DATA",
  },
  {
    targetId: "light:/evidence",
    routePath: "/evidence",
    kind: "light-data",
    cost: "medium",
    enabledByDefault: false,
    triggers: ["capture-ready", "route-enter"],
    requiresCapture: true,
    timeoutMs: PRELOAD_BUDGET.lightDataTimeoutMs,
    canAbort: true,
    featureFlag: "VITE_PRELOAD_LIGHT_DATA",
  },
  {
    targetId: "light:/hunting",
    routePath: "/hunting",
    kind: "light-data",
    cost: "medium",
    enabledByDefault: false,
    triggers: ["route-enter"],
    requiresCapture: false,
    timeoutMs: PRELOAD_BUDGET.lightDataTimeoutMs,
    canAbort: true,
    featureFlag: "VITE_PRELOAD_LIGHT_DATA",
  },
  {
    targetId: "light:/rules",
    routePath: "/rules",
    kind: "light-data",
    cost: "medium",
    enabledByDefault: false,
    triggers: ["route-enter"],
    requiresCapture: false,
    timeoutMs: PRELOAD_BUDGET.lightDataTimeoutMs,
    canAbort: true,
    featureFlag: "VITE_PRELOAD_LIGHT_DATA",
  },
];

const heavyTargets: PreloadTarget[] = ["/c2-analysis", "/industrial-analysis", "/vehicle-analysis", "/usb-analysis"].map(
  (routePath) => ({
    targetId: `heavy:${routePath}`,
    routePath,
    kind: "heavy-analysis",
    cost: "high",
    enabledByDefault: false,
    triggers: ["hover", "focus", "idle"],
    requiresCapture: true,
    timeoutMs: PRELOAD_BUDGET.heavyWarmupTimeoutMs,
    canAbort: true,
    featureFlag: "VITE_PRELOAD_HEAVY_WARMUP",
  }),
);

export const PRELOAD_TARGETS: PreloadTarget[] = [...codeTargets, ...lightTargets, ...heavyTargets];

export const PRELOAD_DISABLED_HEAVY_ROUTES = ["/media-analysis", "/objects", "/misc", "/apt-analysis"] as const;

export function findPreloadTarget(targetId: string): PreloadTarget | undefined {
  return PRELOAD_TARGETS.find((target) => target.targetId === targetId);
}

export function findCodePreloadTarget(routePath: string): PreloadTarget | undefined {
  return PRELOAD_TARGETS.find((target) => target.kind === "code" && target.routePath === routePath);
}

export function validatePreloadTargets(targets: PreloadTarget[] = PRELOAD_TARGETS): string[] {
  const errors: string[] = [];
  const seen = new Set<string>();
  for (const target of targets) {
    if (!target.targetId.trim()) errors.push("targetId is required");
    if (!target.routePath.trim()) errors.push(`${target.targetId}: routePath is required`);
    if (seen.has(target.targetId)) errors.push(`${target.targetId}: duplicate targetId`);
    seen.add(target.targetId);
    if (target.cost !== "low" && target.timeoutMs <= 0) errors.push(`${target.targetId}: timeoutMs is required`);
    if (target.cost === "high" && target.enabledByDefault) errors.push(`${target.targetId}: HIGH must be default off`);
    if (target.cost === "high" && !target.featureFlag) errors.push(`${target.targetId}: HIGH requires featureFlag`);
    if (target.kind === "heavy-analysis" && !target.canAbort) errors.push(`${target.targetId}: heavy must be abortable`);
  }
  return errors;
}
