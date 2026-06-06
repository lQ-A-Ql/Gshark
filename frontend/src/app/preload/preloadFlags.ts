export function isCodeOnlyRollbackEnabled(): boolean {
  return envFlag("VITE_PRELOAD_CODE_ONLY");
}

export function isTargetDisabledByRuntimeFlag(targetId: string): boolean {
  const raw = String((import.meta.env as Record<string, unknown>).VITE_PRELOAD_DISABLED_TARGETS ?? "");
  return raw
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .includes(targetId);
}

export function envFlag(name: string): boolean {
  return String((import.meta.env as Record<string, unknown>)[name] ?? "").trim() === "1";
}
