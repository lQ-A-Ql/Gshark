export type DesktopGenericIpcPolicy = "compat" | "disabled";

export const DESKTOP_GENERIC_IPC_POLICY_ENV = "VITE_DESKTOP_GENERIC_IPC_POLICY";
export const LEGACY_DESKTOP_GENERIC_IPC_DISABLE_ENV = "VITE_DESKTOP_DISABLE_GENERIC_IPC";

type DesktopGenericIpcEnv = Record<string, unknown>;

export function resolveDesktopGenericIpcPolicy(env: DesktopGenericIpcEnv = import.meta.env): DesktopGenericIpcPolicy {
  const explicitPolicy = String(env[DESKTOP_GENERIC_IPC_POLICY_ENV] ?? "")
    .trim()
    .toLowerCase();
  if (explicitPolicy === "disabled") {
    return "disabled";
  }
  if (explicitPolicy === "compat") {
    return "compat";
  }
  return "disabled";
}

export function isDesktopGenericIpcDisabled(env: DesktopGenericIpcEnv = import.meta.env): boolean {
  return resolveDesktopGenericIpcPolicy(env) === "disabled";
}

export function isLegacyDesktopGenericIpcDisableExperimentEnabled(
  env: DesktopGenericIpcEnv = import.meta.env,
): boolean {
  return String(env[LEGACY_DESKTOP_GENERIC_IPC_DISABLE_ENV] ?? "").trim() === "1";
}
