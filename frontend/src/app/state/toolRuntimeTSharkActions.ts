import type { Dispatch, SetStateAction } from "react";
import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../core/types";
import type { TSharkStatus } from "../integrations/clients/toolRuntimeClient";
import { backendClients } from "../integrations/backendClients";
import { describeTSharkReadyStatus, toTSharkStatus } from "./tsharkStatusState";
import { EMPTY_TSHARK_STATUS, mergeTSharkStatusIntoSnapshot } from "./toolRuntimeSnapshotMutations";
import { readToolRuntimeConfig, writeUserToolRuntimeConfig } from "./toolRuntimeStorage";
import { explicitFieldsFromPatch, type ToolRuntimeConfigExplicitFields } from "./toolRuntimeStorageConfig";

interface SetTSharkPathContext {
  setBackendStatus: (status: string) => void;
  setToolRuntimeCheckDegraded: Dispatch<SetStateAction<boolean>>;
  setTsharkStatus: Dispatch<SetStateAction<TSharkStatus>>;
  setToolRuntimeSnapshot: Dispatch<SetStateAction<ToolRuntimeSnapshot | null>>;
  toolRuntimeSnapshot?: ToolRuntimeSnapshot | null;
}

export async function setTSharkPathAction(
  path: string,
  backendConnected: boolean,
  ctx: SetTSharkPathContext,
): Promise<void> {
  const nextPath = path.trim();
  writeUserToolRuntimeConfig(
    { ...(ctx.toolRuntimeSnapshot?.config ?? readToolRuntimeConfig()), tsharkPath: nextPath },
    { tsharkPath: true },
  );
  if (!backendConnected) {
    ctx.setTsharkStatus((prev) => ({ ...prev, customPath: nextPath, usingCustomPath: nextPath.length > 0 }));
    return;
  }
  const status = await backendClients.runtime.setTSharkPath(nextPath);
  ctx.setToolRuntimeCheckDegraded(false);
  ctx.setTsharkStatus(status);
  ctx.setToolRuntimeSnapshot((prev) => mergeTSharkStatusIntoSnapshot(prev, nextPath, status));
  if (status.available) {
    ctx.setBackendStatus(describeTSharkReadyStatus(status));
    return;
  }
  ctx.setBackendStatus(status.message || "tshark is unavailable");
  throw new Error(status.message || "tshark is unavailable");
}

interface AllowTSharkDirContext {
  setBackendStatus: (status: string) => void;
  setTsharkStatus: Dispatch<SetStateAction<TSharkStatus>>;
  setToolRuntimeSnapshot: Dispatch<SetStateAction<ToolRuntimeSnapshot | null>>;
  toolRuntimeSnapshot?: ToolRuntimeSnapshot | null;
}

function updateLocalTSharkAllowedDirs(
  nextDirs: string[],
  ctx: Pick<AllowTSharkDirContext, "setToolRuntimeSnapshot" | "toolRuntimeSnapshot">,
): void {
  const base = ctx.toolRuntimeSnapshot?.config ?? readToolRuntimeConfig();
  const nextConfig: ToolRuntimeConfig = { ...base, tsharkAllowedDirs: nextDirs };
  const fields: ToolRuntimeConfigExplicitFields = {
    ...explicitFieldsFromPatch({ tsharkAllowedDirs: nextDirs }),
    tsharkAllowedDirs: true,
  };
  writeUserToolRuntimeConfig(nextConfig, fields);
  ctx.setToolRuntimeSnapshot((prev) =>
    prev
      ? {
          ...prev,
          config: { ...prev.config, tsharkAllowedDirs: nextDirs },
        }
      : prev,
  );
}

export async function allowTSharkDirAction(
  dir: string,
  backendConnected: boolean,
  ctx: AllowTSharkDirContext,
): Promise<TSharkStatus> {
  const cleanDir = dir.trim();
  if (!cleanDir) throw new Error("directory is empty");

  const base = ctx.toolRuntimeSnapshot?.config ?? readToolRuntimeConfig();
  const existing = base.tsharkAllowedDirs ?? [];
  const lowerDir = cleanDir.toLowerCase();

  if (!backendConnected) {
    if (!existing.some((d) => d.toLowerCase() === lowerDir)) {
      updateLocalTSharkAllowedDirs([...existing, cleanDir], ctx);
    }
    return ctx.toolRuntimeSnapshot ? toTSharkStatus(ctx.toolRuntimeSnapshot.tshark) : EMPTY_TSHARK_STATUS;
  }

  const status = await backendClients.runtime.allowTSharkDir(cleanDir);
  ctx.setTsharkStatus(status);
  ctx.setToolRuntimeSnapshot((prev) => mergeTSharkStatusIntoSnapshot(prev, status.customPath, status));
  if (status.available) {
    ctx.setBackendStatus(describeTSharkReadyStatus(status));
  } else {
    ctx.setBackendStatus(status.message || "tshark is unavailable");
  }

  const returnedDir = status.extraAllowedDir ?? cleanDir;
  if (returnedDir && !existing.some((d) => d.toLowerCase() === returnedDir.toLowerCase())) {
    updateLocalTSharkAllowedDirs([...existing, returnedDir], ctx);
  }
  return status;
}

export async function removeTSharkAllowedDirAction(
  dir: string,
  backendConnected: boolean,
  ctx: AllowTSharkDirContext,
): Promise<TSharkStatus> {
  const cleanDir = dir.trim();
  if (!cleanDir) throw new Error("directory is empty");

  const base = ctx.toolRuntimeSnapshot?.config ?? readToolRuntimeConfig();
  const existing = base.tsharkAllowedDirs ?? [];
  const lowerDir = cleanDir.toLowerCase();

  if (!backendConnected) {
    const nextDirs = existing.filter((d) => d.toLowerCase() !== lowerDir);
    if (nextDirs.length !== existing.length) {
      updateLocalTSharkAllowedDirs(nextDirs, ctx);
    }
    return ctx.toolRuntimeSnapshot ? toTSharkStatus(ctx.toolRuntimeSnapshot.tshark) : EMPTY_TSHARK_STATUS;
  }

  const status = await backendClients.runtime.removeTSharkAllowedDir(cleanDir);
  ctx.setTsharkStatus(status);
  ctx.setToolRuntimeSnapshot((prev) => mergeTSharkStatusIntoSnapshot(prev, status.customPath, status));
  if (status.available) {
    ctx.setBackendStatus(describeTSharkReadyStatus(status));
  } else {
    ctx.setBackendStatus(status.message || "tshark is unavailable");
  }

  const nextDirs = existing.filter((d) => d.toLowerCase() !== lowerDir);
  updateLocalTSharkAllowedDirs(nextDirs, ctx);
  return status;
}

export async function refreshTSharkAllowedDirsAction(
  backendConnected: boolean,
  ctx: Pick<AllowTSharkDirContext, "setToolRuntimeSnapshot" | "toolRuntimeSnapshot">,
): Promise<string[]> {
  if (!backendConnected) {
    return ctx.toolRuntimeSnapshot?.config.tsharkAllowedDirs ?? readToolRuntimeConfig().tsharkAllowedDirs ?? [];
  }
  const dirs = await backendClients.runtime.listTSharkAllowedDirs();
  const base = ctx.toolRuntimeSnapshot?.config ?? readToolRuntimeConfig();
  const nextConfig: ToolRuntimeConfig = { ...base, tsharkAllowedDirs: dirs };
  writeUserToolRuntimeConfig(nextConfig, { tsharkAllowedDirs: true });
  ctx.setToolRuntimeSnapshot((prev) =>
    prev
      ? {
          ...prev,
          config: { ...prev.config, tsharkAllowedDirs: dirs },
        }
      : prev,
  );
  return dirs;
}
