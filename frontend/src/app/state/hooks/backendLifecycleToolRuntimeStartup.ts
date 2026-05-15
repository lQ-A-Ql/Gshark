import type { Dispatch, SetStateAction } from "react";
import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../../core/types";
import type { TSharkStatus } from "../../integrations/clients/toolRuntimeClient";
import { backendClients } from "../../integrations/backendClients";
import { isOperationTimeoutError, withAbortableTimeout } from "../../utils/asyncControl";
import { STARTUP_TOOL_RUNTIME_TIMEOUT_MS } from "../captureConstants";
import { toTSharkStatus } from "../tsharkStatusState";
import { writeUserToolRuntimeConfig } from "../toolRuntimeStorage";
import {
  TOOL_RUNTIME_CONFIG_FIELDS,
  hasExplicitFields,
  type ToolRuntimeConfigExplicitFields,
  type ToolRuntimeConfigState,
} from "../toolRuntimeStorageConfig";

interface ApplyStartupRuntimeSnapshotOptions {
  readonly isCancelled: () => boolean;
  readonly setBackendStatus: Dispatch<SetStateAction<string>>;
  readonly setToolRuntimeSnapshot: Dispatch<SetStateAction<ToolRuntimeSnapshot | null>>;
  readonly setTsharkStatus: Dispatch<SetStateAction<TSharkStatus>>;
  readonly snapshot: ToolRuntimeSnapshot;
}

export function applyStartupRuntimeSnapshot({
  isCancelled,
  setBackendStatus,
  setToolRuntimeSnapshot,
  setTsharkStatus,
  snapshot,
}: ApplyStartupRuntimeSnapshotOptions) {
  if (isCancelled()) return;
  setToolRuntimeSnapshot(snapshot);
  setTsharkStatus(toTSharkStatus(snapshot.tshark));
  if (snapshot.tshark.available && snapshot.tshark.message && snapshot.tshark.message !== "ok") {
    setBackendStatus(snapshot.tshark.message);
  }
  if (!snapshot.tshark.available) {
    setBackendStatus(snapshot.tshark.message || "未检测到 TShark，可在设置中配置路径");
  }
}

interface SyncSavedToolRuntimeConfigOptions extends Omit<ApplyStartupRuntimeSnapshotOptions, "snapshot"> {
  readonly explicitFields: ToolRuntimeConfigExplicitFields;
  readonly savedConfig: ToolRuntimeConfig;
  readonly setIsToolRuntimeLoading: Dispatch<SetStateAction<boolean>>;
  readonly setToolRuntimeCheckDegraded: Dispatch<SetStateAction<boolean>>;
}

export async function syncSavedToolRuntimeConfig({
  explicitFields,
  isCancelled,
  savedConfig,
  setBackendStatus,
  setIsToolRuntimeLoading,
  setToolRuntimeCheckDegraded,
  setToolRuntimeSnapshot,
  setTsharkStatus,
}: SyncSavedToolRuntimeConfigOptions) {
  if (isCancelled()) return;
  setIsToolRuntimeLoading(true);
  try {
    const snapshot = await withAbortableTimeout(
      (signal) => backendClients.runtime.updateToolRuntimeConfig(savedConfig, signal),
      STARTUP_TOOL_RUNTIME_TIMEOUT_MS,
      "startup tool runtime config sync timed out",
    );
    setToolRuntimeCheckDegraded(false);
    applyStartupRuntimeSnapshot({ isCancelled, setBackendStatus, setToolRuntimeSnapshot, setTsharkStatus, snapshot });
    if (!isCancelled()) writeUserToolRuntimeConfig(snapshot.config, explicitFields);
  } catch (error) {
    if (!isCancelled()) {
      const prefix = isOperationTimeoutError(error) ? "运行时组件配置同步超时" : "运行时组件配置同步失败";
      setToolRuntimeCheckDegraded(true);
      setBackendStatus(`${prefix}；已先进入主界面，可在设置侧栏重试`);
      setTsharkStatus((prev) => ({ ...prev, message: `${prefix}，请稍后在设置侧栏刷新状态` }));
    }
  } finally {
    if (!isCancelled()) setIsToolRuntimeLoading(false);
  }
}

export function toolRuntimeConfigsEqual(left: ToolRuntimeConfig, right: ToolRuntimeConfig): boolean {
  return (
    normalizePath(left.tsharkPath) === normalizePath(right.tsharkPath) &&
    normalizePath(left.ffmpegPath) === normalizePath(right.ffmpegPath) &&
    normalizePath(left.pythonPath) === normalizePath(right.pythonPath) &&
    normalizePath(left.voskModelPath) === normalizePath(right.voskModelPath) &&
    Boolean(left.yaraEnabled) === Boolean(right.yaraEnabled) &&
    normalizePath(left.yaraBin) === normalizePath(right.yaraBin) &&
    normalizePath(left.yaraRules) === normalizePath(right.yaraRules) &&
    Number(left.yaraTimeoutMs || 25000) === Number(right.yaraTimeoutMs || 25000)
  );
}

export function startupToolRuntimeConfigForSync(
  savedState: ToolRuntimeConfigState,
  backendConfig: ToolRuntimeConfig,
): ToolRuntimeConfig | null {
  if (savedState.source === "missing" || savedState.source === "observed-backend-snapshot") {
    return null;
  }
  if (!hasExplicitFields(savedState.explicitFields)) {
    return null;
  }
  const next = { ...backendConfig };
  for (const field of TOOL_RUNTIME_CONFIG_FIELDS) {
    if (savedState.explicitFields[field]) {
      next[field] = savedState.config[field] as never;
    }
  }
  return next;
}

function normalizePath(value: unknown): string {
  return String(value ?? "").trim();
}
