import type { Dispatch, SetStateAction } from "react";
import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../../core/types";
import type { TSharkStatus } from "../../integrations/clients/toolRuntimeClient";
import { backendClients } from "../../integrations/backendClients";
import { isOperationTimeoutError, withAbortableTimeout } from "../../utils/asyncControl";
import { STARTUP_TOOL_RUNTIME_TIMEOUT_MS } from "../captureConstants";
import { FULL_TOOL_RUNTIME_TIMEOUT_MS } from "../toolRuntimeProbeActions";
import { toTSharkStatus } from "../tsharkStatusState";
import {
  describeToolRuntimeProbeError,
  detectToolRuntimeProbeTransport,
  type ToolRuntimeProbeState,
  type ToolRuntimeProbeTransport,
} from "../toolRuntimeProbeState";
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
  readonly setToolRuntimeProbeState: Dispatch<SetStateAction<ToolRuntimeProbeState>>;
  readonly setLastToolRuntimeProbeError: Dispatch<SetStateAction<string>>;
  readonly snapshot: ToolRuntimeSnapshot;
}

export function applyStartupRuntimeSnapshot({
  isCancelled,
  setBackendStatus,
  setToolRuntimeSnapshot,
  setTsharkStatus,
  setToolRuntimeProbeState,
  setLastToolRuntimeProbeError,
  snapshot,
}: ApplyStartupRuntimeSnapshotOptions) {
  if (isCancelled()) return;
  setToolRuntimeSnapshot(snapshot);
  setTsharkStatus(toTSharkStatus(snapshot.tshark));
  setToolRuntimeProbeState(snapshot.probeMode === "fast" ? "partial" : "ready");
  setLastToolRuntimeProbeError("");
  if (snapshot.tshark.available && snapshot.tshark.message && snapshot.tshark.message !== "ok") {
    setBackendStatus(snapshot.tshark.message);
  }
  if (!snapshot.tshark.available) {
    setBackendStatus(snapshot.tshark.message || "未检测到 TShark，可在设置中配置路径");
  }
}

interface MarkRuntimeProbeFailureOptions {
  readonly error: unknown;
  readonly isCancelled: () => boolean;
  readonly timeoutPrefix: string;
  readonly failurePrefix: string;
  readonly retryMessage: string;
  readonly setBackendStatus: Dispatch<SetStateAction<string>>;
  readonly setToolRuntimeCheckDegraded: Dispatch<SetStateAction<boolean>>;
  readonly setToolRuntimeProbeState: Dispatch<SetStateAction<ToolRuntimeProbeState>>;
  readonly setLastToolRuntimeProbeError: Dispatch<SetStateAction<string>>;
  readonly setTsharkStatus: Dispatch<SetStateAction<TSharkStatus>>;
}

export function markRuntimeProbeFailure({
  error,
  failurePrefix,
  isCancelled,
  retryMessage,
  setBackendStatus,
  setLastToolRuntimeProbeError,
  setToolRuntimeCheckDegraded,
  setToolRuntimeProbeState,
  setTsharkStatus,
  timeoutPrefix,
}: MarkRuntimeProbeFailureOptions) {
  if (isCancelled()) return;
  const prefix = isOperationTimeoutError(error) ? timeoutPrefix : failurePrefix;
  const detail = describeToolRuntimeProbeError(error);
  setToolRuntimeCheckDegraded(true);
  setToolRuntimeProbeState("failed");
  setLastToolRuntimeProbeError(detail);
  setBackendStatus(`${prefix}：${detail} ${retryMessage}`);
  setTsharkStatus((prev) => ({ ...prev, message: `${prefix}：${detail}` }));
}

interface SyncSavedToolRuntimeConfigOptions extends Omit<ApplyStartupRuntimeSnapshotOptions, "snapshot"> {
  readonly explicitFields: ToolRuntimeConfigExplicitFields;
  readonly savedConfig: ToolRuntimeConfig;
  readonly setIsToolRuntimeLoading: Dispatch<SetStateAction<boolean>>;
  readonly setToolRuntimeCheckDegraded: Dispatch<SetStateAction<boolean>>;
  readonly setToolRuntimeProbeTransport: Dispatch<SetStateAction<ToolRuntimeProbeTransport>>;
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
  setToolRuntimeProbeState,
  setToolRuntimeProbeTransport,
  setLastToolRuntimeProbeError,
}: SyncSavedToolRuntimeConfigOptions) {
  if (isCancelled()) return;
  setIsToolRuntimeLoading(true);
  setToolRuntimeProbeState("probing_fast");
  setToolRuntimeProbeTransport(detectToolRuntimeProbeTransport());
  setLastToolRuntimeProbeError("");
  try {
    const snapshot = await withAbortableTimeout(
      (signal) => backendClients.runtime.updateToolRuntimeConfig(savedConfig, signal, "fast"),
      STARTUP_TOOL_RUNTIME_TIMEOUT_MS,
      "startup fast tool runtime config sync timed out",
    );
    setToolRuntimeCheckDegraded(false);
    setToolRuntimeProbeTransport(snapshot.transport ?? detectToolRuntimeProbeTransport());
    applyStartupRuntimeSnapshot({
      isCancelled,
      setBackendStatus,
      setToolRuntimeSnapshot,
      setTsharkStatus,
      setToolRuntimeProbeState,
      setLastToolRuntimeProbeError,
      snapshot,
    });
    if (!isCancelled()) writeUserToolRuntimeConfig(snapshot.config, explicitFields);
    if (!isCancelled()) {
      void loadFullToolRuntimeInBackground({
        isCancelled,
        setBackendStatus,
        setToolRuntimeSnapshot,
        setTsharkStatus,
        setToolRuntimeProbeState,
        setToolRuntimeProbeTransport,
        setLastToolRuntimeProbeError,
        setToolRuntimeCheckDegraded,
      });
    }
  } catch (error) {
    markRuntimeProbeFailure({
      error,
      failurePrefix: "运行时组件配置同步失败",
      isCancelled,
      retryMessage: "已先进入主界面，可在设置侧栏重试",
      setBackendStatus,
      setLastToolRuntimeProbeError,
      setToolRuntimeCheckDegraded,
      setToolRuntimeProbeState,
      setTsharkStatus,
      timeoutPrefix: "运行时组件配置同步超时",
    });
  } finally {
    if (!isCancelled()) setIsToolRuntimeLoading(false);
  }
}

interface FullToolRuntimeBackgroundOptions extends Omit<ApplyStartupRuntimeSnapshotOptions, "snapshot"> {
  readonly setToolRuntimeProbeTransport: Dispatch<SetStateAction<ToolRuntimeProbeTransport>>;
  readonly setToolRuntimeCheckDegraded: Dispatch<SetStateAction<boolean>>;
}

export async function loadFullToolRuntimeInBackground({
  isCancelled,
  setBackendStatus,
  setToolRuntimeSnapshot,
  setTsharkStatus,
  setToolRuntimeProbeState,
  setToolRuntimeProbeTransport,
  setLastToolRuntimeProbeError,
  setToolRuntimeCheckDegraded,
}: FullToolRuntimeBackgroundOptions) {
  if (isCancelled()) return;
  setToolRuntimeProbeState("probing_full");
  setToolRuntimeProbeTransport(detectToolRuntimeProbeTransport());
  try {
    const snapshot = await withAbortableTimeout(
      (signal) => backendClients.runtime.getToolRuntimeSnapshot(signal, "full"),
      FULL_TOOL_RUNTIME_TIMEOUT_MS,
      "background full tool runtime check timed out",
    );
    setToolRuntimeCheckDegraded(false);
    setToolRuntimeProbeTransport(snapshot.transport ?? detectToolRuntimeProbeTransport());
    applyStartupRuntimeSnapshot({
      isCancelled,
      setBackendStatus,
      setToolRuntimeSnapshot,
      setTsharkStatus,
      setToolRuntimeProbeState,
      setLastToolRuntimeProbeError,
      snapshot,
    });
  } catch (error) {
    if (isCancelled()) return;
    setToolRuntimeCheckDegraded(true);
    setToolRuntimeProbeState("timeout_background");
    setLastToolRuntimeProbeError(describeToolRuntimeProbeError(error));
    setBackendStatus(`完整运行时组件探测仍在后台进行：${describeToolRuntimeProbeError(error)}`);
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
