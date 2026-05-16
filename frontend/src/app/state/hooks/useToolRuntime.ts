import { useCallback, useState } from "react";
import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../../core/types";
import type { TSharkStatus } from "../../integrations/clients/toolRuntimeClient";
import { backendClients } from "../../integrations/backendClients";
import { buildOfflineToolRuntimeSnapshot } from "../toolRuntimeOfflineSnapshot";
import { toTSharkStatus } from "../tsharkStatusState";
import { readToolRuntimeConfig, writeUserToolRuntimeConfig } from "../toolRuntimeStorage";
import {
  buildNextToolRuntimeConfig,
  EMPTY_TSHARK_STATUS,
  mergeTSharkStatusIntoSnapshot,
} from "../toolRuntimeSnapshotMutations";
import {
  describeToolRuntimeProbeError,
  detectToolRuntimeProbeTransport,
  type ToolRuntimeProbeState,
  type ToolRuntimeProbeTransport,
} from "../toolRuntimeProbeState";

export function useToolRuntime() {
  const [tsharkStatus, setTsharkStatus] = useState<TSharkStatus>(EMPTY_TSHARK_STATUS);
  const [isTSharkChecking, setIsTSharkChecking] = useState(false);
  const [toolRuntimeSnapshot, setToolRuntimeSnapshot] = useState<ToolRuntimeSnapshot | null>(null);
  const [isToolRuntimeLoading, setIsToolRuntimeLoading] = useState(false);
  const [toolRuntimeCheckDegraded, setToolRuntimeCheckDegraded] = useState(false);
  const [toolRuntimeProbeState, setToolRuntimeProbeState] = useState<ToolRuntimeProbeState>("idle");
  const [toolRuntimeProbeTransport, setToolRuntimeProbeTransport] = useState<ToolRuntimeProbeTransport>("unknown");
  const [lastToolRuntimeProbeError, setLastToolRuntimeProbeError] = useState("");

  const setTSharkPath = useCallback(
    async (path: string, backendConnected: boolean, setBackendStatus: (status: string) => void) => {
      const nextPath = path.trim();
      writeUserToolRuntimeConfig(
        {
          ...(toolRuntimeSnapshot?.config ?? readToolRuntimeConfig()),
          tsharkPath: nextPath,
        },
        { tsharkPath: true },
      );
      if (!backendConnected) {
        setTsharkStatus((prev) => ({
          ...prev,
          customPath: nextPath,
          usingCustomPath: nextPath.length > 0,
        }));
        return;
      }

      const status = await backendClients.runtime.setTSharkPath(nextPath);
      setToolRuntimeCheckDegraded(false);
      setTsharkStatus(status);
      setToolRuntimeSnapshot((prev) => mergeTSharkStatusIntoSnapshot(prev, nextPath, status));

      if (status.available) {
        if (status.message && status.message !== "ok") {
          setBackendStatus(status.message);
        } else {
          setBackendStatus(status.usingCustomPath ? `tshark ready: ${status.path}` : "tshark ready");
        }
        return;
      }
      setBackendStatus(status.message || "tshark is unavailable");
      throw new Error(status.message || "tshark is unavailable");
    },
    [toolRuntimeSnapshot],
  );

  const refreshToolRuntimeSnapshot = useCallback(async (backendConnected: boolean) => {
    if (!backendConnected) {
      setToolRuntimeProbeState("idle");
      setToolRuntimeProbeTransport("unknown");
      setLastToolRuntimeProbeError("后端未连接，暂时无法探测运行时组件。");
      return null;
    }
    setIsToolRuntimeLoading(true);
    setToolRuntimeProbeState("probing");
    setToolRuntimeProbeTransport(detectToolRuntimeProbeTransport());
    setLastToolRuntimeProbeError("");
    try {
      const snapshot = await backendClients.runtime.getToolRuntimeSnapshot();
      setToolRuntimeCheckDegraded(false);
      setToolRuntimeProbeState("ready");
      setLastToolRuntimeProbeError("");
      setToolRuntimeSnapshot(snapshot);
      setTsharkStatus(toTSharkStatus(snapshot.tshark));
      return snapshot;
    } catch (error) {
      setToolRuntimeCheckDegraded(true);
      setToolRuntimeProbeState("failed");
      setLastToolRuntimeProbeError(describeToolRuntimeProbeError(error));
      throw error;
    } finally {
      setIsToolRuntimeLoading(false);
    }
  }, []);

  const saveToolRuntimeConfig = useCallback(
    async (
      patch: Partial<ToolRuntimeConfig>,
      backendConnected: boolean,
      setBackendStatus: (status: string) => void,
    ) => {
      const base = toolRuntimeSnapshot?.config ?? readToolRuntimeConfig();
      const nextConfig = buildNextToolRuntimeConfig(base, patch);

      writeUserToolRuntimeConfig(nextConfig);
      if (!backendConnected) {
        const offlineSnapshot = buildOfflineToolRuntimeSnapshot(nextConfig);
        setToolRuntimeProbeState("ready");
        setToolRuntimeProbeTransport("unknown");
        setLastToolRuntimeProbeError("");
        setToolRuntimeSnapshot(offlineSnapshot);
        setTsharkStatus((prev) => ({
          ...prev,
          customPath: nextConfig.tsharkPath,
          usingCustomPath: nextConfig.tsharkPath.length > 0,
        }));
        return offlineSnapshot;
      }

      setIsToolRuntimeLoading(true);
      setToolRuntimeProbeState("probing");
      setToolRuntimeProbeTransport(detectToolRuntimeProbeTransport());
      setLastToolRuntimeProbeError("");
      try {
        const snapshot = await backendClients.runtime.updateToolRuntimeConfig(nextConfig);
        writeUserToolRuntimeConfig(snapshot.config);
        setToolRuntimeCheckDegraded(false);
        setToolRuntimeProbeState("ready");
        setLastToolRuntimeProbeError("");
        setToolRuntimeSnapshot(snapshot);
        setTsharkStatus(toTSharkStatus(snapshot.tshark));
        if (snapshot.tshark.available) {
          setBackendStatus(
            snapshot.tshark.message && snapshot.tshark.message !== "ok" ? snapshot.tshark.message : "工具路径已更新",
          );
        } else {
          setBackendStatus(snapshot.tshark.message || "tshark is unavailable");
        }
        return snapshot;
      } catch (error) {
        setToolRuntimeCheckDegraded(true);
        setToolRuntimeProbeState("failed");
        setLastToolRuntimeProbeError(describeToolRuntimeProbeError(error));
        throw error;
      } finally {
        setIsToolRuntimeLoading(false);
      }
    },
    [toolRuntimeSnapshot],
  );

  return {
    tsharkStatus,
    setTsharkStatus,
    isTSharkChecking,
    setIsTSharkChecking,
    toolRuntimeSnapshot,
    setToolRuntimeSnapshot,
    isToolRuntimeLoading,
    setIsToolRuntimeLoading,
    toolRuntimeCheckDegraded,
    setToolRuntimeCheckDegraded,
    toolRuntimeProbeState,
    setToolRuntimeProbeState,
    toolRuntimeProbeTransport,
    setToolRuntimeProbeTransport,
    lastToolRuntimeProbeError,
    setLastToolRuntimeProbeError,
    setTSharkPath,
    refreshToolRuntimeSnapshot,
    saveToolRuntimeConfig,
  };
}
