import { useCallback, useState } from "react";
import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../../core/types";
import type { TSharkStatus } from "../../integrations/clients/toolRuntimeClient";
import { backendClients } from "../../integrations/backendClients";
import { applyOfflineToolRuntimeConfig } from "../toolRuntimeOfflineApply";
import { probeToolRuntimeSnapshot, syncToolRuntimeConfig } from "../toolRuntimeProbeActions";
import { startFullToolRuntimeProbe } from "../toolRuntimeBackgroundProbe";
import { describeTSharkApplyStatus, describeTSharkReadyStatus, toTSharkStatus } from "../tsharkStatusState";
import { readToolRuntimeConfig, writeUserToolRuntimeConfig } from "../toolRuntimeStorage";
import {
  explicitFieldsFromPatch,
  normalizeExplicitFields,
  type ToolRuntimeConfigExplicitFields,
} from "../toolRuntimeStorageConfig";
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

  const startBackgroundFullProbe = useCallback(() => {
    startFullToolRuntimeProbe({
      setToolRuntimeCheckDegraded,
      setToolRuntimeProbeState,
      setToolRuntimeProbeTransport,
      setLastToolRuntimeProbeError,
      setToolRuntimeSnapshot,
      setTsharkStatus,
    });
  }, []);

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
        setBackendStatus(describeTSharkReadyStatus(status));
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
    setToolRuntimeProbeState("probing_fast");
    setToolRuntimeProbeTransport(detectToolRuntimeProbeTransport());
    setLastToolRuntimeProbeError("");
    try {
      const snapshot = await probeToolRuntimeSnapshot("fast");
      setToolRuntimeCheckDegraded(false);
      setToolRuntimeProbeState("partial");
      setToolRuntimeProbeTransport(snapshot.transport ?? detectToolRuntimeProbeTransport());
      setLastToolRuntimeProbeError("");
      setToolRuntimeSnapshot(snapshot);
      setTsharkStatus(toTSharkStatus(snapshot.tshark));
      startBackgroundFullProbe();
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
      explicitFields?: ToolRuntimeConfigExplicitFields,
    ) => {
      const base = toolRuntimeSnapshot?.config ?? readToolRuntimeConfig();
      const nextConfig = buildNextToolRuntimeConfig(base, patch);
      const fields = normalizeExplicitFields(explicitFields ?? explicitFieldsFromPatch(patch));

      writeUserToolRuntimeConfig(nextConfig, fields);
      if (!backendConnected) {
        return applyOfflineToolRuntimeConfig({
          config: nextConfig,
          setToolRuntimeProbeState,
          setToolRuntimeProbeTransport,
          setLastToolRuntimeProbeError,
          setToolRuntimeSnapshot,
          setTsharkStatus,
        });
      }

      setIsToolRuntimeLoading(true);
      setToolRuntimeProbeState("probing_fast");
      setToolRuntimeProbeTransport(detectToolRuntimeProbeTransport());
      setLastToolRuntimeProbeError("");
      try {
        const snapshot = await syncToolRuntimeConfig(nextConfig, "fast");
        writeUserToolRuntimeConfig(snapshot.config, fields);
        setToolRuntimeCheckDegraded(false);
        setToolRuntimeProbeState("partial");
        setToolRuntimeProbeTransport(snapshot.transport ?? detectToolRuntimeProbeTransport());
        setLastToolRuntimeProbeError("");
        setToolRuntimeSnapshot(snapshot);
        setTsharkStatus(toTSharkStatus(snapshot.tshark));
        startBackgroundFullProbe();
        setBackendStatus(
          snapshot.tshark.available
            ? describeTSharkApplyStatus(snapshot.tshark)
            : snapshot.tshark.message || "tshark is unavailable",
        );
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
    [startBackgroundFullProbe, toolRuntimeSnapshot],
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
