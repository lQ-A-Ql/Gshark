import { useCallback, useState } from "react";
import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../../core/types";
import type { TSharkStatus } from "../../integrations/clients/toolRuntimeClient";
import { backendClients } from "../../integrations/backendClients";
import { buildOfflineToolRuntimeSnapshot } from "../toolRuntimeOfflineSnapshot";
import { toTSharkStatus } from "../tsharkStatusState";
import { readToolRuntimeConfig, writeUserToolRuntimeConfig } from "../toolRuntimeStorage";

const EMPTY_TSHARK_STATUS: TSharkStatus = {
  available: false,
  path: "",
  message: "",
  customPath: "",
  usingCustomPath: false,
};

export function useToolRuntime() {
  const [tsharkStatus, setTsharkStatus] = useState<TSharkStatus>(EMPTY_TSHARK_STATUS);
  const [isTSharkChecking, setIsTSharkChecking] = useState(false);
  const [toolRuntimeSnapshot, setToolRuntimeSnapshot] = useState<ToolRuntimeSnapshot | null>(null);
  const [isToolRuntimeLoading, setIsToolRuntimeLoading] = useState(false);
  const [toolRuntimeCheckDegraded, setToolRuntimeCheckDegraded] = useState(false);

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
      setToolRuntimeSnapshot((prev) =>
        prev
          ? {
              ...prev,
              config: { ...prev.config, tsharkPath: nextPath },
              tshark: {
                ...prev.tshark,
                available: status.available,
                path: status.path,
                message: status.message,
                customPath: status.customPath || undefined,
                usingCustomPath: status.usingCustomPath,
                version: status.version,
                fieldProfile: status.fieldProfile,
                fieldCount: status.fieldCount,
                missingRequiredFields: status.missingRequiredFields,
                missingOptionalFields: status.missingOptionalFields,
                capabilityMessage: status.capabilityMessage,
                capabilityCheckDegraded: status.capabilityCheckDegraded,
              },
            }
          : prev,
      );

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
      return null;
    }
    setIsToolRuntimeLoading(true);
    try {
      const snapshot = await backendClients.runtime.getToolRuntimeSnapshot();
      setToolRuntimeCheckDegraded(false);
      setToolRuntimeSnapshot(snapshot);
      setTsharkStatus(toTSharkStatus(snapshot.tshark));
      return snapshot;
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
      const nextConfig: ToolRuntimeConfig = {
        ...base,
        ...patch,
        tsharkPath: String(patch.tsharkPath ?? base.tsharkPath ?? "").trim(),
        ffmpegPath: String(patch.ffmpegPath ?? base.ffmpegPath ?? "").trim(),
        pythonPath: String(patch.pythonPath ?? base.pythonPath ?? "").trim(),
        voskModelPath: String(patch.voskModelPath ?? base.voskModelPath ?? "").trim(),
        yaraEnabled: patch.yaraEnabled ?? base.yaraEnabled,
        yaraBin: String(patch.yaraBin ?? base.yaraBin ?? "").trim(),
        yaraRules: String(patch.yaraRules ?? base.yaraRules ?? "").trim(),
        yaraTimeoutMs: Number(patch.yaraTimeoutMs ?? base.yaraTimeoutMs ?? 25000) || 25000,
      };

      writeUserToolRuntimeConfig(nextConfig);
      if (!backendConnected) {
        const offlineSnapshot = buildOfflineToolRuntimeSnapshot(nextConfig);
        setToolRuntimeSnapshot(offlineSnapshot);
        setTsharkStatus((prev) => ({
          ...prev,
          customPath: nextConfig.tsharkPath,
          usingCustomPath: nextConfig.tsharkPath.length > 0,
        }));
        return offlineSnapshot;
      }

      setIsToolRuntimeLoading(true);
      try {
        const snapshot = await backendClients.runtime.updateToolRuntimeConfig(nextConfig);
        writeUserToolRuntimeConfig(snapshot.config);
        setToolRuntimeCheckDegraded(false);
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
    setTSharkPath,
    refreshToolRuntimeSnapshot,
    saveToolRuntimeConfig,
  };
}
