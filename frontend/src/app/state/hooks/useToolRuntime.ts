import { useCallback, useState } from "react";
import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../../core/types";
import { bridge, type TSharkStatus } from "../../integrations/wailsBridge";

const TSHARK_PATH_STORAGE_KEY = "gshark.tshark-path.v1";
const TOOL_RUNTIME_STORAGE_KEY = "gshark.tool-runtime.v1";

const EMPTY_TOOL_RUNTIME_CONFIG: ToolRuntimeConfig = {
  tsharkPath: "",
  ffmpegPath: "",
  pythonPath: "",
  voskModelPath: "",
  yaraEnabled: true,
  yaraBin: "",
  yaraRules: "",
  yaraTimeoutMs: 25000,
};

const EMPTY_TSHARK_STATUS: TSharkStatus = {
  available: false,
  path: "",
  message: "",
  customPath: "",
  usingCustomPath: false,
};

export function readToolRuntimeConfig(): ToolRuntimeConfig {
  if (typeof window === "undefined") return { ...EMPTY_TOOL_RUNTIME_CONFIG };
  try {
    const raw = window.localStorage.getItem(TOOL_RUNTIME_STORAGE_KEY);
    if (!raw) {
      const legacyTsharkPath = window.localStorage.getItem(TSHARK_PATH_STORAGE_KEY)?.trim() ?? "";
      return { ...EMPTY_TOOL_RUNTIME_CONFIG, tsharkPath: legacyTsharkPath };
    }
    const parsed = JSON.parse(raw);
    return {
      tsharkPath: String(parsed?.tsharkPath ?? window.localStorage.getItem(TSHARK_PATH_STORAGE_KEY) ?? "").trim(),
      ffmpegPath: String(parsed?.ffmpegPath ?? "").trim(),
      pythonPath: String(parsed?.pythonPath ?? "").trim(),
      voskModelPath: String(parsed?.voskModelPath ?? "").trim(),
      yaraEnabled: parsed?.yaraEnabled !== false,
      yaraBin: String(parsed?.yaraBin ?? "").trim(),
      yaraRules: String(parsed?.yaraRules ?? "").trim(),
      yaraTimeoutMs: Number(parsed?.yaraTimeoutMs ?? 25000) || 25000,
    };
  } catch {
    return { ...EMPTY_TOOL_RUNTIME_CONFIG };
  }
}

export function writeToolRuntimeConfig(config: ToolRuntimeConfig) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(TOOL_RUNTIME_STORAGE_KEY, JSON.stringify(config));
    if (config.tsharkPath) {
      window.localStorage.setItem(TSHARK_PATH_STORAGE_KEY, config.tsharkPath);
    }
  } catch {
    // localStorage write failed
  }
}

export function useToolRuntime() {
  const [tsharkStatus, setTsharkStatus] = useState<TSharkStatus>(EMPTY_TSHARK_STATUS);
  const [isTSharkChecking, setIsTSharkChecking] = useState(false);
  const [toolRuntimeSnapshot, setToolRuntimeSnapshot] = useState<ToolRuntimeSnapshot | null>(null);
  const [isToolRuntimeLoading, setIsToolRuntimeLoading] = useState(false);
  const [toolRuntimeCheckDegraded, setToolRuntimeCheckDegraded] = useState(false);

  const setTSharkPath = useCallback(async (path: string, backendConnected: boolean, setBackendStatus: (status: string) => void) => {
    const nextPath = path.trim();
    writeToolRuntimeConfig({
      ...(toolRuntimeSnapshot?.config ?? readToolRuntimeConfig()),
      tsharkPath: nextPath,
    });
    if (!backendConnected) {
      setTsharkStatus((prev) => ({
        ...prev,
        customPath: nextPath,
        usingCustomPath: nextPath.length > 0,
      }));
      return;
    }

    const status = await bridge.setTSharkPath(nextPath);
    setToolRuntimeCheckDegraded(false);
    setTsharkStatus(status);
    setToolRuntimeSnapshot((prev) => prev ? ({
      ...prev,
      config: { ...prev.config, tsharkPath: nextPath },
      tshark: {
        ...prev.tshark,
        available: status.available,
        path: status.path,
        message: status.message,
        customPath: status.customPath || undefined,
        usingCustomPath: status.usingCustomPath,
      },
    }) : prev);

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
  }, [toolRuntimeSnapshot]);

  const refreshToolRuntimeSnapshot = useCallback(async (backendConnected: boolean) => {
    if (!backendConnected) {
      return null;
    }
    setIsToolRuntimeLoading(true);
    try {
      const snapshot = await bridge.getToolRuntimeSnapshot();
      setToolRuntimeCheckDegraded(false);
      setToolRuntimeSnapshot(snapshot);
      setTsharkStatus({
        available: snapshot.tshark.available,
        path: snapshot.tshark.path,
        message: snapshot.tshark.message,
        customPath: snapshot.tshark.customPath ?? "",
        usingCustomPath: snapshot.tshark.usingCustomPath,
      });
      return snapshot;
    } finally {
      setIsToolRuntimeLoading(false);
    }
  }, []);

  const saveToolRuntimeConfig = useCallback(async (patch: Partial<ToolRuntimeConfig>, backendConnected: boolean, setBackendStatus: (status: string) => void) => {
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

    writeToolRuntimeConfig(nextConfig);
    if (!backendConnected) {
      const offlineSnapshot: ToolRuntimeSnapshot = {
        config: nextConfig,
        tshark: {
          available: false,
          path: "",
          message: "后端未连接",
          customPath: nextConfig.tsharkPath || undefined,
          usingCustomPath: Boolean(nextConfig.tsharkPath),
        },
        ffmpeg: {
          available: false,
          path: "",
          message: "后端未连接",
          customPath: nextConfig.ffmpegPath || undefined,
          usingCustomPath: Boolean(nextConfig.ffmpegPath),
        },
        speech: {
          available: false,
          engine: "vosk",
          language: "zh-CN",
          pythonAvailable: false,
          ffmpegAvailable: false,
          voskAvailable: false,
          modelAvailable: false,
          modelPath: nextConfig.voskModelPath || undefined,
          message: "后端未连接",
        },
        yara: {
          available: false,
          enabled: nextConfig.yaraEnabled,
          message: "后端未连接",
          customBin: nextConfig.yaraBin || undefined,
          customRules: nextConfig.yaraRules || undefined,
          usingCustomBin: Boolean(nextConfig.yaraBin),
          usingCustomRules: Boolean(nextConfig.yaraRules),
          timeoutMs: nextConfig.yaraTimeoutMs,
        },
      };
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
      const snapshot = await bridge.updateToolRuntimeConfig(nextConfig);
      setToolRuntimeCheckDegraded(false);
      setToolRuntimeSnapshot(snapshot);
      setTsharkStatus({
        available: snapshot.tshark.available,
        path: snapshot.tshark.path,
        message: snapshot.tshark.message,
        customPath: snapshot.tshark.customPath ?? "",
        usingCustomPath: snapshot.tshark.usingCustomPath,
      });
      if (snapshot.tshark.available) {
        setBackendStatus(snapshot.tshark.message && snapshot.tshark.message !== "ok" ? snapshot.tshark.message : "工具路径已更新");
      } else {
        setBackendStatus(snapshot.tshark.message || "tshark is unavailable");
      }
      return snapshot;
    } finally {
      setIsToolRuntimeLoading(false);
    }
  }, [toolRuntimeSnapshot]);

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
