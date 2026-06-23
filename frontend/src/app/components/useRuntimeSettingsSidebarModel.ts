import { useEffect, useMemo, useState } from "react";

import type { ToolRuntimeConfig } from "../core/types";
import { useBackend } from "../state/contexts/BackendContext";
import { toolRuntimeProbeStateText } from "../state/toolRuntimeProbeState";
import { TOOL_RUNTIME_CONFIG_FIELDS } from "../state/toolRuntimeStorageConfig";
import type { ToolRuntimeConfigExplicitFields } from "../state/toolRuntimeStorageConfig";
import { copyTextToClipboard } from "../utils/browserFile";
import { buildSpeechIssues } from "./RuntimeSettingsSpeechIssues";
import { normalizeConfig } from "./RuntimeSettingsSidebarParts";

export function useRuntimeSettingsSidebarModel() {
  const runtime = useBackend();
  const [form, setForm] = useState<ToolRuntimeConfig>(() => normalizeConfig(runtime.toolRuntimeSnapshot?.config));
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [mcpBusy, setMCPBusy] = useState(false);
  const [mcpNotice, setMCPNotice] = useState("");

  useEffect(() => {
    setForm(normalizeConfig(runtime.toolRuntimeSnapshot?.config));
  }, [runtime.toolRuntimeSnapshot?.config]);

  const dirty = useMemo(() => {
    const base = normalizeConfig(runtime.toolRuntimeSnapshot?.config);
    return JSON.stringify(base) !== JSON.stringify(form);
  }, [form, runtime.toolRuntimeSnapshot?.config]);
  const dirtyFields = useMemo(
    () => buildDirtyRuntimeFields(normalizeConfig(runtime.toolRuntimeSnapshot?.config), form),
    [form, runtime.toolRuntimeSnapshot?.config],
  );

  const speechIssues = useMemo(() => buildSpeechIssues(runtime.toolRuntimeSnapshot), [runtime.toolRuntimeSnapshot]);
  const unknownMessage = useMemo(() => {
    if (!runtime.backendConnected) return "后端未连接";
    if (runtime.toolRuntimeProbeState === "failed") {
      return runtime.lastToolRuntimeProbeError || "运行时组件探测失败，请重试。";
    }
    if (runtime.toolRuntimeProbeState === "probing" || runtime.toolRuntimeProbeState === "probing_fast") {
      return "正在快速探测运行时组件";
    }
    if (runtime.toolRuntimeProbeState === "probing_full") return "快速状态已可用，完整能力探测后台进行中";
    if (runtime.toolRuntimeProbeState === "timeout_background") {
      return runtime.lastToolRuntimeProbeError || "完整能力探测仍在后台进行";
    }
    return runtime.toolRuntimeProbeState === "partial" ? "快速状态已可用" : "等待首次探测";
  }, [runtime.backendConnected, runtime.lastToolRuntimeProbeError, runtime.toolRuntimeProbeState]);

  const speechSummary = useMemo(() => {
    if (!runtime.backendConnected) return "后端未连接";
    if (runtime.toolRuntimeSnapshot?.speech.available) return "离线转写相关依赖已经就绪，可以直接开始转写音频。";
    if (speechIssues.length > 0) return `当前未就绪项：${speechIssues.join(" / ")}`;
    if (!runtime.toolRuntimeSnapshot) return unknownMessage;
    return runtime.toolRuntimeSnapshot.speech.message || "等待检测";
  }, [runtime.backendConnected, runtime.toolRuntimeSnapshot, speechIssues, unknownMessage]);
  const tokenAvailable = runtime.backendAuthToken.trim().length > 0;
  const mcpEndpoint = runtime.mcpStatus?.endpoint || "";

  const save = async () => {
    setBusy(true);
    setNotice("");
    try {
      const snapshot = await runtime.saveToolRuntimeConfig(form, dirtyFields);
      setForm(normalizeConfig(snapshot.config));
      setNotice("工具路径已保存并应用。");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "工具路径保存失败。");
    } finally {
      setBusy(false);
    }
  };

  const allowToolDir = async (
    field: "ffmpegAllowedDirs" | "pythonAllowedDirs" | "yaraAllowedDirs",
    dir: string,
  ) => {
    const cleanDir = dir.trim();
    if (!cleanDir) return;
    const existing = form[field] ?? [];
    if (existing.some((item) => item.toLowerCase() === cleanDir.toLowerCase())) return;
    const nextForm = { ...form, [field]: [...existing, cleanDir] };
    setForm(nextForm);
    setBusy(true);
    setNotice("");
    try {
      const snapshot = await runtime.saveToolRuntimeConfig(nextForm, { [field]: true });
      setForm(normalizeConfig(snapshot.config));
      setNotice("工具目录已加入白名单。");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "工具目录加白失败。");
    } finally {
      setBusy(false);
    }
  };

  const refresh = async () => {
    setBusy(true);
    setNotice("");
    try {
      const snapshot = await runtime.refreshToolRuntimeSnapshot();
      setNotice(snapshot ? "已重新探测工具状态。" : "后端未连接，暂时无法探测工具。");
      if (snapshot) setForm(normalizeConfig(snapshot.config));
    } catch (error) {
      setNotice(runtime.lastToolRuntimeProbeError || (error instanceof Error ? error.message : "工具状态刷新失败。"));
    } finally {
      setBusy(false);
    }
  };

  const runMCPTask = async <T,>(
    task: () => Promise<T>,
    options: {
      successMessage: (result: T) => string;
      failureMessage: string;
    },
  ): Promise<T | null> => {
    setMCPBusy(true);
    setMCPNotice("");
    try {
      const result = await task();
      setMCPNotice(options.successMessage(result));
      return result;
    } catch (error) {
      setMCPNotice(error instanceof Error ? error.message : options.failureMessage);
      return null;
    } finally {
      setMCPBusy(false);
    }
  };

  const refreshMCP = async () => {
    await runMCPTask(() => runtime.refreshMCPStatus(), {
      successMessage: (status) => (status ? "MCP 状态已刷新。" : "后端未连接，暂时无法读取 MCP 状态。"),
      failureMessage: "MCP 状态刷新失败。",
    });
  };

  const saveMCP = async (enabled: boolean) => {
    return await runMCPTask(() => runtime.saveMCPConfig({ enabled }), {
      successMessage: () => (enabled ? "本地 MCP 已启用。" : "本地 MCP 已关闭。"),
      failureMessage: "MCP 配置保存失败。",
    });
  };

  const copyMCPValue = async (
    value: string,
    options: {
      successMessage: string;
      failureMessage: string;
      emptyMessage?: string;
    },
  ) => {
    if (!value.trim()) {
      setMCPNotice(options.emptyMessage ?? options.failureMessage);
      return;
    }
    const ok = await copyTextToClipboard(value);
    setMCPNotice(ok ? options.successMessage : options.failureMessage);
  };

  const copyEndpoint = async () => {
    await copyMCPValue(mcpEndpoint, {
      successMessage: "MCP 端点已复制。",
      failureMessage: "复制端点失败。",
    });
  };

  const copyToken = async () => {
    await copyMCPValue(runtime.backendAuthToken, {
      successMessage: "Bearer token 已复制。",
      failureMessage: "复制 token 失败。",
      emptyMessage: "桌面 token 暂不可用，请等待后端完成启动。",
    });
  };

  return {
    ...runtime,
    tsharkDirControls: {
      allowTSharkDir: runtime.allowTSharkDir,
      removeTSharkAllowedDir: runtime.removeTSharkAllowedDir,
      refreshTSharkAllowedDirs: runtime.refreshTSharkAllowedDirs,
    },
    busy,
    dirty,
    form,
    mcpBusy,
    mcpNotice,
    notice,
    probeTransportError: runtime.toolRuntimeSnapshot?.transportError ?? "",
    setForm,
    allowToolDir,
    speechIssues,
    speechSummary,
    authToken: runtime.backendAuthToken,
    tokenAvailable,
    tokenBusy: runtime.isBackendAuthTokenLoading,
    unknownMessage,
    unknownStateText: toolRuntimeProbeStateText(runtime.toolRuntimeProbeState),
    copyEndpoint,
    copyToken,
    refresh,
    refreshMCP,
    save,
    saveMCP,
  };
}

function buildDirtyRuntimeFields(base: ToolRuntimeConfig, form: ToolRuntimeConfig): ToolRuntimeConfigExplicitFields {
  const fields: ToolRuntimeConfigExplicitFields = {};
  for (const field of TOOL_RUNTIME_CONFIG_FIELDS) {
    if (normalizeFieldValue(base[field]) !== normalizeFieldValue(form[field])) {
      fields[field] = true;
    }
  }
  return fields;
}

function normalizeFieldValue(value: ToolRuntimeConfig[keyof ToolRuntimeConfig]): string {
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(Number(value) || 0);
  return String(value ?? "").trim();
}
