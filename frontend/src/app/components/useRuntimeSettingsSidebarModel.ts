import { useEffect, useMemo, useState } from "react";

import type { ToolRuntimeConfig } from "../core/types";
import { useSentinel } from "../state/SentinelContext";
import { toolRuntimeProbeStateText } from "../state/toolRuntimeProbeState";
import { TOOL_RUNTIME_CONFIG_FIELDS } from "../state/toolRuntimeStorageConfig";
import type { ToolRuntimeConfigExplicitFields } from "../state/toolRuntimeStorageConfig";
import { buildSpeechIssues } from "./RuntimeSettingsSpeechIssues";
import { normalizeConfig } from "./RuntimeSettingsSidebarParts";

export function useRuntimeSettingsSidebarModel() {
  const runtime = useSentinel();
  const [form, setForm] = useState<ToolRuntimeConfig>(() => normalizeConfig(runtime.toolRuntimeSnapshot?.config));
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");

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

  return {
    ...runtime,
    busy,
    dirty,
    form,
    notice,
    probeTransportError: runtime.toolRuntimeSnapshot?.transportError ?? "",
    setForm,
    speechIssues,
    speechSummary,
    unknownMessage,
    unknownStateText: toolRuntimeProbeStateText(runtime.toolRuntimeProbeState),
    refresh,
    save,
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
