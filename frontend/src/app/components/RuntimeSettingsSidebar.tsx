import { useEffect, useMemo, useState } from "react";

import type { ToolRuntimeConfig } from "../core/types";
import { useSentinel } from "../state/SentinelContext";
import { buildSpeechIssues, normalizeConfig } from "./RuntimeSettingsSidebarParts";
import {
  CaptureSettingsSection,
  MediaSettingsSection,
  SpeechSettingsSection,
  YaraSettingsSection,
} from "./RuntimeSettingsSections";
import { RuntimeSettingsActions, RuntimeSettingsFooter, RuntimeSettingsHeader } from "./RuntimeSettingsShell";
import { useSidebar } from "./ui/sidebar";

export function RuntimeSettingsSidebar() {
  const { toggleSidebar } = useSidebar();
  const {
    backendConnected,
    toolRuntimeSnapshot,
    isToolRuntimeLoading,
    refreshToolRuntimeSnapshot,
    saveToolRuntimeConfig,
  } = useSentinel();

  const [form, setForm] = useState<ToolRuntimeConfig>(() => normalizeConfig(toolRuntimeSnapshot?.config));
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");

  useEffect(() => {
    setForm(normalizeConfig(toolRuntimeSnapshot?.config));
  }, [toolRuntimeSnapshot?.config]);

  const dirty = useMemo(() => {
    const base = normalizeConfig(toolRuntimeSnapshot?.config);
    return JSON.stringify(base) !== JSON.stringify(form);
  }, [form, toolRuntimeSnapshot?.config]);

  const speechIssues = useMemo(() => buildSpeechIssues(toolRuntimeSnapshot), [toolRuntimeSnapshot]);
  const speechSummary = useMemo(() => {
    if (!backendConnected) {
      return "后端未连接";
    }
    if (toolRuntimeSnapshot?.speech.available) {
      return "离线转写相关依赖已经就绪，可以直接开始转写音频。";
    }
    if (speechIssues.length > 0) {
      return `当前未就绪项：${speechIssues.join(" / ")}`;
    }
    return toolRuntimeSnapshot?.speech.message || "等待检测";
  }, [backendConnected, speechIssues, toolRuntimeSnapshot?.speech.available, toolRuntimeSnapshot?.speech.message]);

  const save = async () => {
    setBusy(true);
    setNotice("");
    try {
      const snapshot = await saveToolRuntimeConfig(form);
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
      const snapshot = await refreshToolRuntimeSnapshot();
      if (snapshot) {
        setForm(normalizeConfig(snapshot.config));
      }
      setNotice("已刷新工具状态。");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "工具状态刷新失败。");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full flex-col overflow-hidden rounded-[28px] border border-slate-200/80 bg-white/95 shadow-[0_28px_80px_-28px_rgba(15,23,42,0.45)] backdrop-blur">
      <RuntimeSettingsHeader form={form} snapshot={toolRuntimeSnapshot} onClose={toggleSidebar} />

      <div className="flex flex-1 flex-col overflow-hidden">
        <RuntimeSettingsActions
          busy={busy}
          loading={isToolRuntimeLoading}
          backendConnected={backendConnected}
          dirty={dirty}
          onRefresh={() => void refresh()}
          onSave={() => void save()}
        />

        <div className="flex-1 space-y-4 overflow-auto bg-[linear-gradient(180deg,rgba(248,250,252,0.5),rgba(255,255,255,0.95))] px-5 py-5">
          <CaptureSettingsSection
            backendConnected={backendConnected}
            form={form}
            snapshot={toolRuntimeSnapshot}
            setForm={setForm}
          />
          <YaraSettingsSection
            backendConnected={backendConnected}
            form={form}
            snapshot={toolRuntimeSnapshot}
            setForm={setForm}
          />
          <MediaSettingsSection
            backendConnected={backendConnected}
            form={form}
            snapshot={toolRuntimeSnapshot}
            setForm={setForm}
          />
          <SpeechSettingsSection
            form={form}
            snapshot={toolRuntimeSnapshot}
            speechIssues={speechIssues}
            speechSummary={speechSummary}
            setForm={setForm}
          />
        </div>
      </div>

      <RuntimeSettingsFooter notice={notice} backendConnected={backendConnected} />
    </div>
  );
}
