import { useEffect, useMemo, useState } from "react";
import {
  AudioLines,
  Bot,
  FolderCog,
  MicVocal,
  RefreshCw,
  Save,
  SearchCode,
  ShieldAlert,
  Sparkles,
  X,
} from "lucide-react";

import type { ToolRuntimeConfig } from "../core/types";
import { useSentinel } from "../state/SentinelContext";
import { useSidebar } from "./ui/sidebar";

function normalizeConfig(config?: ToolRuntimeConfig | null): ToolRuntimeConfig {
  return {
    tsharkPath: config?.tsharkPath ?? "",
    ffmpegPath: config?.ffmpegPath ?? "",
    pythonPath: config?.pythonPath ?? "",
    voskModelPath: config?.voskModelPath ?? "",
    yaraEnabled: config?.yaraEnabled ?? true,
    yaraBin: config?.yaraBin ?? "",
    yaraRules: config?.yaraRules ?? "",
    yaraTimeoutMs: config?.yaraTimeoutMs && config.yaraTimeoutMs > 0 ? config.yaraTimeoutMs : 25000,
  };
}

function statusTone(available: boolean, enabled = true) {
  if (!enabled) {
    return "border-slate-200 bg-slate-50 text-slate-500";
  }
  return available
    ? "border-emerald-200 bg-emerald-50 text-emerald-700"
    : "border-rose-200 bg-rose-50 text-rose-700";
}

function Field({
  label,
  hint,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  hint?: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-xs font-medium text-slate-700">{label}</span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="h-9 rounded-lg border border-slate-200 bg-white px-3 text-xs text-slate-900 outline-none transition focus:border-blue-400"
      />
      {hint ? <span className="text-[11px] leading-5 text-slate-500">{hint}</span> : null}
    </label>
  );
}

function StatusLine({
  label,
  available,
  message,
  path,
  enabled = true,
  preferMessageWhenUnavailable = false,
}: {
  label: string;
  available: boolean;
  message: string;
  path?: string;
  enabled?: boolean;
  preferMessageWhenUnavailable?: boolean;
}) {
  const resolvedText = !enabled
    ? message || "当前组件已关闭"
    : (!available && preferMessageWhenUnavailable)
      ? (message || "等待检测")
      : (path?.trim() ? path : message || "等待检测");
  return (
    <div className={`rounded-xl border px-3 py-2 ${statusTone(available, enabled)}`}>
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs font-semibold">{label}</span>
        <span className="text-[11px]">{!enabled ? "已关闭" : available ? "已就绪" : "未就绪"}</span>
      </div>
      <div className="mt-1 break-all text-[11px] leading-5">
        {resolvedText}
      </div>
    </div>
  );
}

function MiniStatus({
  label,
  available,
  enabled = true,
}: {
  label: string;
  available: boolean;
  enabled?: boolean;
}) {
  const tone = !enabled
    ? "border-slate-200 bg-slate-50 text-slate-500"
    : available
      ? "border-emerald-200 bg-emerald-50 text-emerald-700"
      : "border-rose-200 bg-rose-50 text-rose-700";
  return (
    <div className={`rounded-2xl border px-3 py-2 ${tone}`}>
      <div className="text-[11px] font-semibold uppercase tracking-[0.16em]">{label}</div>
      <div className="mt-1 text-sm font-semibold">{!enabled ? "已关闭" : available ? "就绪" : "缺失"}</div>
    </div>
  );
}

function buildSpeechIssues(snapshot: ReturnType<typeof useSentinel>["toolRuntimeSnapshot"]) {
  const speech = snapshot?.speech;
  if (!speech) {
    return [];
  }
  const issues: string[] = [];
  if (!speech.pythonAvailable) {
    issues.push("Python 不可用");
  }
  if (!speech.voskAvailable) {
    issues.push("vosk 模块缺失");
  }
  if (!speech.modelAvailable) {
    issues.push("Vosk 模型目录缺失");
  }
  if (!speech.ffmpegAvailable) {
    issues.push("ffmpeg 不可用");
  }
  return issues;
}

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
      <div className="border-b border-slate-200 bg-[linear-gradient(135deg,rgba(239,246,255,0.92),rgba(255,255,255,0.98))] px-5 py-5">
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-blue-600">Runtime Settings</div>
            <div className="mt-2 text-[22px] font-semibold leading-none text-slate-900">运行时组件设置</div>
            <p className="mt-2 max-w-md text-xs leading-5 text-slate-600">
              这里统一管理抓包、YARA、媒体播放和离线语音转写依赖的本地组件路径。
              保存之后会立即重新检测，方便直接确认当前环境是否已经接好。
            </p>
          </div>
          <button
            type="button"
            onClick={toggleSidebar}
            className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-slate-200 bg-white/90 text-slate-500 transition hover:border-slate-300 hover:text-slate-800"
            title="收起设置侧栏"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-4 grid grid-cols-2 gap-2">
          <MiniStatus label="TShark" available={toolRuntimeSnapshot?.tshark.available ?? false} />
          <MiniStatus label="FFmpeg" available={toolRuntimeSnapshot?.ffmpeg.available ?? false} />
          <MiniStatus label="Speech" available={toolRuntimeSnapshot?.speech.available ?? false} />
          <MiniStatus
            label="YARA"
            available={toolRuntimeSnapshot?.yara.available ?? false}
            enabled={toolRuntimeSnapshot?.yara.enabled ?? form.yaraEnabled}
          />
        </div>
      </div>

      <div className="flex flex-1 flex-col overflow-hidden">
        <div className="flex items-center gap-2 border-b border-slate-200 bg-white/90 px-5 py-3">
          <button
            onClick={() => void refresh()}
            disabled={busy || isToolRuntimeLoading || !backendConnected}
            className="inline-flex h-10 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3.5 text-xs font-medium text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${busy || isToolRuntimeLoading ? "animate-spin" : ""}`} />
            刷新状态
          </button>
          <button
            onClick={() => void save()}
            disabled={busy || isToolRuntimeLoading || !dirty}
            className="inline-flex h-10 items-center gap-2 rounded-xl border border-blue-200 bg-blue-600 px-3.5 text-xs font-medium text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <Save className="h-3.5 w-3.5" />
            保存并应用
          </button>
        </div>

        <div className="flex-1 space-y-4 overflow-auto bg-[linear-gradient(180deg,rgba(248,250,252,0.5),rgba(255,255,255,0.95))] px-5 py-5">
          <section className="space-y-4 rounded-[24px] border border-slate-200 bg-white p-4 shadow-[0_12px_32px_-24px_rgba(15,23,42,0.35)]">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
              <div className="flex h-9 w-9 items-center justify-center rounded-2xl bg-blue-50 text-blue-600">
                <SearchCode className="h-4 w-4" />
              </div>
              抓包与解析
            </div>
            <Field
              label="tshark 路径"
              hint="这里可以直接填写 tshark.exe，也可以填写 Wireshark 安装目录，程序会自动尝试定位。"
              value={form.tsharkPath}
              onChange={(value) => setForm((prev) => ({ ...prev, tsharkPath: value }))}
              placeholder="C:\\Program Files\\Wireshark\\tshark.exe"
            />
            <StatusLine
              label="TShark"
              available={toolRuntimeSnapshot?.tshark.available ?? false}
              message={toolRuntimeSnapshot?.tshark.message ?? (backendConnected ? "等待检测" : "后端未连接")}
              path={toolRuntimeSnapshot?.tshark.path}
            />
          </section>

          <section className="space-y-4 rounded-[24px] border border-slate-200 bg-white p-4 shadow-[0_12px_32px_-24px_rgba(15,23,42,0.35)]">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
              <div className="flex h-9 w-9 items-center justify-center rounded-2xl bg-amber-50 text-amber-600">
                <ShieldAlert className="h-4 w-4" />
              </div>
              YARA 狩猎
            </div>
            <div className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2.5">
              <div>
                <div className="text-xs font-semibold text-slate-800">启用 YARA 狩猎</div>
                <div className="mt-0.5 text-[11px] text-slate-500">关闭后会保留路径配置，只是不再参与对象扫描。</div>
              </div>
              <label className="inline-flex items-center gap-2 text-xs font-medium text-slate-700">
                <input
                  type="checkbox"
                  checked={form.yaraEnabled}
                  onChange={(event) => setForm((prev) => ({ ...prev, yaraEnabled: event.target.checked }))}
                />
                已启用
              </label>
            </div>
            <div className="grid grid-cols-1 gap-3">
              <Field
                label="YARA 可执行路径"
                value={form.yaraBin}
                onChange={(value) => setForm((prev) => ({ ...prev, yaraBin: value }))}
                placeholder="C:\\tools\\yara64.exe"
              />
              <Field
                label="YARA 规则文件"
                value={form.yaraRules}
                onChange={(value) => setForm((prev) => ({ ...prev, yaraRules: value }))}
                placeholder="C:\\rules\\default.yar"
              />
              <label className="flex flex-col gap-1.5">
                <span className="text-xs font-medium text-slate-700">YARA 超时（毫秒）</span>
                <input
                  type="number"
                  min={1000}
                  step={1000}
                  value={form.yaraTimeoutMs}
                  onChange={(event) => setForm((prev) => ({ ...prev, yaraTimeoutMs: Number(event.target.value) || 25000 }))}
                  className="h-10 rounded-xl border border-slate-200 bg-white px-3 text-xs text-slate-900 outline-none transition focus:border-blue-400"
                />
              </label>
            </div>
            <StatusLine
              label="YARA"
              available={toolRuntimeSnapshot?.yara.available ?? false}
              enabled={toolRuntimeSnapshot?.yara.enabled ?? form.yaraEnabled}
              message={toolRuntimeSnapshot?.yara.message ?? (backendConnected ? "等待检测" : "后端未连接")}
              path={toolRuntimeSnapshot?.yara.path}
            />
            {toolRuntimeSnapshot?.yara.rulePath ? (
              <div className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-[11px] leading-5 text-slate-500">
                当前使用的规则文件：
                <span className="break-all text-slate-700"> {toolRuntimeSnapshot.yara.rulePath}</span>
              </div>
            ) : null}
          </section>

          <section className="space-y-4 rounded-[24px] border border-slate-200 bg-white p-4 shadow-[0_12px_32px_-24px_rgba(15,23,42,0.35)]">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
              <div className="flex h-9 w-9 items-center justify-center rounded-2xl bg-emerald-50 text-emerald-600">
                <AudioLines className="h-4 w-4" />
              </div>
              媒体播放与转码
            </div>
            <Field
              label="ffmpeg 路径"
              hint="这里会同时影响媒体播放、音频试听，以及离线转写前的 wav 转换。"
              value={form.ffmpegPath}
              onChange={(value) => setForm((prev) => ({ ...prev, ffmpegPath: value }))}
              placeholder="C:\\ffmpeg\\bin\\ffmpeg.exe"
            />
            <StatusLine
              label="FFmpeg"
              available={toolRuntimeSnapshot?.ffmpeg.available ?? false}
              message={toolRuntimeSnapshot?.ffmpeg.message ?? (backendConnected ? "等待检测" : "后端未连接")}
              path={toolRuntimeSnapshot?.ffmpeg.path}
            />
          </section>

          <section className="space-y-4 rounded-[24px] border border-slate-200 bg-white p-4 shadow-[0_12px_32px_-24px_rgba(15,23,42,0.35)]">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
              <div className="flex h-9 w-9 items-center justify-center rounded-2xl bg-rose-50 text-rose-600">
                <Bot className="h-4 w-4" />
              </div>
              离线语音转写
            </div>
            <div className="grid grid-cols-1 gap-3">
              <Field
                label="Python 路径"
                hint="这里用于调用本地 Vosk 识别脚本。留空时会优先尝试默认的 Python 3。"
                value={form.pythonPath}
                onChange={(value) => setForm((prev) => ({ ...prev, pythonPath: value }))}
                placeholder="C:\\Users\\QAQ\\AppData\\Local\\Programs\\Python\\Python311\\python.exe"
              />
              <Field
                label="Vosk 模型目录"
                hint="这里填写模型根目录本身，也就是里面能看到 am、conf、graph 等子目录的那一层。"
                value={form.voskModelPath}
                onChange={(value) => setForm((prev) => ({ ...prev, voskModelPath: value }))}
                placeholder="C:\\Users\\QAQ\\AppData\\Local\\gshark-sentinel\\models\\vosk\\zh-CN"
              />
            </div>
            <StatusLine
              label="Speech To Text"
              available={toolRuntimeSnapshot?.speech.available ?? false}
              message={speechSummary}
              path={toolRuntimeSnapshot?.speech.pythonCommand || toolRuntimeSnapshot?.speech.modelPath}
              preferMessageWhenUnavailable
            />
            {speechIssues.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {speechIssues.map((issue) => (
                  <span
                    key={issue}
                    className="rounded-full border border-rose-200 bg-rose-50 px-2.5 py-1 text-[11px] font-medium text-rose-700"
                  >
                    缺少：{issue}
                  </span>
                ))}
              </div>
            ) : null}
            <div className="grid grid-cols-2 gap-2">
              <div className={`rounded-xl border px-3 py-2 ${statusTone(toolRuntimeSnapshot?.speech.pythonAvailable ?? false)}`}>
                <div className="flex items-center gap-1 text-xs font-semibold"><FolderCog className="h-3.5 w-3.5" /> Python</div>
                <div className="mt-1 break-all text-[11px] leading-5">
                  {toolRuntimeSnapshot?.speech.pythonCommand || "等待检测"}
                </div>
              </div>
              <div className={`rounded-xl border px-3 py-2 ${statusTone(toolRuntimeSnapshot?.speech.modelAvailable ?? false)}`}>
                <div className="flex items-center gap-1 text-xs font-semibold"><MicVocal className="h-3.5 w-3.5" /> Vosk 模型</div>
                <div className="mt-1 break-all text-[11px] leading-5">
                  {toolRuntimeSnapshot?.speech.modelPath || form.voskModelPath || "等待检测"}
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>

      <div className="border-t border-slate-200 bg-white/90 px-5 py-4">
        <div className="flex items-start gap-2 rounded-2xl border border-slate-200 bg-slate-50 px-3 py-3 text-[11px] leading-5 text-slate-500">
          <Sparkles className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-400" />
          <div>
            {notice || (backendConnected ? "路径修改后会立即应用到当前桌面端运行时，重启后也会自动重新加载这些设置。" : "后端暂时未连接，不过可以先填写路径，待后端连上后会自动重新应用。")}
          </div>
        </div>
      </div>
    </div>
  );
}
