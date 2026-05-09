import { AudioLines, Bot, FolderCog, MicVocal, SearchCode, ShieldAlert } from "lucide-react";

import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../core/types";
import { Field, RuntimeDependencyCard, StatusLine } from "./RuntimeSettingsSidebarParts";

export function CaptureSettingsSection({
  backendConnected,
  form,
  snapshot,
  setForm,
}: {
  backendConnected: boolean;
  form: ToolRuntimeConfig;
  snapshot?: ToolRuntimeSnapshot | null;
  setForm: (updater: (prev: ToolRuntimeConfig) => ToolRuntimeConfig) => void;
}) {
  return (
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
        available={snapshot?.tshark.available ?? false}
        message={snapshot?.tshark.message ?? (backendConnected ? "等待检测" : "后端未连接")}
        path={snapshot?.tshark.path}
      />
    </section>
  );
}

export function YaraSettingsSection({
  backendConnected,
  form,
  snapshot,
  setForm,
}: {
  backendConnected: boolean;
  form: ToolRuntimeConfig;
  snapshot?: ToolRuntimeSnapshot | null;
  setForm: (updater: (prev: ToolRuntimeConfig) => ToolRuntimeConfig) => void;
}) {
  return (
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
          <div className="mt-0.5 text-[11px] text-slate-500">
            关闭后会保留路径配置，只是不再参与对象与重组流内容的狩猎扫描。
          </div>
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
          placeholder="C:\\rules\\default.yar 或 C:\\rules\\traffic-pack\\"
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
        available={snapshot?.yara.available ?? false}
        enabled={snapshot?.yara.enabled ?? form.yaraEnabled}
        message={snapshot?.yara.message ?? (backendConnected ? "等待检测" : "后端未连接")}
        path={snapshot?.yara.path}
      />
      {snapshot?.yara.rulePath ? (
        <div className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-[11px] leading-5 text-slate-500">
          当前使用的规则文件：
          <span className="break-all text-slate-700"> {snapshot.yara.rulePath}</span>
        </div>
      ) : null}
      {snapshot?.yara.lastScanMessage ? (
        <div className="rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-[11px] leading-5 text-amber-700">
          最近一次扫描告警：
          <span className="break-all"> {snapshot.yara.lastScanMessage}</span>
        </div>
      ) : null}
    </section>
  );
}

export function MediaSettingsSection({
  backendConnected,
  form,
  snapshot,
  setForm,
}: {
  backendConnected: boolean;
  form: ToolRuntimeConfig;
  snapshot?: ToolRuntimeSnapshot | null;
  setForm: (updater: (prev: ToolRuntimeConfig) => ToolRuntimeConfig) => void;
}) {
  return (
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
        available={snapshot?.ffmpeg.available ?? false}
        message={snapshot?.ffmpeg.message ?? (backendConnected ? "等待检测" : "后端未连接")}
        path={snapshot?.ffmpeg.path}
      />
    </section>
  );
}

export function SpeechSettingsSection({
  form,
  snapshot,
  speechIssues,
  speechSummary,
  setForm,
}: {
  form: ToolRuntimeConfig;
  snapshot?: ToolRuntimeSnapshot | null;
  speechIssues: string[];
  speechSummary: string;
  setForm: (updater: (prev: ToolRuntimeConfig) => ToolRuntimeConfig) => void;
}) {
  return (
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
        available={snapshot?.speech.available ?? false}
        message={speechSummary}
        path={snapshot?.speech.pythonCommand || snapshot?.speech.modelPath}
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
        <RuntimeDependencyCard
          label="Python"
          Icon={FolderCog}
          available={snapshot?.speech.pythonAvailable ?? false}
          value={snapshot?.speech.pythonCommand || "等待检测"}
        />
        <RuntimeDependencyCard
          label="Vosk 模型"
          Icon={MicVocal}
          available={snapshot?.speech.modelAvailable ?? false}
          value={snapshot?.speech.modelPath || form.voskModelPath || "等待检测"}
        />
      </div>
    </section>
  );
}
