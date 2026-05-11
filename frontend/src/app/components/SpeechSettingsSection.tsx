import { Bot, FolderCog, MicVocal } from "lucide-react";

import { Field, RuntimeDependencyCard, StatusLine } from "./RuntimeSettingsSidebarParts";
import type { SpeechSettingsSectionProps } from "./RuntimeSettingsSectionTypes";

export function SpeechSettingsSection({
  form,
  snapshot,
  speechIssues,
  speechSummary,
  setForm,
}: SpeechSettingsSectionProps) {
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
