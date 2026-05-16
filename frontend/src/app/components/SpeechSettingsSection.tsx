import { Bot, FolderCog, MicVocal } from "lucide-react";

import { RuntimeDependencyCard } from "./RuntimeDependencyCard";
import { pythonPathHint, voskModelPathHint } from "./RuntimeSettingsHints";
import { RuntimeSettingsSectionShell, RuntimeSettingsSectionTitle } from "./RuntimeSettingsSectionShell";
import { Field, StatusLine } from "./RuntimeSettingsSidebarParts";
import type { SpeechSettingsSectionProps } from "./RuntimeSettingsSectionTypes";

export function SpeechSettingsSection({
  form,
  snapshot,
  speechIssues,
  speechSummary,
  setForm,
  unknownStateText,
}: SpeechSettingsSectionProps) {
  return (
    <RuntimeSettingsSectionShell>
      <RuntimeSettingsSectionTitle Icon={Bot} iconClassName="bg-rose-50 text-rose-600">
        离线语音转写
      </RuntimeSettingsSectionTitle>
      <div className="grid grid-cols-1 gap-3">
        <Field
          label="显式配置：Python 路径"
          hint={pythonPathHint(snapshot, form.pythonPath)}
          value={form.pythonPath}
          onChange={(value) => setForm((prev) => ({ ...prev, pythonPath: value }))}
          placeholder="C:\\Users\\QAQ\\AppData\\Local\\Programs\\Python\\Python311\\python.exe"
        />
        <Field
          label="显式配置：Vosk 模型目录"
          hint={voskModelPathHint(snapshot, form.voskModelPath)}
          value={form.voskModelPath}
          onChange={(value) => setForm((prev) => ({ ...prev, voskModelPath: value }))}
          placeholder="C:\\Users\\QAQ\\AppData\\Local\\gshark-sentinel\\models\\vosk\\zh-CN"
        />
      </div>
      <StatusLine
        label="Speech To Text"
        available={snapshot?.speech.available}
        known={Boolean(snapshot)}
        message={speechSummary}
        unknownStateText={unknownStateText}
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
          known={Boolean(snapshot)}
          value={snapshot?.speech.pythonCommand || "等待检测"}
        />
        <RuntimeDependencyCard
          label="Vosk 模型"
          Icon={MicVocal}
          available={snapshot?.speech.modelAvailable ?? false}
          known={Boolean(snapshot)}
          value={snapshot?.speech.modelPath || form.voskModelPath || "等待检测"}
        />
      </div>
    </RuntimeSettingsSectionShell>
  );
}
