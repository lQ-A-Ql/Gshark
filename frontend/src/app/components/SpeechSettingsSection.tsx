import { Bot } from "lucide-react";

import { pythonPathHint, voskModelPathHint } from "./RuntimeSettingsHints";
import { RuntimeToolPathAllowWarning } from "./RuntimeToolPathAllowWarning";
import { SpeechDependencyDetails } from "./SpeechDependencyDetails";
import { RuntimeSettingsSectionShell, RuntimeSettingsSectionTitle } from "./RuntimeSettingsSectionShell";
import { Field, StatusLine } from "./RuntimeSettingsSidebarParts";
import type { SpeechSettingsSectionProps } from "./SpeechSettingsSectionProps";

export function SpeechSettingsSection({
  form,
  snapshot,
  speechIssues,
  speechSummary,
  setForm,
  unknownStateText,
  allowToolDir,
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
          placeholder="C:\\Users\\QAQ\\AppData\\Local\\meow-traffic\\models\\vosk\\zh-CN"
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
      <RuntimeToolPathAllowWarning
        field="pythonAllowedDirs"
        path={snapshot?.speech.pythonCommand}
        customPath={form.pythonPath}
        pathWarning={snapshot?.speech.pythonPathWarning}
        allowToolDir={allowToolDir}
      />
      <SpeechDependencyDetails form={form} snapshot={snapshot} speechIssues={speechIssues} />
    </RuntimeSettingsSectionShell>
  );
}
