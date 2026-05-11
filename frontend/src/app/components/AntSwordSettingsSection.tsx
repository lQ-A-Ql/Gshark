import { DecoderSettingsSection, LabeledInput, LabeledSelect, LabeledToggle } from "./StreamDecoderWorkbenchParts";
import type { DecoderSettings } from "./StreamDecoderWorkbenchUtils";
import { clampNumericText, type DecoderSettingsSectionProps } from "./StreamDecoderSettingsSectionTypes";

export function AntSwordSettingsSection({ settings, setSettings, onClose }: DecoderSettingsSectionProps) {
  return (
    <DecoderSettingsSection title="AntSword 设置" onClose={onClose}>
      <div className="grid gap-3 md:grid-cols-2">
        <LabeledInput
          label="Pass"
          value={settings.antsword.pass}
          onChange={(value) => setSettings((prev) => ({ ...prev, antsword: { ...prev.antsword, pass: value } }))}
        />
        <LabeledToggle
          label="从表单中提取 pass 参数"
          checked={settings.antsword.extractParam}
          onChange={(checked) =>
            setSettings((prev) => ({ ...prev, antsword: { ...prev.antsword, extractParam: checked } }))
          }
        />
        <LabeledInput
          label="URL 解码轮数"
          value={String(settings.antsword.urlDecodeRounds)}
          onChange={(value) =>
            setSettings((prev) => ({
              ...prev,
              antsword: {
                ...prev.antsword,
                urlDecodeRounds: clampNumericText(value),
              },
            }))
          }
        />
        <LabeledSelect
          label="编码器"
          value={settings.antsword.encoder}
          options={[
            ["", "默认 (Base64)"],
            ["rot13", "ROT13"],
          ]}
          onChange={(value) =>
            setSettings((prev) => ({
              ...prev,
              antsword: { ...prev.antsword, encoder: value as DecoderSettings["antsword"]["encoder"] },
            }))
          }
        />
      </div>
    </DecoderSettingsSection>
  );
}
