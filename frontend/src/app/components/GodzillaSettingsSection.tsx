import { DecoderSettingsSection, LabeledInput, LabeledSelect, LabeledToggle } from "./StreamDecoderWorkbenchParts";
import type { DecoderSettings } from "./StreamDecoderWorkbenchUtils";
import { clampNumericText, type DecoderSettingsSectionProps } from "./StreamDecoderSettingsSectionTypes";

export function GodzillaSettingsSection({ settings, setSettings, onClose }: DecoderSettingsSectionProps) {
  return (
    <DecoderSettingsSection title="Godzilla 设置" onClose={onClose}>
      <div className="grid gap-3 md:grid-cols-2">
        <LabeledInput
          label="Pass"
          value={settings.godzilla.pass}
          onChange={(value) => setSettings((prev) => ({ ...prev, godzilla: { ...prev.godzilla, pass: value } }))}
        />
        <LabeledInput
          label="Key"
          value={settings.godzilla.key}
          onChange={(value) => setSettings((prev) => ({ ...prev, godzilla: { ...prev.godzilla, key: value } }))}
        />
        <LabeledSelect
          label="输入编码"
          value={settings.godzilla.inputEncoding}
          options={[
            ["auto", "自动"],
            ["base64", "Base64"],
            ["hex", "Hex"],
          ]}
          onChange={(value) =>
            setSettings((prev) => ({
              ...prev,
              godzilla: {
                ...prev.godzilla,
                inputEncoding: value as DecoderSettings["godzilla"]["inputEncoding"],
              },
            }))
          }
        />
        <LabeledSelect
          label="加密算法"
          value={settings.godzilla.cipher}
          options={[
            ["aes_ecb", "AES-ECB"],
            ["aes_cbc", "AES-CBC"],
            ["xor", "XOR (PHP)"],
          ]}
          onChange={(value) =>
            setSettings((prev) => ({
              ...prev,
              godzilla: { ...prev.godzilla, cipher: value as DecoderSettings["godzilla"]["cipher"] },
            }))
          }
        />
        <LabeledInput
          label="URL 解码轮数"
          value={String(settings.godzilla.urlDecodeRounds)}
          onChange={(value) =>
            setSettings((prev) => ({
              ...prev,
              godzilla: {
                ...prev.godzilla,
                urlDecodeRounds: clampNumericText(value),
              },
            }))
          }
        />
        <LabeledToggle
          label="从表单中提取 pass 参数"
          checked={settings.godzilla.extractParam}
          onChange={(checked) =>
            setSettings((prev) => ({ ...prev, godzilla: { ...prev.godzilla, extractParam: checked } }))
          }
        />
        <LabeledToggle
          label="剥离 MD5 头尾标记"
          checked={settings.godzilla.stripMarkers}
          onChange={(checked) =>
            setSettings((prev) => ({ ...prev, godzilla: { ...prev.godzilla, stripMarkers: checked } }))
          }
        />
      </div>
    </DecoderSettingsSection>
  );
}
