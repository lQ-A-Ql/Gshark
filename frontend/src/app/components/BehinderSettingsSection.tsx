import { DecoderSettingsSection, LabeledInput, LabeledSelect, LabeledToggle } from "./StreamDecoderWorkbenchParts";
import type { DecoderSettings } from "./StreamDecoderWorkbenchUtils";
import { clampNumericText, type DecoderSettingsSectionProps } from "./StreamDecoderSettingsSectionTypes";

export function BehinderSettingsSection({ settings, setSettings, onClose }: DecoderSettingsSectionProps) {
  return (
    <DecoderSettingsSection title="Behinder 设置" onClose={onClose}>
      <div className="grid gap-3 md:grid-cols-2">
        <LabeledInput
          label="Pass"
          value={settings.behinder.pass}
          onChange={(value) => setSettings((prev) => ({ ...prev, behinder: { ...prev.behinder, pass: value } }))}
        />
        <LabeledInput
          label="手动 Key"
          value={settings.behinder.key}
          onChange={(value) => setSettings((prev) => ({ ...prev, behinder: { ...prev.behinder, key: value } }))}
          placeholder="留空则按 md5(pass)[:16] 派生"
        />
        <LabeledSelect
          label="输入编码"
          value={settings.behinder.inputEncoding}
          options={[
            ["auto", "自动"],
            ["base64", "Base64"],
            ["hex", "Hex"],
          ]}
          onChange={(value) =>
            setSettings((prev) => ({
              ...prev,
              behinder: {
                ...prev.behinder,
                inputEncoding: value as DecoderSettings["behinder"]["inputEncoding"],
              },
            }))
          }
        />
        <LabeledInput
          label="URL 解码轮数"
          value={String(settings.behinder.urlDecodeRounds)}
          onChange={(value) =>
            setSettings((prev) => ({
              ...prev,
              behinder: {
                ...prev.behinder,
                urlDecodeRounds: clampNumericText(value),
              },
            }))
          }
        />
        <LabeledToggle
          label="从表单中提取 pass 参数"
          checked={settings.behinder.extractParam}
          onChange={(checked) =>
            setSettings((prev) => ({ ...prev, behinder: { ...prev.behinder, extractParam: checked } }))
          }
        />
        <LabeledToggle
          label="自动从 pass 派生 key"
          checked={settings.behinder.deriveKeyFromPass}
          onChange={(checked) =>
            setSettings((prev) => ({ ...prev, behinder: { ...prev.behinder, deriveKeyFromPass: checked } }))
          }
        />
        <LabeledSelect
          label="加密模式"
          value={settings.behinder.cipherMode}
          options={[
            ["ecb", "AES-ECB (冰蝎4.x默认)"],
            ["cbc", "AES-CBC (冰蝎2.x/3.x)"],
          ]}
          onChange={(value) =>
            setSettings((prev) => ({
              ...prev,
              behinder: { ...prev.behinder, cipherMode: value as DecoderSettings["behinder"]["cipherMode"] },
            }))
          }
        />
        {settings.behinder.cipherMode === "cbc" && (
          <LabeledInput
            label="IV (留空则全零)"
            value={settings.behinder.iv}
            onChange={(value) => setSettings((prev) => ({ ...prev, behinder: { ...prev.behinder, iv: value } }))}
            placeholder="留空则使用全零 IV"
          />
        )}
      </div>
    </DecoderSettingsSection>
  );
}
