import type { Dispatch, SetStateAction } from "react";

import {
  DecoderSettingsSection,
  LabeledInput,
  LabeledSelect,
  LabeledToggle,
} from "./StreamDecoderWorkbenchParts";
import type { DecoderSettings } from "./StreamDecoderWorkbenchUtils";

export type DecoderSettingsKind = "behinder" | "antsword" | "godzilla";

type StreamDecoderSettingsPanelProps = {
  activeSettings: DecoderSettingsKind;
  settings: DecoderSettings;
  setSettings: Dispatch<SetStateAction<DecoderSettings>>;
  onClose: () => void;
};

export function StreamDecoderSettingsPanel({
  activeSettings,
  settings,
  setSettings,
  onClose,
}: StreamDecoderSettingsPanelProps) {
  return (
    <div className="mt-4 rounded-lg border border-border bg-background/80 p-4">
      {activeSettings === "behinder" && (
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
                    urlDecodeRounds: Math.max(0, Number(value.replace(/[^0-9]/g, "")) || 0),
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
                onChange={(value) =>
                  setSettings((prev) => ({ ...prev, behinder: { ...prev.behinder, iv: value } }))
                }
                placeholder="留空则使用全零 IV"
              />
            )}
          </div>
        </DecoderSettingsSection>
      )}
      {activeSettings === "antsword" && (
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
                    urlDecodeRounds: Math.max(0, Number(value.replace(/[^0-9]/g, "")) || 0),
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
      )}
      {activeSettings === "godzilla" && (
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
                    urlDecodeRounds: Math.max(0, Number(value.replace(/[^0-9]/g, "")) || 0),
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
      )}
    </div>
  );
}
