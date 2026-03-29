import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Binary, Bug, Cog, KeyRound, LoaderCircle, ShieldAlert, Wand2 } from "lucide-react";
import type { StreamDecodeResult, StreamDecoderKind } from "../core/types";
import { bridge } from "../integrations/wailsBridge";

type DecoderSettings = {
  behinder: {
    pass: string;
    key: string;
    extractParam: boolean;
    deriveKeyFromPass: boolean;
    inputEncoding: "auto" | "base64" | "hex";
  };
  antsword: {
    pass: string;
    extractParam: boolean;
    urlDecodeRounds: number;
  };
  godzilla: {
    pass: string;
    key: string;
    extractParam: boolean;
    stripMarkers: boolean;
    inputEncoding: "auto" | "base64" | "hex";
    cipher: "aes_ecb" | "xor";
  };
};

const SETTINGS_STORAGE_KEY = "gshark.stream-decoders.v1";

const DEFAULT_SETTINGS: DecoderSettings = {
  behinder: {
    pass: "rebeyond",
    key: "",
    extractParam: true,
    deriveKeyFromPass: true,
    inputEncoding: "auto",
  },
  antsword: {
    pass: "pass",
    extractParam: true,
    urlDecodeRounds: 1,
  },
  godzilla: {
    pass: "pass",
    key: "",
    extractParam: true,
    stripMarkers: true,
    inputEncoding: "auto",
    cipher: "aes_ecb",
  },
};

export function StreamDecoderWorkbench({
  payload,
  chunkLabel,
  tone = "blue",
}: {
  payload: string;
  chunkLabel: string;
  tone?: "blue" | "amber" | "emerald";
}) {
  const [settings, setSettings] = useState<DecoderSettings>(() => readDecoderSettings());
  const [activeSettings, setActiveSettings] = useState<Exclude<StreamDecoderKind, "base64"> | null>(null);
  const [result, setResult] = useState<StreamDecodeResult | null>(null);
  const [decodeError, setDecodeError] = useState("");
  const [runningDecoder, setRunningDecoder] = useState<StreamDecoderKind | null>(null);

  useEffect(() => {
    persistDecoderSettings(settings);
  }, [settings]);

  useEffect(() => {
    setResult(null);
    setDecodeError("");
    setRunningDecoder(null);
  }, [payload, chunkLabel]);

  const hasPayload = payload.trim().length > 0;
  const toneClass = useMemo(() => {
    if (tone === "amber") return "border-amber-500/30 bg-amber-500/10";
    if (tone === "emerald") return "border-emerald-500/30 bg-emerald-500/10";
    return "border-blue-500/30 bg-blue-500/10";
  }, [tone]);

  async function runDecoder(decoder: StreamDecoderKind) {
    if (!hasPayload) {
      setDecodeError("当前载荷为空，无法解码");
      return;
    }
    setRunningDecoder(decoder);
    setDecodeError("");
    try {
      const options =
        decoder === "behinder" ? settings.behinder :
        decoder === "antsword" ? settings.antsword :
        decoder === "godzilla" ? settings.godzilla :
        {};
      const next = await bridge.decodeStreamPayload(decoder, payload, options);
      setResult(next);
    } catch (error) {
      setDecodeError(error instanceof Error ? error.message : "解码失败");
    } finally {
      setRunningDecoder(null);
    }
  }

  return (
    <div className={`rounded-xl border ${toneClass} p-4`}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-foreground">载荷解码工作台</div>
          <div className="text-xs text-muted-foreground">{chunkLabel}</div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <DecoderButton
            icon={Binary}
            label="Base64"
            active={runningDecoder === "base64"}
            disabled={!hasPayload}
            onClick={() => void runDecoder("base64")}
          />
          <DecoderButton
            icon={ShieldAlert}
            label="冰蝎"
            active={runningDecoder === "behinder"}
            disabled={!hasPayload}
            onClick={() => void runDecoder("behinder")}
          />
          <SettingsButton onClick={() => setActiveSettings("behinder")} />
          <DecoderButton
            icon={Bug}
            label="蚁剑"
            active={runningDecoder === "antsword"}
            disabled={!hasPayload}
            onClick={() => void runDecoder("antsword")}
          />
          <SettingsButton onClick={() => setActiveSettings("antsword")} />
          <DecoderButton
            icon={Wand2}
            label="哥斯拉"
            active={runningDecoder === "godzilla"}
            disabled={!hasPayload}
            onClick={() => void runDecoder("godzilla")}
          />
          <SettingsButton onClick={() => setActiveSettings("godzilla")} />
        </div>
      </div>

      {activeSettings && (
        <div className="mt-4 rounded-lg border border-border bg-background/80 p-4">
          {activeSettings === "behinder" && (
            <DecoderSettingsSection title="冰蝎设置" onClose={() => setActiveSettings(null)}>
              <div className="grid gap-3 md:grid-cols-2">
                <LabeledInput label="Pass" value={settings.behinder.pass} onChange={(value) => setSettings((prev) => ({ ...prev, behinder: { ...prev.behinder, pass: value } }))} />
                <LabeledInput label="手动 Key" value={settings.behinder.key} onChange={(value) => setSettings((prev) => ({ ...prev, behinder: { ...prev.behinder, key: value } }))} placeholder="留空则按 md5(pass)[:16] 派生" />
                <LabeledSelect label="输入编码" value={settings.behinder.inputEncoding} options={[["auto", "自动"], ["base64", "Base64"], ["hex", "Hex"]]} onChange={(value) => setSettings((prev) => ({ ...prev, behinder: { ...prev.behinder, inputEncoding: value as DecoderSettings["behinder"]["inputEncoding"] } }))} />
                <LabeledToggle label="从表单提取 pass 参数" checked={settings.behinder.extractParam} onChange={(checked) => setSettings((prev) => ({ ...prev, behinder: { ...prev.behinder, extractParam: checked } }))} />
                <LabeledToggle label="自动从 pass 派生 key" checked={settings.behinder.deriveKeyFromPass} onChange={(checked) => setSettings((prev) => ({ ...prev, behinder: { ...prev.behinder, deriveKeyFromPass: checked } }))} />
              </div>
            </DecoderSettingsSection>
          )}
          {activeSettings === "antsword" && (
            <DecoderSettingsSection title="蚁剑设置" onClose={() => setActiveSettings(null)}>
              <div className="grid gap-3 md:grid-cols-2">
                <LabeledInput label="Pass" value={settings.antsword.pass} onChange={(value) => setSettings((prev) => ({ ...prev, antsword: { ...prev.antsword, pass: value } }))} />
                <LabeledToggle label="从表单提取 pass 参数" checked={settings.antsword.extractParam} onChange={(checked) => setSettings((prev) => ({ ...prev, antsword: { ...prev.antsword, extractParam: checked } }))} />
                <LabeledInput label="URL 解码轮数" value={String(settings.antsword.urlDecodeRounds)} onChange={(value) => setSettings((prev) => ({ ...prev, antsword: { ...prev.antsword, urlDecodeRounds: Math.max(0, Number(value.replace(/[^0-9]/g, "")) || 0) } }))} />
              </div>
            </DecoderSettingsSection>
          )}
          {activeSettings === "godzilla" && (
            <DecoderSettingsSection title="哥斯拉设置" onClose={() => setActiveSettings(null)}>
              <div className="grid gap-3 md:grid-cols-2">
                <LabeledInput label="Pass" value={settings.godzilla.pass} onChange={(value) => setSettings((prev) => ({ ...prev, godzilla: { ...prev.godzilla, pass: value } }))} />
                <LabeledInput label="Key" value={settings.godzilla.key} onChange={(value) => setSettings((prev) => ({ ...prev, godzilla: { ...prev.godzilla, key: value } }))} />
                <LabeledSelect label="输入编码" value={settings.godzilla.inputEncoding} options={[["auto", "自动"], ["base64", "Base64"], ["hex", "Hex"]]} onChange={(value) => setSettings((prev) => ({ ...prev, godzilla: { ...prev.godzilla, inputEncoding: value as DecoderSettings["godzilla"]["inputEncoding"] } }))} />
                <LabeledSelect label="加密算法" value={settings.godzilla.cipher} options={[["aes_ecb", "AES-ECB"], ["xor", "XOR"]]} onChange={(value) => setSettings((prev) => ({ ...prev, godzilla: { ...prev.godzilla, cipher: value as DecoderSettings["godzilla"]["cipher"] } }))} />
                <LabeledToggle label="从表单提取 pass 参数" checked={settings.godzilla.extractParam} onChange={(checked) => setSettings((prev) => ({ ...prev, godzilla: { ...prev.godzilla, extractParam: checked } }))} />
                <LabeledToggle label="剥离 MD5 头尾标记" checked={settings.godzilla.stripMarkers} onChange={(checked) => setSettings((prev) => ({ ...prev, godzilla: { ...prev.godzilla, stripMarkers: checked } }))} />
              </div>
            </DecoderSettingsSection>
          )}
        </div>
      )}

      <div className="mt-4 grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <PayloadPane title="原始载荷" content={payload || "(empty payload)"} />
        <PayloadPane
          title={result ? `${result.summary} · ${result.encoding}` : "解码结果"}
          content={decodeError ? decodeError : result?.text || "点击上方按钮开始解码"}
          error={Boolean(decodeError)}
          loading={Boolean(runningDecoder)}
          bytesHex={result?.bytesHex}
        />
      </div>
    </div>
  );
}

function DecoderButton({
  icon: Icon,
  label,
  active,
  disabled,
  onClick,
}: {
  icon: typeof KeyRound;
  label: string;
  active: boolean;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled || active}
      className="inline-flex items-center gap-2 rounded-lg border border-border bg-background px-3 py-2 text-xs font-medium text-foreground shadow-sm transition-colors hover:bg-accent disabled:cursor-not-allowed disabled:opacity-60"
    >
      {active ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Icon className="h-3.5 w-3.5" />}
      {label}
    </button>
  );
}

function SettingsButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center rounded-lg border border-border bg-background p-2 text-muted-foreground shadow-sm transition-colors hover:bg-accent hover:text-foreground"
      title="解密设置"
    >
      <Cog className="h-3.5 w-3.5" />
    </button>
  );
}

function DecoderSettingsSection({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-sm font-semibold text-foreground">{title}</div>
        <button onClick={onClose} className="rounded border border-border px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground">
          收起
        </button>
      </div>
      {children}
    </div>
  );
}

function LabeledInput({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}) {
  return (
    <label className="flex flex-col gap-1 text-xs text-muted-foreground">
      <span>{label}</span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="rounded-md border border-border bg-background px-3 py-2 font-mono text-foreground outline-none focus:border-blue-500"
      />
    </label>
  );
}

function LabeledSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: Array<[string, string]>;
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex flex-col gap-1 text-xs text-muted-foreground">
      <span>{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-md border border-border bg-background px-3 py-2 text-foreground outline-none focus:border-blue-500"
      >
        {options.map(([optionValue, optionLabel]) => (
          <option key={optionValue} value={optionValue}>{optionLabel}</option>
        ))}
      </select>
    </label>
  );
}

function LabeledToggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className="flex items-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-xs text-foreground">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} className="accent-blue-600" />
      <span>{label}</span>
    </label>
  );
}

function PayloadPane({
  title,
  content,
  error = false,
  loading = false,
  bytesHex,
}: {
  title: string;
  content: string;
  error?: boolean;
  loading?: boolean;
  bytesHex?: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-background/90 p-3">
      <div className="mb-2 flex items-center justify-between">
        <div className="text-xs font-semibold text-foreground">{title}</div>
        {loading && <span className="text-[11px] text-blue-600">解码中...</span>}
      </div>
      <pre className={`max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-md border px-3 py-2 text-xs leading-5 ${error ? "border-rose-500/30 bg-rose-500/10 text-rose-700" : "border-border bg-card text-foreground"}`}>
        {content}
      </pre>
      {bytesHex && !error && (
        <div className="mt-2 rounded-md border border-border bg-card px-3 py-2">
          <div className="mb-1 text-[11px] font-semibold text-muted-foreground">Hex</div>
          <pre className="max-h-28 overflow-auto whitespace-pre-wrap break-all text-[11px] leading-5 text-muted-foreground">{bytesHex}</pre>
        </div>
      )}
    </div>
  );
}

function readDecoderSettings(): DecoderSettings {
  if (typeof window === "undefined") return DEFAULT_SETTINGS;
  try {
    const raw = window.localStorage.getItem(SETTINGS_STORAGE_KEY);
    if (!raw) return DEFAULT_SETTINGS;
    const parsed = JSON.parse(raw);
    return {
      behinder: { ...DEFAULT_SETTINGS.behinder, ...(parsed.behinder ?? {}) },
      antsword: { ...DEFAULT_SETTINGS.antsword, ...(parsed.antsword ?? {}) },
      godzilla: { ...DEFAULT_SETTINGS.godzilla, ...(parsed.godzilla ?? {}) },
    };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

function persistDecoderSettings(settings: DecoderSettings) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(settings));
  } catch {
    // ignore persistence errors
  }
}
