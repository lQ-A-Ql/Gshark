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
    urlDecodeRounds: number;
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
    urlDecodeRounds: number;
    inputEncoding: "auto" | "base64" | "hex";
    cipher: "aes_ecb" | "xor";
  };
};

type BatchItem = {
  index: number;
  payload: string;
  label: string;
};

const SETTINGS_STORAGE_KEY = "gshark.stream-decoders.v1";

const DEFAULT_SETTINGS: DecoderSettings = {
  behinder: {
    pass: "rebeyond",
    key: "",
    extractParam: true,
    deriveKeyFromPass: true,
    urlDecodeRounds: 0,
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
    urlDecodeRounds: 0,
    inputEncoding: "auto",
    cipher: "aes_ecb",
  },
};

export function StreamDecoderWorkbench({
  payload,
  chunkLabel,
  tone = "blue",
  onApplyDecoded,
  batchItems,
  selectedBatchIndex,
  onApplyDecodedBatch,
}: {
  payload: string;
  chunkLabel: string;
  tone?: "blue" | "amber" | "emerald";
  onApplyDecoded?: (payload: string) => void | Promise<void>;
  batchItems?: BatchItem[];
  selectedBatchIndex?: number;
  onApplyDecodedBatch?: (patches: Array<{ index: number; body: string }>) => void | Promise<void>;
}) {
  const [settings, setSettings] = useState<DecoderSettings>(() => readDecoderSettings());
  const [activeSettings, setActiveSettings] = useState<Exclude<StreamDecoderKind, "base64"> | null>(null);
  const [result, setResult] = useState<StreamDecodeResult | null>(null);
  const [decodeError, setDecodeError] = useState("");
  const [runningDecoder, setRunningDecoder] = useState<StreamDecoderKind | null>(null);
  const [applyMessage, setApplyMessage] = useState("");
  const selectedBatchOrdinal = useMemo(() => {
    if (!batchItems || batchItems.length === 0) return 1;
    const hit = batchItems.findIndex((item) => item.index === selectedBatchIndex);
    return (hit >= 0 ? hit : 0) + 1;
  }, [batchItems, selectedBatchIndex]);
  const [rangeStart, setRangeStart] = useState(() => String(selectedBatchOrdinal));
  const [rangeEnd, setRangeEnd] = useState(() => String(selectedBatchOrdinal));

  useEffect(() => {
    persistDecoderSettings(settings);
  }, [settings]);

  useEffect(() => {
    setResult(null);
    setDecodeError("");
    setRunningDecoder(null);
    setApplyMessage("");
  }, [payload, chunkLabel]);

  useEffect(() => {
    setRangeStart(String(selectedBatchOrdinal));
    setRangeEnd(String(selectedBatchOrdinal));
  }, [selectedBatchOrdinal, batchItems?.length]);

  const preparedPayload = useMemo(() => normalizeTransportPayload(payload), [payload]);
  const extractedBase64Candidate = useMemo(() => extractBestBase64Candidate(preparedPayload), [preparedPayload]);
  const hasPayload = preparedPayload.trim().length > 0;
  const hasBatchMode = Boolean(batchItems && batchItems.length > 0 && onApplyDecodedBatch);
  const batchCount = batchItems?.length ?? 0;
  const toneClass = useMemo(() => {
    if (tone === "amber") return "border-amber-500/30 bg-amber-500/10";
    if (tone === "emerald") return "border-emerald-500/30 bg-emerald-500/10";
    return "border-blue-500/30 bg-blue-500/10";
  }, [tone]);

  async function decodeOne(decoder: StreamDecoderKind, rawPayload: string) {
    const normalized = normalizeTransportPayload(rawPayload);
    if (!normalized.trim()) {
      throw new Error("当前 payload 为空，无法解码");
    }
    const options =
      decoder === "behinder" ? settings.behinder :
      decoder === "antsword" ? settings.antsword :
      decoder === "godzilla" ? settings.godzilla :
      {};
    return bridge.decodeStreamPayload(decoder, prepareDecoderInput(decoder, normalized), options);
  }

  async function runDecoder(decoder: StreamDecoderKind) {
    if (!hasBatchMode && !hasPayload) {
      setDecodeError("当前 payload 为空，无法解码");
      return;
    }

    setRunningDecoder(decoder);
    setDecodeError("");
    setApplyMessage("");
    try {
      if (hasBatchMode && batchItems) {
        const start = clampBatchOrdinal(rangeStart, batchCount);
        const end = clampBatchOrdinal(rangeEnd, batchCount);
        const from = Math.min(start, end);
        const to = Math.max(start, end);
        const selected = batchItems.slice(from - 1, to);
        const patches: Array<{ index: number; body: string }> = [];
        let lastResult: StreamDecodeResult | null = null;

        for (const item of selected) {
          const next = await decodeOne(decoder, item.payload);
          lastResult = next;
          if (next.text.trim()) {
            patches.push({ index: item.index, body: next.text });
          }
        }

        if (patches.length === 0) {
          throw new Error("所选区间没有可覆盖的解码结果");
        }

        await onApplyDecodedBatch?.(patches);
        setResult(lastResult);
        setApplyMessage(`已批量解码并持久化 ${patches.length} 个片段，区间 ${from}-${to}`);
        return;
      }

      const next = await decodeOne(decoder, payload);
      setResult(next);
      if (onApplyDecoded && next.text.trim()) {
        await onApplyDecoded(next.text);
        setApplyMessage(`已使用 ${next.summary} 覆盖当前片段并写回持久层`);
      }
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
          <div className="text-sm font-semibold text-foreground">Payload 解码工作台</div>
          <div className="text-xs text-muted-foreground">{chunkLabel}</div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <DecoderButton
            icon={Binary}
            label="Base64"
            active={runningDecoder === "base64"}
            disabled={!hasPayload && !hasBatchMode}
            onClick={() => void runDecoder("base64")}
          />
          <DecoderButton
            icon={ShieldAlert}
            label="Behinder"
            active={runningDecoder === "behinder"}
            disabled={!hasPayload && !hasBatchMode}
            onClick={() => void runDecoder("behinder")}
          />
          <SettingsButton onClick={() => setActiveSettings("behinder")} />
          <DecoderButton
            icon={Bug}
            label="AntSword"
            active={runningDecoder === "antsword"}
            disabled={!hasPayload && !hasBatchMode}
            onClick={() => void runDecoder("antsword")}
          />
          <SettingsButton onClick={() => setActiveSettings("antsword")} />
          <DecoderButton
            icon={Wand2}
            label="Godzilla"
            active={runningDecoder === "godzilla"}
            disabled={!hasPayload && !hasBatchMode}
            onClick={() => void runDecoder("godzilla")}
          />
          <SettingsButton onClick={() => setActiveSettings("godzilla")} />
        </div>
      </div>

      {hasBatchMode && (
        <div className="mt-4 rounded-lg border border-border bg-background/80 p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-sm font-semibold text-foreground">批量解码区间</div>
              <div className="text-xs text-muted-foreground">
                选中任一解码器后，会对指定区间内的 payload 逐条解码，并覆盖原 payload 后持久化。
              </div>
            </div>
            <div className="rounded-md border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
              当前片段位于第 {selectedBatchOrdinal} / {batchCount} 条
            </div>
          </div>
          <div className="grid gap-3 md:grid-cols-[120px_120px_minmax(0,1fr)]">
            <LabeledInput
              label="起始序号"
              value={rangeStart}
              onChange={setRangeStart}
              placeholder="1"
            />
            <LabeledInput
              label="结束序号"
              value={rangeEnd}
              onChange={setRangeEnd}
              placeholder={String(batchCount)}
            />
            <div className="rounded-md border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
              将按当前列表顺序处理第 {clampBatchOrdinal(rangeStart, batchCount)} 到 {clampBatchOrdinal(rangeEnd, batchCount)} 条。
              {batchItems && batchItems.length > 0 && (
                <div className="mt-1 truncate text-foreground" title={batchItems[Math.min(batchCount - 1, Math.max(0, clampBatchOrdinal(rangeStart, batchCount) - 1))]?.label}>
                  起点: {batchItems[Math.min(batchCount - 1, Math.max(0, clampBatchOrdinal(rangeStart, batchCount) - 1))]?.label ?? "--"}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {activeSettings && (
        <div className="mt-4 rounded-lg border border-border bg-background/80 p-4">
          {activeSettings === "behinder" && (
            <DecoderSettingsSection title="Behinder 设置" onClose={() => setActiveSettings(null)}>
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
                  options={[["auto", "自动"], ["base64", "Base64"], ["hex", "Hex"]]}
                  onChange={(value) => setSettings((prev) => ({ ...prev, behinder: { ...prev.behinder, inputEncoding: value as DecoderSettings["behinder"]["inputEncoding"] } }))}
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
                  onChange={(checked) => setSettings((prev) => ({ ...prev, behinder: { ...prev.behinder, extractParam: checked } }))}
                />
                <LabeledToggle
                  label="自动从 pass 派生 key"
                  checked={settings.behinder.deriveKeyFromPass}
                  onChange={(checked) => setSettings((prev) => ({ ...prev, behinder: { ...prev.behinder, deriveKeyFromPass: checked } }))}
                />
              </div>
            </DecoderSettingsSection>
          )}
          {activeSettings === "antsword" && (
            <DecoderSettingsSection title="AntSword 设置" onClose={() => setActiveSettings(null)}>
              <div className="grid gap-3 md:grid-cols-2">
                <LabeledInput
                  label="Pass"
                  value={settings.antsword.pass}
                  onChange={(value) => setSettings((prev) => ({ ...prev, antsword: { ...prev.antsword, pass: value } }))}
                />
                <LabeledToggle
                  label="从表单中提取 pass 参数"
                  checked={settings.antsword.extractParam}
                  onChange={(checked) => setSettings((prev) => ({ ...prev, antsword: { ...prev.antsword, extractParam: checked } }))}
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
              </div>
            </DecoderSettingsSection>
          )}
          {activeSettings === "godzilla" && (
            <DecoderSettingsSection title="Godzilla 设置" onClose={() => setActiveSettings(null)}>
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
                  options={[["auto", "自动"], ["base64", "Base64"], ["hex", "Hex"]]}
                  onChange={(value) => setSettings((prev) => ({ ...prev, godzilla: { ...prev.godzilla, inputEncoding: value as DecoderSettings["godzilla"]["inputEncoding"] } }))}
                />
                <LabeledSelect
                  label="加密算法"
                  value={settings.godzilla.cipher}
                  options={[["aes_ecb", "AES-ECB"], ["xor", "XOR"]]}
                  onChange={(value) => setSettings((prev) => ({ ...prev, godzilla: { ...prev.godzilla, cipher: value as DecoderSettings["godzilla"]["cipher"] } }))}
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
                  onChange={(checked) => setSettings((prev) => ({ ...prev, godzilla: { ...prev.godzilla, extractParam: checked } }))}
                />
                <LabeledToggle
                  label="剥离 MD5 头尾标记"
                  checked={settings.godzilla.stripMarkers}
                  onChange={(checked) => setSettings((prev) => ({ ...prev, godzilla: { ...prev.godzilla, stripMarkers: checked } }))}
                />
              </div>
            </DecoderSettingsSection>
          )}
        </div>
      )}

      <div className="mt-4 grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <PayloadPane
          title={preparedPayload === payload ? "原始 payload" : "原始 payload（已自动提取）"}
          content={preparedPayload || "(empty payload)"}
          footer={
            preparedPayload !== payload
              ? "前端已自动剥离 HTTP 头或十六进制包裹层"
              : extractedBase64Candidate !== preparedPayload
                ? "检测到 Base64 候选串，点击 Base64 可直接尝试"
                : undefined
          }
        />
        <PayloadPane
          title={result ? `${result.summary} / ${result.encoding}` : "解码结果"}
          content={decodeError ? decodeError : result?.text || "点击上方解码器开始分析"}
          error={Boolean(decodeError)}
          loading={Boolean(runningDecoder)}
          bytesHex={result?.bytesHex}
          footer={applyMessage || undefined}
        />
      </div>
    </div>
  );
}

function clampBatchOrdinal(rawValue: string | number | undefined, total: number) {
  if (total <= 0) return 1;
  const parsed = Number(String(rawValue ?? "").replace(/[^0-9]/g, ""));
  if (!Number.isFinite(parsed) || parsed <= 0) return 1;
  return Math.max(1, Math.min(total, Math.floor(parsed)));
}

function prepareDecoderInput(decoder: StreamDecoderKind, payload: string): string {
  if (decoder === "base64") {
    return extractBestBase64Candidate(payload);
  }
  return payload;
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
      title="解码设置"
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
  footer,
}: {
  title: string;
  content: string;
  error?: boolean;
  loading?: boolean;
  bytesHex?: string;
  footer?: string;
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
      {footer && <div className="mt-2 text-[11px] text-blue-700 dark:text-blue-300">{footer}</div>}
    </div>
  );
}

const BASE64_CANDIDATE_PATTERN = /[A-Za-z0-9+/=_-]{8,}/g;

function normalizeTransportPayload(raw: string): string {
  let current = String(raw ?? "").trim();
  for (let i = 0; i < 3; i += 1) {
    let next = current;
    if (looksLikeHttpMessage(next)) {
      next = extractHttpBody(next).trim();
    }
    const unwrapped = unwrapHexEncodedText(next);
    if (unwrapped) {
      next = unwrapped.trim();
    }
    if (next === current) {
      break;
    }
    current = next;
  }
  return current;
}

function looksLikeHttpMessage(raw: string): boolean {
  const text = raw.trim();
  if (!text) return false;
  return text.startsWith("HTTP/") || text.startsWith("GET ") || text.startsWith("POST ") || text.includes("\nHost:") || text.includes("\r\nHost:");
}

function extractHttpBody(raw: string): string {
  const crlfIndex = raw.indexOf("\r\n\r\n");
  if (crlfIndex >= 0) return raw.slice(crlfIndex + 4);
  const lfIndex = raw.indexOf("\n\n");
  if (lfIndex >= 0) return raw.slice(lfIndex + 2);
  return raw;
}

function unwrapHexEncodedText(raw: string): string {
  const decoded = decodeLooseHex(raw);
  if (!decoded || decoded.length === 0) return "";
  const trimmed = trimNullBytes(decoded);
  if (trimmed.length === 0 || !looksMostlyPrintable(trimmed)) return "";
  return new TextDecoder().decode(trimmed);
}

function decodeLooseHex(raw: string): Uint8Array | null {
  const cleaned = raw.trim().replace(/[:\s]/g, "");
  if (!cleaned || cleaned.length % 2 !== 0 || /[^0-9a-fA-F]/.test(cleaned)) {
    return null;
  }
  const out = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < cleaned.length; i += 2) {
    out[i / 2] = Number.parseInt(cleaned.slice(i, i + 2), 16);
  }
  return out;
}

function trimNullBytes(data: Uint8Array): Uint8Array {
  let start = 0;
  let end = data.length;
  while (start < end && data[start] === 0) start += 1;
  while (end > start && data[end - 1] === 0) end -= 1;
  return data.slice(start, end);
}

function looksMostlyPrintable(data: Uint8Array): boolean {
  if (data.length === 0) return false;
  let printable = 0;
  for (const value of data) {
    if (value === 9 || value === 10 || value === 13 || (value >= 32 && value <= 126)) {
      printable += 1;
    }
  }
  return printable / data.length >= 0.85;
}

function extractBestBase64Candidate(raw: string): string {
  const trimmed = raw.trim();
  const matches = trimmed.match(BASE64_CANDIDATE_PATTERN);
  if (!matches || matches.length === 0) {
    return trimmed;
  }
  let best = "";
  for (const match of matches) {
    if (match.length > best.length) {
      best = match;
    }
  }
  return best || trimmed;
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
