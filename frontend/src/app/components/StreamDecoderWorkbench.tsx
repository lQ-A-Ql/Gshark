import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Binary, Bug, Cog, KeyRound, LoaderCircle, Search, ShieldAlert, Wand2 } from "lucide-react";
import type { StreamDecodeResult, StreamDecoderKind } from "../core/types";
import { bridge } from "../integrations/wailsBridge";

type DecoderSettings = {
  behinder: {
    pass: string;
    key: string;
    iv: string;
    extractParam: boolean;
    deriveKeyFromPass: boolean;
    urlDecodeRounds: number;
    inputEncoding: "auto" | "base64" | "hex";
    cipherMode: "ecb" | "cbc";
  };
  antsword: {
    pass: string;
    extractParam: boolean;
    urlDecodeRounds: number;
    encoder: "" | "rot13";
  };
  godzilla: {
    pass: string;
    key: string;
    extractParam: boolean;
    stripMarkers: boolean;
    urlDecodeRounds: number;
    inputEncoding: "auto" | "base64" | "hex";
    cipher: "aes_ecb" | "aes_cbc" | "xor";
  };
};

type BatchItem = {
  index: number;
  payload: string;
  label: string;
};

type BatchDecodeProgress = {
  total: number;
  done: number;
  success: number;
  failed: number;
  currentLabel: string;
};

const MAX_BATCH_FAILURE_DETAILS = 20;

const SETTINGS_STORAGE_KEY = "gshark.stream-decoders.v1";

const DEFAULT_SETTINGS: DecoderSettings = {
  behinder: {
    pass: "rebeyond",
    key: "",
    iv: "",
    extractParam: true,
    deriveKeyFromPass: true,
    urlDecodeRounds: 0,
    inputEncoding: "auto",
    cipherMode: "ecb",
  },
  antsword: {
    pass: "pass",
    extractParam: true,
    urlDecodeRounds: 1,
    encoder: "",
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
  const [batchProgress, setBatchProgress] = useState<BatchDecodeProgress | null>(null);
  const [batchFailureDetails, setBatchFailureDetails] = useState<string[]>([]);
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
    setBatchProgress(null);
    setBatchFailureDetails([]);
  }, [payload, chunkLabel]);

  useEffect(() => {
    setRangeStart(String(selectedBatchOrdinal));
    setRangeEnd(String(selectedBatchOrdinal));
  }, [selectedBatchOrdinal, batchItems?.length]);

  const preparedPayload = useMemo(() => normalizeTransportPayload(payload), [payload]);
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
        let successCount = 0;
        let failedCount = 0;
        const failureMessages: string[] = [];

        setBatchProgress({
          total: selected.length,
          done: 0,
          success: 0,
          failed: 0,
          currentLabel: selected[0]?.label ?? "",
        });
        setBatchFailureDetails([]);

        for (let idx = 0; idx < selected.length; idx += 1) {
          const item = selected[idx];
          setBatchProgress((prev) => prev ? { ...prev, currentLabel: item.label } : prev);
          try {
            const next = await decodeOne(decoder, item.payload);
            lastResult = next;
            if (next.text.trim()) {
              patches.push({ index: item.index, body: next.text });
              successCount += 1;
            } else {
              failedCount += 1;
              if (failureMessages.length < MAX_BATCH_FAILURE_DETAILS) {
                failureMessages.push(`[${item.index}] ${item.label}: 解码结果为空`);
              }
            }
          } catch (error) {
            failedCount += 1;
            const message = error instanceof Error ? error.message : "解码失败";
            if (failureMessages.length < MAX_BATCH_FAILURE_DETAILS) {
              failureMessages.push(`[${item.index}] ${item.label}: ${message}`);
            }
          }
          setBatchProgress((prev) => prev ? {
            ...prev,
            done: idx + 1,
            success: successCount,
            failed: failedCount,
          } : prev);
        }

        setBatchFailureDetails(failureMessages);

        if (patches.length === 0) {
          throw new Error("所选区间没有可覆盖的解码结果");
        }

        await onApplyDecodedBatch?.(patches);
        setResult(lastResult);
        setApplyMessage(`已批量解码并持久化 ${patches.length}/${selected.length} 个片段（失败 ${failedCount} 条），区间 ${from}-${to}`);
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
      if (!hasBatchMode) {
        setBatchProgress(null);
      }
    }
  }

  return (
    <div className={`min-w-0 rounded-xl border ${toneClass} p-4`}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-foreground">Payload 解码工作台</div>
          <div className="text-xs text-muted-foreground">{chunkLabel}</div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <DecoderButton
            icon={Search}
            label="自动检测"
            active={runningDecoder === "auto"}
            disabled={!hasPayload && !hasBatchMode}
            onClick={() => void runDecoder("auto")}
          />
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

          {batchProgress && (
            <div className="mt-3 rounded-md border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span>进度：{batchProgress.done}/{batchProgress.total}</span>
                <span>成功：{batchProgress.success} · 失败：{batchProgress.failed}</span>
              </div>
              {batchProgress.total > 0 && (
                <div className="mt-2 h-2 w-full overflow-hidden rounded bg-muted">
                  <div
                    className="h-full bg-blue-500 transition-all"
                    style={{ width: `${Math.min(100, Math.round((batchProgress.done / batchProgress.total) * 100))}%` }}
                  />
                </div>
              )}
              {batchProgress.currentLabel && (
                <div className="mt-2 truncate text-foreground" title={batchProgress.currentLabel}>
                  当前：{batchProgress.currentLabel}
                </div>
              )}
            </div>
          )}

          {batchFailureDetails.length > 0 && (
            <div className="mt-3 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-200">
              <div className="font-semibold">批量失败明细（最多显示 {MAX_BATCH_FAILURE_DETAILS} 条）</div>
              <ul className="mt-2 max-h-40 list-disc space-y-1 overflow-auto pl-4">
                {batchFailureDetails.map((item, idx) => (
                  <li key={`${idx}-${item}`}>{item}</li>
                ))}
              </ul>
            </div>
          )}
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
                <LabeledSelect
                  label="加密模式"
                  value={settings.behinder.cipherMode}
                  options={[["ecb", "AES-ECB (冰蝎4.x默认)"], ["cbc", "AES-CBC (冰蝎2.x/3.x)"]]}
                  onChange={(value) => setSettings((prev) => ({ ...prev, behinder: { ...prev.behinder, cipherMode: value as DecoderSettings["behinder"]["cipherMode"] } }))}
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
                <LabeledSelect
                  label="编码器"
                  value={settings.antsword.encoder}
                  options={[["", "默认 (Base64)"], ["rot13", "ROT13"]]}
                  onChange={(value) => setSettings((prev) => ({ ...prev, antsword: { ...prev.antsword, encoder: value as DecoderSettings["antsword"]["encoder"] } }))}
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
                  options={[["aes_ecb", "AES-ECB"], ["aes_cbc", "AES-CBC"], ["xor", "XOR (PHP)"]]}
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

      <div className="mt-4 grid min-w-0 gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <PayloadPane
          title={preparedPayload === payload ? "原始 payload" : "原始 payload（已自动提取）"}
          content={preparedPayload || "(empty payload)"}
          footer={
            preparedPayload !== payload
              ? "前端仅做轻量预处理；实际提取与解码以服务端规则为准"
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
      <pre className={`max-h-72 min-w-0 overflow-auto whitespace-pre-wrap break-all rounded-md border px-3 py-2 text-xs leading-5 ${error ? "border-rose-500/30 bg-rose-500/10 text-rose-700" : "border-border bg-card text-foreground"}`}>
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

const HTTP_METHOD_PREFIXES = ["GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE "];

function normalizeTransportPayload(raw: string): string {
  const current = String(raw ?? "").trim();
  if (!current) {
    return "";
  }
  if (looksLikeHttpMessage(current)) {
    return extractHttpBody(current).trim();
  }
  return current;
}

function looksLikeHttpMessage(raw: string): boolean {
  const text = raw.trim();
  if (!text) return false;
  if (text.startsWith("HTTP/")) {
    return true;
  }
  for (const method of HTTP_METHOD_PREFIXES) {
    if (text.startsWith(method)) {
      return true;
    }
  }
  return text.includes("\nHost:") || text.includes("\r\nHost:");
}

function extractHttpBody(raw: string): string {
  const crlfIndex = raw.indexOf("\r\n\r\n");
  if (crlfIndex >= 0) return raw.slice(crlfIndex + 4);
  const lfIndex = raw.indexOf("\n\n");
  if (lfIndex >= 0) return raw.slice(lfIndex + 2);
  return raw;
}

function extractBestBase64Candidate(raw: string): string {
  return raw.trim();
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
