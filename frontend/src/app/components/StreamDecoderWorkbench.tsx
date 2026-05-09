import { useEffect, useMemo, useRef, useState } from "react";
import { Binary, Bug, Search, ShieldAlert, Wand2 } from "lucide-react";
import type { StreamDecodeResult, StreamDecoderKind, StreamPayloadInspection } from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import {
  ApplyModeButton,
  DecoderButton,
  LabeledInput,
  PayloadPane,
  SettingsButton,
} from "./StreamDecoderWorkbenchParts";
import { StreamDecoderSettingsPanel, type DecoderSettingsKind } from "./StreamDecoderSettingsPanel";
import {
  asKnownDecoder,
  buildDecoderOptions,
  candidateHintBadges,
  clampBatchOrdinal,
  MAX_BATCH_FAILURE_DETAILS,
  mergeDecoderHintSources,
  mergeHintIntoSettings,
  normalizeTransportPayload,
  prepareDecoderInput,
  isAbortError,
  persistDecoderSettings,
  readDecoderSettings,
  type BatchDecodeProgress,
  type BatchItem,
  type DecoderApplyMode,
  type DecoderHintSource,
  type DecoderSettings,
} from "./StreamDecoderWorkbenchUtils";

export function StreamDecoderWorkbench({
  payload,
  inspectRevision,
  chunkLabel,
  tone = "blue",
  onApplyDecoded,
  batchItems,
  selectedBatchIndex,
  onApplyDecodedBatch,
  sourceHint,
}: {
  payload: string;
  inspectRevision?: number | string;
  chunkLabel: string;
  tone?: "blue" | "amber" | "emerald";
  onApplyDecoded?: (payload: string) => void | Promise<void>;
  batchItems?: BatchItem[];
  selectedBatchIndex?: number;
  onApplyDecodedBatch?: (patches: Array<{ index: number; body: string }>) => void | Promise<void>;
  sourceHint?: DecoderHintSource;
}) {
  const [settings, setSettings] = useState<DecoderSettings>(() => readDecoderSettings());
  const [activeSettings, setActiveSettings] = useState<DecoderSettingsKind | null>(null);
  const [result, setResult] = useState<StreamDecodeResult | null>(null);
  const [decodeError, setDecodeError] = useState("");
  const [runningDecoder, setRunningDecoder] = useState<StreamDecoderKind | null>(null);
  const [applyMessage, setApplyMessage] = useState("");
  const [batchProgress, setBatchProgress] = useState<BatchDecodeProgress | null>(null);
  const [batchFailureDetails, setBatchFailureDetails] = useState<string[]>([]);
  const [inspection, setInspection] = useState<StreamPayloadInspection | null>(null);
  const [inspectionLoading, setInspectionLoading] = useState(false);
  const [inspectionError, setInspectionError] = useState("");
  const [selectedCandidateId, setSelectedCandidateId] = useState("");
  const [applyMode, setApplyMode] = useState<DecoderApplyMode>("derived");
  const activeDecodeAbortRef = useRef<AbortController | null>(null);
  const canOverwrite = Boolean(onApplyDecoded);
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
    activeDecodeAbortRef.current?.abort();
    activeDecodeAbortRef.current = null;
    setResult(null);
    setDecodeError("");
    setRunningDecoder(null);
    setApplyMessage("");
    setBatchProgress(null);
    setBatchFailureDetails([]);
    setInspection(null);
    setInspectionError("");
    setInspectionLoading(false);
    setSelectedCandidateId("");
    setApplyMode("derived");
  }, [payload, chunkLabel]);

  useEffect(
    () => () => {
      activeDecodeAbortRef.current?.abort();
    },
    [],
  );

  useEffect(() => {
    if (!canOverwrite && applyMode === "overwrite") {
      setApplyMode("derived");
    }
  }, [applyMode, canOverwrite]);

  useEffect(() => {
    setRangeStart(String(selectedBatchOrdinal));
    setRangeEnd(String(selectedBatchOrdinal));
  }, [selectedBatchOrdinal, batchItems?.length]);

  const preparedPayload = useMemo(() => normalizeTransportPayload(payload), [payload]);
  const selectedCandidate = useMemo(
    () => inspection?.candidates.find((item) => item.id === selectedCandidateId) ?? inspection?.candidates[0] ?? null,
    [inspection, selectedCandidateId],
  );
  const activeHintSource = useMemo<DecoderHintSource | undefined>(
    () => mergeDecoderHintSources(selectedCandidate, sourceHint),
    [selectedCandidate, sourceHint],
  );
  const effectivePayload = useMemo(() => {
    const candidateValue = selectedCandidate?.value?.trim();
    if (candidateValue) {
      return candidateValue;
    }
    const normalized = inspection?.normalizedPayload?.trim();
    if (normalized) {
      return normalized;
    }
    return preparedPayload;
  }, [inspection?.normalizedPayload, preparedPayload, selectedCandidate?.value]);
  const candidateCount = inspection?.candidates.length ?? 0;
  const hasPayload = preparedPayload.trim().length > 0;
  const hasBatchMode = Boolean(batchItems && batchItems.length > 0 && onApplyDecodedBatch);
  const batchCount = batchItems?.length ?? 0;
  const toneClass = useMemo(() => {
    if (tone === "amber") return "border-amber-500/30 bg-amber-500/10";
    if (tone === "emerald") return "border-emerald-500/30 bg-emerald-500/10";
    return "border-blue-500/30 bg-blue-500/10";
  }, [tone]);

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    if (!preparedPayload.trim()) {
      setInspection(null);
      setInspectionError("");
      setInspectionLoading(false);
      setSelectedCandidateId("");
      return;
    }
    setInspectionLoading(true);
    setInspectionError("");
    void bridge
      .inspectStreamPayload(payload, controller.signal)
      .then((next) => {
        if (cancelled) return;
        setInspection(next);
        const suggested =
          next.suggestedCandidateId && next.candidates.some((item) => item.id === next.suggestedCandidateId)
            ? next.suggestedCandidateId
            : (next.candidates[0]?.id ?? "");
        setSelectedCandidateId(suggested);
      })
      .catch((error) => {
        if (cancelled) return;
        if (isAbortError(error)) return;
        setInspection(null);
        setSelectedCandidateId("");
        setInspectionError(error instanceof Error ? error.message : "payload 候选提取失败");
      })
      .finally(() => {
        if (!cancelled) {
          setInspectionLoading(false);
        }
      });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [payload, preparedPayload, inspectRevision]);

  useEffect(() => {
    setSettings((prev) => mergeHintIntoSettings(prev, activeHintSource));
  }, [activeHintSource]);

  async function decodeOne(decoder: StreamDecoderKind, rawPayload: string, signal?: AbortSignal) {
    const normalized = normalizeTransportPayload(rawPayload);
    if (!normalized.trim()) {
      throw new Error("当前 payload 为空，无法解码");
    }
    const options = buildDecoderOptions(decoder, settings, activeHintSource);
    return bridge.decodeStreamPayload(decoder, prepareDecoderInput(decoder, normalized), options, signal);
  }

  function cancelDecode() {
    activeDecodeAbortRef.current?.abort();
    setRunningDecoder(null);
    setDecodeError("解码已取消");
    setBatchProgress(null);
  }

  async function runDecoder(decoder: StreamDecoderKind) {
    if (!hasBatchMode && !hasPayload) {
      setDecodeError("当前 payload 为空，无法解码");
      return;
    }

    activeDecodeAbortRef.current?.abort();
    const controller = new AbortController();
    activeDecodeAbortRef.current = controller;
    setSettings((prev) => mergeHintIntoSettings(prev, activeHintSource));
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
          setBatchProgress((prev) => (prev ? { ...prev, currentLabel: item.label } : prev));
          try {
            if (controller.signal.aborted) {
              throw new Error("解码已取消");
            }
            const next = await decodeOne(decoder, item.payload, controller.signal);
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
          setBatchProgress((prev) =>
            prev
              ? {
                  ...prev,
                  done: idx + 1,
                  success: successCount,
                  failed: failedCount,
                }
              : prev,
          );
        }

        setBatchFailureDetails(failureMessages);

        if (patches.length === 0) {
          throw new Error("所选区间没有可覆盖的解码结果");
        }

        await onApplyDecodedBatch?.(patches);
        setResult(lastResult);
        setApplyMessage(
          `已批量解码并持久化 ${patches.length}/${selected.length} 个片段（失败 ${failedCount} 条），区间 ${from}-${to}`,
        );
        return;
      }

      const next = await decodeOne(decoder, effectivePayload, controller.signal);
      setResult(next);
      if (applyMode === "overwrite" && onApplyDecoded && next.text.trim()) {
        await onApplyDecoded(next.text);
        setApplyMessage(`已使用 ${next.summary} 覆盖当前片段并写回持久层`);
      } else if (applyMode === "derived") {
        setApplyMessage(
          `已基于${selectedCandidate?.label || "当前 payload"}生成衍生视图，可继续对照原文后再决定是否覆盖。`,
        );
      } else {
        setApplyMessage("当前为仅预览模式，结果不会覆盖原始 payload。");
      }
    } catch (error) {
      if (activeDecodeAbortRef.current === controller) {
        setDecodeError(isAbortError(error) ? "解码已取消" : error instanceof Error ? error.message : "解码失败");
      }
    } finally {
      if (activeDecodeAbortRef.current === controller) {
        activeDecodeAbortRef.current = null;
        setRunningDecoder(null);
        if (!hasBatchMode) {
          setBatchProgress(null);
        }
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
          {runningDecoder && (
            <button
              type="button"
              onClick={cancelDecode}
              className="inline-flex items-center gap-2 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-xs font-semibold text-rose-700 shadow-sm transition-colors hover:bg-rose-100"
            >
              取消
            </button>
          )}
        </div>
      </div>

      <div className="mt-4 rounded-lg border border-border bg-background/80 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-sm font-semibold text-foreground">候选提取与指纹识别</div>
            <div className="text-xs text-muted-foreground">
              自动从当前 payload 中提取 HTTP body / 表单参数 / Base64 / Hex 候选，并给出 webshell 家族提示。
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {inspection?.suggestedFamily && (
              <span className="rounded-md border border-cyan-200 bg-cyan-50 px-2 py-1 text-[11px] font-semibold text-cyan-700">
                家族：{inspection.suggestedFamily}
              </span>
            )}
            {inspection?.suggestedDecoder && (
              <button
                type="button"
                className="rounded-md border border-blue-200 bg-blue-50 px-2 py-1 text-[11px] font-semibold text-blue-700 hover:bg-blue-100"
                onClick={() => {
                  const decoder = asKnownDecoder(inspection.suggestedDecoder);
                  if (decoder) {
                    void runDecoder(decoder);
                  }
                }}
              >
                推荐解码：{inspection.suggestedDecoder}
              </button>
            )}
            {typeof inspection?.confidence === "number" && inspection.confidence > 0 && (
              <span className="rounded-md border border-emerald-200 bg-emerald-50 px-2 py-1 text-[11px] font-semibold text-emerald-700">
                置信度 {inspection.confidence}%
              </span>
            )}
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-muted-foreground">覆盖策略</span>
          <ApplyModeButton label="仅预览" active={applyMode === "preview"} onClick={() => setApplyMode("preview")} />
          <ApplyModeButton label="衍生视图" active={applyMode === "derived"} onClick={() => setApplyMode("derived")} />
          {canOverwrite ? (
            <ApplyModeButton
              label="覆盖原文"
              active={applyMode === "overwrite"}
              onClick={() => setApplyMode("overwrite")}
            />
          ) : (
            <span className="rounded-md border border-amber-200 bg-amber-50 px-2.5 py-1 text-[11px] font-semibold text-amber-700">
              MISC 分析模式，不写回抓包
            </span>
          )}
          {selectedCandidate && (
            <span className="rounded-md border border-border bg-card px-2 py-1 text-[11px] text-muted-foreground">
              当前候选：{selectedCandidate.label}
            </span>
          )}
        </div>

        {inspectionLoading && (
          <div className="mt-3 rounded-md border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
            正在识别候选 payload...
          </div>
        )}
        {inspectionError && (
          <div className="mt-3 rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-700">
            {inspectionError}
          </div>
        )}
        {!inspectionLoading && !inspectionError && (
          <div className="mt-3 space-y-3">
            {inspection?.reasons && inspection.reasons.length > 0 && (
              <div className="rounded-md border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
                <div className="mb-1 font-semibold text-foreground">识别依据</div>
                <div className="flex flex-wrap gap-2">
                  {inspection.reasons.map((reason) => (
                    <span key={reason} className="rounded-md border border-border bg-background px-2 py-1">
                      {reason}
                    </span>
                  ))}
                </div>
              </div>
            )}
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {candidateCount > 0 ? (
                inspection!.candidates.map((candidate) => (
                  <div
                    key={candidate.id}
                    onClick={() => setSelectedCandidateId(candidate.id)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        setSelectedCandidateId(candidate.id);
                      }
                    }}
                    role="button"
                    tabIndex={0}
                    className={`rounded-lg border px-3 py-3 text-left transition-colors ${
                      selectedCandidate?.id === candidate.id
                        ? "border-blue-400 bg-blue-50 shadow-sm"
                        : "border-border bg-card hover:border-blue-200 hover:bg-accent/50"
                    }`}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded-md border border-blue-200 bg-blue-50 px-2 py-1 text-[11px] font-semibold text-blue-700">
                        {candidate.kind}
                      </span>
                      {typeof candidate.confidence === "number" && candidate.confidence > 0 && (
                        <span className="rounded-md border border-emerald-200 bg-emerald-50 px-2 py-1 text-[11px] font-semibold text-emerald-700">
                          {candidate.confidence}%
                        </span>
                      )}
                      {candidate.paramName && (
                        <span className="rounded-md border border-border bg-background px-2 py-1 font-mono text-[11px] text-muted-foreground">
                          {candidate.paramName}
                        </span>
                      )}
                      {candidate.familyHint && (
                        <span className="rounded-md border border-cyan-200 bg-cyan-50 px-2 py-1 text-[11px] font-semibold text-cyan-700">
                          {candidate.familyHint}
                        </span>
                      )}
                      {candidate.sourceRole && (
                        <span className="rounded-md border border-emerald-200 bg-emerald-50 px-2 py-1 text-[11px] font-semibold text-emerald-700">
                          {candidate.sourceRole}
                        </span>
                      )}
                      {candidateHintBadges(candidate).map((badge) => (
                        <span
                          key={`${candidate.id}-${badge}`}
                          className="rounded-md border border-amber-200 bg-amber-50 px-2 py-1 font-mono text-[11px] font-semibold text-amber-700"
                        >
                          {badge}
                        </span>
                      ))}
                    </div>
                    <div className="mt-2 text-xs font-semibold text-foreground">{candidate.label}</div>
                    <div className="mt-1 line-clamp-3 break-all font-mono text-[11px] text-muted-foreground">
                      {candidate.preview || candidate.value || "(empty)"}
                    </div>
                    {(candidate.decoderHints?.length ?? 0) > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {candidate.decoderHints!.map((hint) => (
                          <button
                            key={`${candidate.id}-${hint}`}
                            type="button"
                            onClick={(event) => {
                              event.stopPropagation();
                              const decoder = asKnownDecoder(hint);
                              if (decoder) {
                                void runDecoder(decoder);
                              }
                            }}
                            className="rounded border border-blue-200 bg-blue-50 px-2 py-0.5 text-[11px] text-blue-700 hover:bg-blue-100"
                          >
                            {hint}
                          </button>
                        ))}
                      </div>
                    )}
                    {(candidate.fingerprints?.length ?? 0) > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {candidate.fingerprints!.map((fingerprint) => (
                          <span
                            key={`${candidate.id}-${fingerprint}`}
                            className="rounded border border-amber-200 bg-amber-50 px-2 py-0.5 text-[11px] text-amber-700"
                          >
                            {fingerprint}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="rounded-lg border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground md:col-span-2 xl:col-span-3">
                  当前片段未提取到明显候选，仍可直接对原始 payload 使用手动解码器。
                </div>
              )}
            </div>
          </div>
        )}
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
            <LabeledInput label="起始序号" value={rangeStart} onChange={setRangeStart} placeholder="1" />
            <LabeledInput label="结束序号" value={rangeEnd} onChange={setRangeEnd} placeholder={String(batchCount)} />
            <div className="rounded-md border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
              将按当前列表顺序处理第 {clampBatchOrdinal(rangeStart, batchCount)} 到{" "}
              {clampBatchOrdinal(rangeEnd, batchCount)} 条。
              {batchItems && batchItems.length > 0 && (
                <div
                  className="mt-1 truncate text-foreground"
                  title={
                    batchItems[Math.min(batchCount - 1, Math.max(0, clampBatchOrdinal(rangeStart, batchCount) - 1))]
                      ?.label
                  }
                >
                  起点:{" "}
                  {batchItems[Math.min(batchCount - 1, Math.max(0, clampBatchOrdinal(rangeStart, batchCount) - 1))]
                    ?.label ?? "--"}
                </div>
              )}
            </div>
          </div>

          {batchProgress && (
            <div className="mt-3 rounded-md border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span>
                  进度：{batchProgress.done}/{batchProgress.total}
                </span>
                <span>
                  成功：{batchProgress.success} · 失败：{batchProgress.failed}
                </span>
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
            <div className="mt-3 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-700">
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
        <StreamDecoderSettingsPanel
          activeSettings={activeSettings}
          settings={settings}
          setSettings={setSettings}
          onClose={() => setActiveSettings(null)}
        />
      )}

      <div className="mt-4 grid min-w-0 gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <PayloadPane
          title={
            selectedCandidate
              ? `候选 payload / ${selectedCandidate.label}`
              : preparedPayload === payload
                ? "原始 payload"
                : "原始 payload（已自动提取）"
          }
          content={effectivePayload || "(empty payload)"}
          footer={
            selectedCandidate
              ? `原文长度 ${payload.length}，当前候选来源 ${selectedCandidate.kind}${selectedCandidate.paramName ? ` / ${selectedCandidate.paramName}` : ""}`
              : preparedPayload !== payload
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
          confidence={result?.confidence}
          warnings={result?.warnings}
          signals={result?.signals}
          attemptErrors={result?.attemptErrors}
          footer={applyMessage || undefined}
        />
      </div>
    </div>
  );
}
