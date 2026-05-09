import { useEffect, useMemo, useRef, useState } from "react";
import type { StreamDecodeResult, StreamDecoderKind, StreamPayloadInspection } from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import { StreamDecoderBatchPanel } from "./StreamDecoderBatchPanel";
import { StreamDecoderCandidatePanel } from "./StreamDecoderCandidatePanel";
import { StreamDecoderPayloadGrid } from "./StreamDecoderPayloadGrid";
import { StreamDecoderWorkbenchHeader } from "./StreamDecoderWorkbenchHeader";
import { StreamDecoderSettingsPanel, type DecoderSettingsKind } from "./StreamDecoderSettingsPanel";
import {
  buildDecoderOptions,
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
      <StreamDecoderWorkbenchHeader
        chunkLabel={chunkLabel}
        runningDecoder={runningDecoder}
        disabled={!hasPayload && !hasBatchMode}
        onRunDecoder={(decoder) => void runDecoder(decoder)}
        onOpenSettings={setActiveSettings}
        onCancel={cancelDecode}
      />

      <StreamDecoderCandidatePanel
        inspection={inspection}
        inspectionLoading={inspectionLoading}
        inspectionError={inspectionError}
        selectedCandidate={selectedCandidate}
        applyMode={applyMode}
        canOverwrite={canOverwrite}
        onApplyModeChange={setApplyMode}
        onSelectCandidate={setSelectedCandidateId}
        onRunDecoder={(decoder) => void runDecoder(decoder)}
      />

      {hasBatchMode && (
        <StreamDecoderBatchPanel
          batchItems={batchItems}
          batchCount={batchCount}
          selectedBatchOrdinal={selectedBatchOrdinal}
          rangeStart={rangeStart}
          rangeEnd={rangeEnd}
          batchProgress={batchProgress}
          batchFailureDetails={batchFailureDetails}
          onRangeStartChange={setRangeStart}
          onRangeEndChange={setRangeEnd}
        />
      )}

      {activeSettings && (
        <StreamDecoderSettingsPanel
          activeSettings={activeSettings}
          settings={settings}
          setSettings={setSettings}
          onClose={() => setActiveSettings(null)}
        />
      )}

      <StreamDecoderPayloadGrid
        rawPayload={payload}
        preparedPayload={preparedPayload}
        effectivePayload={effectivePayload}
        selectedCandidate={selectedCandidate}
        result={result}
        decodeError={decodeError}
        runningDecoder={runningDecoder}
        applyMessage={applyMessage}
      />
    </div>
  );
}
