import { useEffect, useMemo, useRef, useState } from "react";
import type { StreamDecodeResult, StreamDecoderKind } from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import type { DecoderSettingsKind } from "./StreamDecoderSettingsPanel";
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
import { useStreamPayloadInspection } from "./useStreamPayloadInspection";

export type StreamDecoderWorkbenchProps = {
  payload: string;
  inspectRevision?: number | string;
  chunkLabel: string;
  tone?: "blue" | "amber" | "emerald";
  onApplyDecoded?: (payload: string) => void | Promise<void>;
  batchItems?: BatchItem[];
  selectedBatchIndex?: number;
  onApplyDecodedBatch?: (patches: Array<{ index: number; body: string }>) => void | Promise<void>;
  sourceHint?: DecoderHintSource;
};

export function useStreamDecoderWorkbench({
  payload,
  inspectRevision,
  chunkLabel,
  onApplyDecoded,
  batchItems,
  selectedBatchIndex,
  onApplyDecodedBatch,
  sourceHint,
}: StreamDecoderWorkbenchProps) {
  const [settings, setSettings] = useState<DecoderSettings>(() => readDecoderSettings());
  const [activeSettings, setActiveSettings] = useState<DecoderSettingsKind | null>(null);
  const [result, setResult] = useState<StreamDecodeResult | null>(null);
  const [decodeError, setDecodeError] = useState("");
  const [runningDecoder, setRunningDecoder] = useState<StreamDecoderKind | null>(null);
  const [applyMessage, setApplyMessage] = useState("");
  const [batchProgress, setBatchProgress] = useState<BatchDecodeProgress | null>(null);
  const [batchFailureDetails, setBatchFailureDetails] = useState<string[]>([]);
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
  const {
    inspection,
    inspectionError,
    inspectionLoading,
    selectedCandidate,
    setSelectedCandidateId,
  } = useStreamPayloadInspection({ payload, preparedPayload, inspectRevision });
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

  return {
    activeSettings,
    applyMessage,
    applyMode,
    batchCount,
    batchFailureDetails,
    batchProgress,
    canOverwrite,
    cancelDecode,
    decodeError,
    effectivePayload,
    hasBatchMode,
    hasPayload,
    inspection,
    inspectionError,
    inspectionLoading,
    preparedPayload,
    rangeEnd,
    rangeStart,
    result,
    runDecoder,
    runningDecoder,
    selectedBatchOrdinal,
    selectedCandidate,
    setActiveSettings,
    setApplyMode,
    setRangeEnd,
    setRangeStart,
    setSelectedCandidateId,
    setSettings,
    settings,
  };
}
