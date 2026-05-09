import type { StreamDecodeResult, StreamDecoderKind, StreamPayloadCandidate } from "../core/types";
import { PayloadPane } from "./StreamDecoderWorkbenchParts";

export function StreamDecoderPayloadGrid({
  rawPayload,
  preparedPayload,
  effectivePayload,
  selectedCandidate,
  result,
  decodeError,
  runningDecoder,
  applyMessage,
}: {
  rawPayload: string;
  preparedPayload: string;
  effectivePayload: string;
  selectedCandidate: StreamPayloadCandidate | null;
  result: StreamDecodeResult | null;
  decodeError: string;
  runningDecoder: StreamDecoderKind | null;
  applyMessage: string;
}) {
  return (
    <div className="mt-4 grid min-w-0 gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <PayloadPane
        title={
          selectedCandidate
            ? `候选 payload / ${selectedCandidate.label}`
            : preparedPayload === rawPayload
              ? "原始 payload"
              : "原始 payload（已自动提取）"
        }
        content={effectivePayload || "(empty payload)"}
        footer={
          selectedCandidate
            ? `原文长度 ${rawPayload.length}，当前候选来源 ${selectedCandidate.kind}${selectedCandidate.paramName ? ` / ${selectedCandidate.paramName}` : ""}`
            : preparedPayload !== rawPayload
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
  );
}
