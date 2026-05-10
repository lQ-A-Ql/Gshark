import { type ReactNode } from "react";
import { useNavigate } from "react-router";
import { StreamPayloadDialog } from "../components/stream/StreamWorkbench";
import { estimateTextBytes, MAX_HTTP_PREVIEW_CHARS, renderHTTPChunk, type HTTPViewMode } from "./HttpStreamUtils";
import type { HTTPChunk } from "./HttpStreamChunks";

interface HttpStreamDialogProps {
  chunk: HTTPChunk;
  streamId: number;
  viewMode: HTTPViewMode;
  search: string;
  onClose: () => void;
}

export function HttpStreamDialog({ chunk, streamId, viewMode, search, onClose }: HttpStreamDialogProps) {
  const navigate = useNavigate();
  return (
    <StreamPayloadDialog
      title={`HTTP Payload 详情 #${chunk.packetId}`}
      subtitle={`${chunk.direction === "client" ? "请求" : "响应"} · stream-index ${chunk.streamIndex} · ${estimateTextBytes(chunk.body)} bytes`}
      meta={buildDialogMeta(chunk, streamId, viewMode)}
      extraActions={<OpenMiscButton onClick={() => navigate("/misc")} />}
      content={renderHTTPChunk(chunk.body, viewMode, true)}
      highlight={search}
      filename={`http-stream-${streamId}-packet-${chunk.packetId}.txt`}
      onClose={onClose}
    />
  );
}

function buildDialogMeta(
  chunk: HTTPChunk,
  streamId: number,
  viewMode: HTTPViewMode,
): Array<{ label: string; value: ReactNode }> {
  return [
    { label: "协议", value: "HTTP" },
    { label: "Stream", value: streamId },
    { label: "Packet", value: `#${chunk.packetId}` },
    { label: "方向", value: chunk.direction === "client" ? "请求" : "响应" },
    { label: "Stream Index", value: chunk.streamIndex },
    { label: "视图", value: viewMode },
    { label: "原始字节", value: `${estimateTextBytes(chunk.body)} bytes` },
    { label: "预览阈值", value: `${MAX_HTTP_PREVIEW_CHARS} chars` },
  ];
}

function OpenMiscButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-1 rounded-md border border-cyan-200 bg-cyan-50 px-2.5 py-1.5 text-xs font-medium text-cyan-700 shadow-sm transition-colors hover:bg-cyan-100"
    >
      打开 MISC 解码工作台
    </button>
  );
}
