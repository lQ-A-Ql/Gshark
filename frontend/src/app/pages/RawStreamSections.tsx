import { ArrowLeftRight } from "lucide-react";
import { WorkbenchChip, WorkbenchTitleBar } from "../components/stream/StreamWorkbench";
import type { StreamLoadMeta } from "../core/types";
import { formatRawStreamLoadMeta } from "./RawStreamUtils";
export { RawStreamControlBar } from "./RawStreamControlBar";
export { RawStreamDialog } from "./RawStreamDialog";
export {
  RawStreamPayloadGrid,
  RawStreamSelectedPanel,
  TCP_RAW_STREAM_TONE,
  UDP_RAW_STREAM_TONE,
  type RawStreamTone,
} from "./RawStreamPayloadPanels";

interface RawStreamTitleBarProps {
  chunkCount: number;
  from: string;
  loadMeta?: StreamLoadMeta;
  protocol: "TCP" | "UDP";
  streamId: number;
  to: string;
  totalChunks: number;
  onBack: () => void;
}

export function RawStreamTitleBar({
  chunkCount,
  from,
  loadMeta,
  protocol,
  streamId,
  to,
  totalChunks,
  onBack,
}: RawStreamTitleBarProps) {
  return (
    <WorkbenchTitleBar
      onBack={onBack}
      title={`${protocol} 流追踪 (stream eq ${streamId})`}
      subtitle={
        <span className="flex min-w-0 items-center gap-1 font-mono">
          <span className="truncate">{from}</span>
          <ArrowLeftRight className="h-3 w-3 shrink-0" />
          <span className="truncate">{to}</span>
        </span>
      }
      meta={
        <>
          <WorkbenchChip>
            已载入 {chunkCount}/{totalChunks || chunkCount}
          </WorkbenchChip>
          <WorkbenchChip className="max-w-[520px] truncate">
            {formatRawStreamLoadMeta(protocol, loadMeta)}
          </WorkbenchChip>
        </>
      }
    />
  );
}
