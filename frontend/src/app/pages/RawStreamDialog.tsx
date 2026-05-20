import { StreamPayloadDialog } from "../components/stream/StreamWorkbench";
import {
  buildRawStreamChunkChips,
  buildRawStreamDialogMeta,
  getRawDirectionLabel,
  renderRawStreamChunk,
  type RawViewMode,
  type VisibleRawChunk,
} from "./RawStreamUtils";

interface RawStreamDialogProps {
  chunk: VisibleRawChunk;
  protocol: "TCP" | "UDP";
  search: string;
  streamId: number;
  totalChunks: number;
  viewMode: RawViewMode;
  onClose: () => void;
  onOpenMisc: () => void;
}

export function RawStreamDialog({
  chunk,
  protocol,
  search,
  streamId,
  totalChunks,
  viewMode,
  onClose,
  onOpenMisc,
}: RawStreamDialogProps) {
  return (
    <StreamPayloadDialog
      title={`Payload 详情 #${chunk.packetId}`}
      subtitle={`${getRawDirectionLabel(chunk.direction)} · chunk #${chunk.streamIndex + 1} · ${buildRawStreamChunkChips(chunk)[1]}`}
      meta={buildRawStreamDialogMeta(protocol, streamId, chunk, totalChunks, viewMode)}
      extraActions={<OpenMiscButton onClick={onOpenMisc} />}
      content={renderRawStreamChunk(chunk.body, viewMode, true)}
      highlight={search}
      filename={`${protocol.toLowerCase()}-stream-${streamId}-packet-${chunk.packetId}.txt`}
      onClose={onClose}
    />
  );
}

function OpenMiscButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="gshark-control gshark-evidence-accent inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-cyan-700 transition-colors hover:text-cyan-800"
    >
      打开 MISC 解码工作台
    </button>
  );
}
