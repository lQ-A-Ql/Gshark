import type { Ref } from "react";
import { Panel, PanelGroup, PanelResizeHandle } from "react-resizable-panels";
import { PacketVirtualTable } from "../PacketVirtualTable";
import { Progress } from "../ui/progress";
import type { Packet, ProtocolTreeNode } from "../../core/types";
import { HexAsciiPanel } from "./HexAsciiPanel";
import { ProtocolTreePanel } from "./ProtocolTreePanel";

type StreamTarget = "http" | "tcp" | "udp";

interface WorkspacePreloadProgressProps {
  preloadProcessed: number;
  preloadTotal: number;
  totalPackets: number;
  preloadPercent: number;
  hasDeterministicPreloadProgress: boolean;
}

export function WorkspacePreloadProgress({
  preloadProcessed,
  preloadTotal,
  totalPackets,
  preloadPercent,
  hasDeterministicPreloadProgress,
}: WorkspacePreloadProgressProps) {
  return (
    <div className="border-b border-blue-100 bg-white/78 px-3 py-2 backdrop-blur-xl">
      <div className="mb-1 flex items-center justify-between text-[11px] text-muted-foreground">
        <span>正在预加载全部流量</span>
        <span>
          {hasDeterministicPreloadProgress
            ? `${preloadProcessed.toLocaleString()} / ${Math.max(preloadTotal, totalPackets).toLocaleString()} (${preloadPercent}%)`
            : `已入库 ${Math.max(preloadProcessed, totalPackets).toLocaleString()} 包，正在继续解析...`}
        </span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded bg-muted">
        {hasDeterministicPreloadProgress ? (
          <div className="h-full bg-blue-600 transition-all" style={{ width: `${preloadPercent}%` }} />
        ) : (
          <div className="h-full w-1/3 animate-pulse rounded bg-blue-600/80" />
        )}
      </div>
    </div>
  );
}

interface WorkspacePanelsProps {
  showFilterLoadingBlankState: boolean;
  filterLoadingTitle: string;
  filterLoadingDetail: string;
  filterLoadingProgress: number;
  packets: Packet[];
  selectedPacketId: number | null;
  hasMorePackets: boolean;
  protocolTree: ProtocolTreeNode[];
  selectedTreeNode: string;
  selectedPacket: Packet | null;
  frameBytes: number[];
  selectedByteRange: [number, number] | null;
  selectedByteOffset: number | null;
  hexPanelRef: Ref<HTMLDivElement>;
  onSelectPacket: (id: number) => void;
  onDoubleClickHttp: () => void;
  onFollowStream: (packet: Packet, target: StreamTarget) => void;
  onLoadMorePackets: () => void;
  onSelectTreeNode: (nodeId: string) => void;
  onSelectByte: (offset: number) => void;
  registerNodeRef: (id: string, el: HTMLDivElement | null) => void;
}

export function WorkspacePanels({
  showFilterLoadingBlankState,
  filterLoadingTitle,
  filterLoadingDetail,
  filterLoadingProgress,
  packets,
  selectedPacketId,
  hasMorePackets,
  protocolTree,
  selectedTreeNode,
  selectedPacket,
  frameBytes,
  selectedByteRange,
  selectedByteOffset,
  hexPanelRef,
  onSelectPacket,
  onDoubleClickHttp,
  onFollowStream,
  onLoadMorePackets,
  onSelectTreeNode,
  onSelectByte,
  registerNodeRef,
}: WorkspacePanelsProps) {
  return (
    <PanelGroup direction="vertical" className="flex min-h-0 flex-1 flex-col">
      <Panel defaultSize={50} minSize={20} className="bg-white/82 backdrop-blur-xl">
        {showFilterLoadingBlankState ? (
          <WorkspaceFilterLoadingPanel
            title={filterLoadingTitle}
            detail={filterLoadingDetail}
            progress={filterLoadingProgress}
          />
        ) : (
          <PacketVirtualTable
            packets={packets}
            selectedPacketId={selectedPacketId}
            onSelect={onSelectPacket}
            onDoubleClickHttp={onDoubleClickHttp}
            onFollowStream={onFollowStream}
            hasMorePackets={hasMorePackets}
            onLoadMorePackets={onLoadMorePackets}
          />
        )}
      </Panel>

      <PanelResizeHandle className="z-20 h-1 cursor-row-resize bg-border transition-colors hover:bg-blue-300 active:bg-blue-500" />

      <Panel defaultSize={50} className="flex">
        <PanelGroup direction="horizontal">
          <ProtocolTreePanel
            nodes={protocolTree}
            selectedId={selectedTreeNode}
            onSelect={onSelectTreeNode}
            registerNodeRef={registerNodeRef}
          />

          <PanelResizeHandle className="z-20 w-1 cursor-col-resize bg-border transition-colors hover:bg-blue-300 active:bg-blue-500" />

          <HexAsciiPanel
            packet={selectedPacket}
            frameBytes={frameBytes}
            selectedByteRange={selectedByteRange}
            selectedByteOffset={selectedByteOffset}
            panelRef={hexPanelRef}
            onSelectByte={onSelectByte}
          />
        </PanelGroup>
      </Panel>
    </PanelGroup>
  );
}

function WorkspaceFilterLoadingPanel({
  title,
  detail,
  progress,
}: {
  title: string;
  detail: string;
  progress: number;
}) {
  return (
    <div className="flex h-full min-h-0 items-center justify-center bg-white/70 px-6">
      <div className="w-full max-w-xl rounded-[24px] border border-white/80 bg-white/88 p-6 shadow-[0_22px_55px_rgba(148,163,184,0.16)] backdrop-blur-xl">
        <div className="mb-3 text-sm font-semibold text-foreground">{title}</div>
        <div className="mb-4 text-xs text-muted-foreground">{detail}</div>
        <Progress value={progress} className="h-2.5" />
        <div className="mt-3 flex items-center justify-between text-[11px] text-muted-foreground">
          <span>正在读取首屏匹配结果</span>
          <span>{progress}%</span>
        </div>
      </div>
    </div>
  );
}
