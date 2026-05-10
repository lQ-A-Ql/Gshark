import { useEffect, useMemo, useRef, useState } from "react";
import { Network } from "lucide-react";
import { useNavigate } from "react-router";
import { CaptureWelcomePanel } from "../components/CaptureWelcomePanel";
import { WorkbenchTitleBar } from "../components/DesignSystem";
import { DisplayFilterBar } from "../components/workspace/DisplayFilterBar";
import { WorkspacePanels, WorkspacePreloadProgress } from "../components/workspace/WorkspacePanels";
import { CaptureFileControls, PacketLocatorControls, PacketPagingControls } from "../components/workspace/WorkspaceTopControls";
import { useWorkspaceFilterHistory } from "../components/workspace/useWorkspaceFilterHistory";
import { buildFrameBytes, findClosestNodeByOffset } from "../components/workspace/workspaceSelection";
import { useSentinel } from "../state/SentinelContext";
import type { Packet, ProtocolTreeNode } from "../core/types";

export default function Workspace() {
  const {
    displayFilter,
    setDisplayFilter,
    applyFilter,
    clearFilter,
    filteredPackets,
    totalPackets,
    currentPage,
    totalPages,
    isPreloadingCapture,
    preloadProcessed,
    preloadTotal,
    hasMorePackets,
    hasPrevPackets,
    isPageLoading,
    isFilterLoading,
    packetPageError,
    loadMorePackets,
    loadPrevPackets,
    jumpToPage,
    retryPacketPage,
    locatePacketById,
    selectedPacket,
    selectedPacketRawHex,
    selectedPacketId,
    selectPacket,
    protocolTree,
    fileMeta,
    openCapture,
    stopCapture,
    setActiveStream,
    backendConnected,
    backendStatus,
    tsharkStatus,
  } = useSentinel();

  const [selectedTreeNode, setSelectedTreeNode] = useState<string>("frame");
  const [selectedByteOffset, setSelectedByteOffset] = useState<number | null>(null);
  const [capturePath, setCapturePath] = useState(fileMeta.name);
  const [pageInput, setPageInput] = useState("1");
  const [packetIdInput, setPacketIdInput] = useState("");
  const [filterLoadingProgress, setFilterLoadingProgress] = useState(18);
  const filterInputRef = useRef<HTMLInputElement | null>(null);
  const treeRefs = useRef<Map<string, HTMLDivElement>>(new Map());
  const hexPanelRef = useRef<HTMLDivElement | null>(null);
  const navigate = useNavigate();
  const { filterSuggestions, rememberFilter, clearFilterHistory } = useWorkspaceFilterHistory();

  const applyFilterWithHistory = (value?: string) => {
    const next = (value ?? displayFilter).trim();
    if (next) {
      if (next !== displayFilter) {
        setDisplayFilter(next);
      }
      rememberFilter(next);
      applyFilter(next);
      return;
    }
    applyFilter("");
  };

  useEffect(() => {
    setCapturePath(fileMeta.name);
  }, [fileMeta.name]);

  useEffect(() => {
    setPageInput(String(currentPage));
  }, [currentPage]);

  useEffect(() => {
    const handler = () => {
      filterInputRef.current?.focus();
      filterInputRef.current?.select();
    };

    window.addEventListener("gshark:focus-filter", handler);
    return () => window.removeEventListener("gshark:focus-filter", handler);
  }, []);

  useEffect(() => {
    setSelectedTreeNode("frame");
    setSelectedByteOffset(null);
  }, [selectedPacket?.id]);

  useEffect(() => {
    const node = treeRefs.current.get(selectedTreeNode);
    if (node) {
      node.scrollIntoView({ block: "nearest" });
    }
  }, [selectedTreeNode]);

  useEffect(() => {
    if (selectedByteOffset == null || !hexPanelRef.current) return;
    const el = hexPanelRef.current.querySelector<HTMLButtonElement>(`button[data-byte='${selectedByteOffset}']`);
    if (el) {
      el.scrollIntoView({ block: "nearest", inline: "nearest" });
    }
  }, [selectedByteOffset]);

  useEffect(() => {
    if (!isFilterLoading || isPreloadingCapture) {
      setFilterLoadingProgress(12);
      return;
    }
    setFilterLoadingProgress(18);
    const timer = window.setInterval(() => {
      setFilterLoadingProgress((prev) => {
        if (prev >= 92) return 92;
        const step = Math.max(1, Math.round((96 - prev) * 0.18));
        return Math.min(92, prev + step);
      });
    }, 180);
    return () => window.clearInterval(timer);
  }, [isFilterLoading, isPreloadingCapture]);

  const treeRangeMap = useMemo(() => {
    const map = new Map<string, [number, number]>();
    const walk = (node: ProtocolTreeNode) => {
      if (node.byteRange) {
        map.set(node.id, node.byteRange);
      }
      node.children?.forEach(walk);
    };
    protocolTree.forEach(walk);
    return map;
  }, [protocolTree]);

  const selectedByteRange = treeRangeMap.get(selectedTreeNode) ?? null;
  const frameBytes = useMemo(() => buildFrameBytes(selectedPacket, selectedPacketRawHex), [selectedPacket, selectedPacketRawHex]);
  const preloadPercent = useMemo(() => {
    if (preloadTotal <= 0) return 0;
    return Math.max(0, Math.min(100, Math.floor((preloadProcessed / preloadTotal) * 100)));
  }, [preloadProcessed, preloadTotal]);
  const hasDeterministicPreloadProgress = preloadTotal > 0;
  const hasOpenedCapture = Boolean(fileMeta.path);
  const showFilterLoadingBlankState = useMemo(
    () => isFilterLoading && !isPreloadingCapture && filteredPackets.length === 0,
    [filteredPackets.length, isFilterLoading, isPreloadingCapture],
  );
  const filterLoadingTitle = useMemo(() => {
    const message = backendStatus.trim();
    if (message.startsWith("正在应用过滤器")) return message;
    if (message.startsWith("正在重置过滤器")) return message;
    return displayFilter.trim() ? `正在扫描过滤结果: ${displayFilter.trim()}` : "正在恢复全部流量";
  }, [backendStatus, displayFilter]);
  const filterLoadingDetail = useMemo(() => (
    displayFilter.trim()
      ? "旧页已清空，首屏命中结果返回前会在这里显示实时进度。"
      : "正在重新装载未过滤的数据包第一页。"
  ), [displayFilter]);
  const filterErrorMessage = useMemo(() => {
    const message = backendStatus.trim();
    if (!message || !displayFilter.trim()) return "";
    const normalized = message.toLowerCase();
    if (
      normalized.includes("filter")
      || normalized.includes("过滤")
      || normalized.includes("tshark")
      || normalized.includes("unexpected")
      || normalized.includes("invalid")
    ) {
      return message;
    }
    return "";
  }, [backendStatus, displayFilter]);
  const pagerItems = useMemo(() => {
    const pages = new Set<number>([1, totalPages, currentPage - 1, currentPage, currentPage + 1]);
    return Array.from(pages)
      .filter((p) => p >= 1 && p <= totalPages)
      .sort((a, b) => a - b);
  }, [currentPage, totalPages]);

  const handleSelectTreeNode = (nodeId: string) => {
    setSelectedTreeNode(nodeId);
    const range = treeRangeMap.get(nodeId);
    if (range) {
      setSelectedByteOffset(range[0]);
    }
  };

  const handleSelectByte = (offset: number) => {
    setSelectedByteOffset(offset);
    const matched = findClosestNodeByOffset(offset, protocolTree);
    if (matched) {
      setSelectedTreeNode(matched);
    }
  };

  const handleFollowStream = (packet: Packet, target: "http" | "tcp" | "udp") => {
    if (packet.streamId == null) return;
    selectPacket(packet.id);

    if (target === "http") {
      void setActiveStream("HTTP", packet.streamId);
      navigate("/http-stream", { state: { streamId: packet.streamId } });
      return;
    }
    if (target === "udp") {
      void setActiveStream("UDP", packet.streamId);
      navigate("/udp-stream", { state: { streamId: packet.streamId } });
      return;
    }
    void setActiveStream("TCP", packet.streamId);
    navigate("/tcp-stream", { state: { streamId: packet.streamId } });
  };

  const captureActionsDisabled = !backendConnected || !tsharkStatus.available;

  if (!hasOpenedCapture) {
    return <CaptureWelcomePanel />;
  }

  return (
    <div className="flex h-full flex-col overflow-hidden bg-[radial-gradient(circle_at_top,rgba(147,197,253,0.22),transparent_36%),linear-gradient(180deg,#f7fbff_0%,#f8fafc_100%)] text-sm text-foreground">
      <WorkbenchTitleBar
        title="流量工作区"
        subtitle={fileMeta.path ? `${fileMeta.name} · ${totalPackets.toLocaleString()} packets` : "打开 PCAP/PCAPNG 后开始分析"}
        icon={<Network className="h-4 w-4 text-blue-600" />}
        className="border-blue-100 bg-white/90 shadow-[0_18px_48px_rgba(148,163,184,0.16)] backdrop-blur-xl"
        actions={(
          <>
            <CaptureFileControls
              capturePath={capturePath}
              onCapturePathChange={setCapturePath}
              onChooseFile={() => void openCapture()}
              onOpenPath={() => void openCapture(capturePath)}
              onStop={() => void stopCapture()}
              disabled={captureActionsDisabled}
              backendConnected={backendConnected}
            />
            <PacketPagingControls
              hasPrevPackets={hasPrevPackets}
              hasMorePackets={hasMorePackets}
              isPreloadingCapture={isPreloadingCapture}
              isPageLoading={isPageLoading}
              totalPackets={totalPackets}
              currentPage={currentPage}
              totalPages={totalPages}
              pageInput={pageInput}
              pagerItems={pagerItems}
              onPageInputChange={setPageInput}
              onLoadPrev={() => void loadPrevPackets()}
              onLoadMore={() => void loadMorePackets()}
              onJumpToPage={(page) => void jumpToPage(page)}
            />
            <PacketLocatorControls
              packetIdInput={packetIdInput}
              onPacketIdInputChange={setPacketIdInput}
              onLocatePacket={(packetId) => void locatePacketById(packetId)}
              disabled={isPreloadingCapture || isPageLoading}
            />
          </>
        )}
      />
      <div className="border-b border-blue-100 bg-white/80 shadow-[0_12px_32px_rgba(148,163,184,0.12)] backdrop-blur-xl">
        <DisplayFilterBar
          value={displayFilter}
          suggestions={filterSuggestions}
          inputRef={filterInputRef}
          disabled={isPreloadingCapture || isPageLoading}
          onChange={setDisplayFilter}
          onApply={() => applyFilterWithHistory()}
          onClear={clearFilter}
          onClearHistory={clearFilterHistory}
        />
        <div className="px-3 pb-2 text-[11px] text-slate-500">
          {'过滤器已切换为 tshark display filter 原生语法，支持 "http.request"、"tcp.stream eq 3"、"frame.number >= 100"、"ip.addr == 192.168.1.10" 等表达式。'}
        </div>
      </div>
      {filterErrorMessage && (
        <div className="border-b border-rose-200 bg-rose-500/10 px-3 py-2 text-[11px] text-rose-700 shrink-0">
          {filterErrorMessage}
        </div>
      )}

      {isPreloadingCapture && (
        <WorkspacePreloadProgress
          preloadProcessed={preloadProcessed}
          preloadTotal={preloadTotal}
          totalPackets={totalPackets}
          preloadPercent={preloadPercent}
          hasDeterministicPreloadProgress={hasDeterministicPreloadProgress}
        />
      )}

      <WorkspacePanels
        showFilterLoadingBlankState={showFilterLoadingBlankState}
        filterLoadingTitle={filterLoadingTitle}
        filterLoadingDetail={filterLoadingDetail}
        filterLoadingProgress={filterLoadingProgress}
        packetPageError={packetPageError}
        captureName={fileMeta.name}
        displayFilter={displayFilter}
        packets={filteredPackets}
        selectedPacketId={selectedPacketId}
        hasMorePackets={hasMorePackets}
        protocolTree={protocolTree}
        selectedTreeNode={selectedTreeNode}
        selectedPacket={selectedPacket}
        frameBytes={frameBytes}
        selectedByteRange={selectedByteRange}
        selectedByteOffset={selectedByteOffset}
        hexPanelRef={hexPanelRef}
        onSelectPacket={selectPacket}
        onDoubleClickHttp={() => navigate("/http-stream")}
        onFollowStream={handleFollowStream}
        onRetryPacketPage={() => void retryPacketPage()}
        onLoadMorePackets={() => void loadMorePackets()}
        onSelectTreeNode={handleSelectTreeNode}
        onSelectByte={handleSelectByte}
        registerNodeRef={(id, el) => {
          if (el) {
            treeRefs.current.set(id, el);
          } else {
            treeRefs.current.delete(id);
          }
        }}
      />
    </div>
  );
}
