import { useEffect, useMemo, useRef, useState } from "react";
import { Panel, PanelGroup, PanelResizeHandle } from "react-resizable-panels";
import { Filter, Play, RefreshCw, XCircle, Network, FileText, FolderOpen, Square } from "lucide-react";
import { useNavigate } from "react-router";
import { PacketVirtualTable } from "../components/PacketVirtualTable";
import { useSentinel } from "../state/SentinelContext";
import type { Packet, ProtocolTreeNode } from "../core/types";

const FILTER_HISTORY_KEY = "gshark.filter-history.v1";
const MAX_FILTER_HISTORY = 12;

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
    loadMorePackets,
    loadPrevPackets,
    jumpToPage,
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
    tsharkStatus,
  } = useSentinel();

  const [selectedTreeNode, setSelectedTreeNode] = useState<string>("frame");
  const [selectedByteOffset, setSelectedByteOffset] = useState<number | null>(null);
  const [capturePath, setCapturePath] = useState(fileMeta.name);
  const [pageInput, setPageInput] = useState("1");
  const [packetIdInput, setPacketIdInput] = useState("");
  const [recentFilters, setRecentFilters] = useState<string[]>([]);
  const filterInputRef = useRef<HTMLInputElement | null>(null);
  const treeRefs = useRef<Map<string, HTMLDivElement>>(new Map());
  const hexPanelRef = useRef<HTMLDivElement | null>(null);
  const navigate = useNavigate();

  const defaultFilterSuggestions = [
    "http",
    "tcp",
    "udp",
    "dns",
    "tls",
    "arp",
    "icmp",
    "ip",
    "ipv6",
    "tcp contains \"GET\"",
    "http.request",
    "http.response",
    "http.host contains \"bing\"",
    "http.request.uri contains \"login\"",
    "http.content_type contains \"json\"",
    "tcp.stream == 39",
    "udp.stream == 1",
    "tcp.flags.syn == 1 and tcp.flags.ack == 0",
    "frame.len > 1000",
    "frame.number >= 100 and frame.number <= 500",
    "ip.addr == 192.168.204.146",
    "ip.src == 192.168.1.10",
    "ip.dst == 10.0.0.5",
    "tcp.port == 80",
    "udp.port == 53",
    "http.request.method == POST",
    "http.response.code == 200",
    "http and http.request.method == POST",
  ];

  const filterSuggestions = useMemo(() => {
    const merged = [...recentFilters, ...defaultFilterSuggestions];
    return Array.from(new Set(merged.map((item) => item.trim()).filter(Boolean)));
  }, [recentFilters]);

  const persistRecentFilters = (items: string[]) => {
    setRecentFilters(items);
    if (typeof window === "undefined") return;
    try {
      window.localStorage.setItem(FILTER_HISTORY_KEY, JSON.stringify(items));
    } catch {
      // ignore persistence errors
    }
  };

  const rememberFilter = (rawValue: string) => {
    const value = rawValue.trim();
    if (!value) return;
    const next = [value, ...recentFilters.filter((item) => item !== value)].slice(0, MAX_FILTER_HISTORY);
    persistRecentFilters(next);
  };

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
    if (typeof window === "undefined") return;
    try {
      const raw = window.localStorage.getItem(FILTER_HISTORY_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return;
      const cleaned = parsed
        .map((item) => String(item ?? "").trim())
        .filter(Boolean)
        .slice(0, MAX_FILTER_HISTORY);
      setRecentFilters(cleaned);
    } catch {
      // ignore malformed history
    }
  }, []);

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

  return (
    <div className="flex h-full flex-col overflow-hidden bg-card text-sm text-foreground">
      <div className="flex items-center gap-2 border-b border-border bg-accent/40 px-3 py-2 shrink-0">
        <div className="flex w-[320px] items-center overflow-hidden rounded-md border border-border bg-background shadow-sm focus-within:border-blue-500">
          <FolderOpen className="ml-2 h-4 w-4 text-muted-foreground" />
          <input
            value={capturePath}
            onChange={(event) => setCapturePath(event.target.value)}
            name="capture-path-input"
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="none"
            spellCheck={false}
            className="w-full border-none bg-transparent px-2 py-1 text-xs font-mono text-foreground outline-none placeholder:text-muted-foreground"
            placeholder="输入 PCAP/PCAPNG 绝对路径"
          />
        </div>
        <button
          onClick={() => void openCapture()}
          disabled={captureActionsDisabled}
          className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1 text-xs text-foreground shadow-sm transition-all hover:bg-accent disabled:cursor-not-allowed disabled:opacity-60"
          title={backendConnected ? "选择并打开 PCAP/PCAPNG 文件" : "后端未连接"}
        >
          <FolderOpen className="h-3.5 w-3.5 text-blue-600" /> 选择文件
        </button>
        <button
          onClick={() => void openCapture(capturePath)}
          disabled={captureActionsDisabled}
          className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1 text-xs text-foreground shadow-sm transition-all hover:bg-accent disabled:cursor-not-allowed disabled:opacity-60"
          title={backendConnected ? "按路径打开（适用于本机路径）" : "后端未连接"}
        >
          <FolderOpen className="h-3.5 w-3.5 text-indigo-600" /> 路径打开
        </button>
        <button
          onClick={() => void stopCapture()}
          disabled={!backendConnected}
          className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1 text-xs text-foreground shadow-sm transition-all hover:bg-accent disabled:cursor-not-allowed disabled:opacity-60"
          title={backendConnected ? "停止当前解析任务" : "后端未连接"}
        >
          <Square className="h-3.5 w-3.5 text-rose-600" /> 停止
        </button>
        <button
          onClick={() => void loadPrevPackets()}
          disabled={!hasPrevPackets || isPreloadingCapture || isPageLoading}
          className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1 text-xs text-foreground shadow-sm transition-all hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
        >
          <RefreshCw className="h-3 w-3" /> {isPageLoading ? "翻页中" : "上一页"}
        </button>
        <button
          onClick={() => void loadMorePackets()}
          disabled={!hasMorePackets || isPreloadingCapture || isPageLoading}
          className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1 text-xs text-foreground shadow-sm transition-all hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
        >
          <RefreshCw className="h-3 w-3" /> {isPreloadingCapture ? `预加载中 ${totalPackets.toLocaleString()}` : isPageLoading ? "翻页中" : hasMorePackets ? "下一页" : "已到末页"}
        </button>
        <div className="flex items-center gap-1 rounded-md border border-border bg-background px-2 py-1 text-xs">
          <input
            value={pageInput}
            onChange={(event) => setPageInput(event.target.value.replace(/[^0-9]/g, ""))}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                const target = Number(pageInput || currentPage);
                void jumpToPage(target);
              }
            }}
            className="w-14 border-none bg-transparent text-center font-mono text-foreground outline-none"
            placeholder="页"
            disabled={isPreloadingCapture || isPageLoading}
          />
          <span className="text-muted-foreground">/ {totalPages.toLocaleString()}</span>
          <button
            onClick={() => void jumpToPage(Number(pageInput || currentPage))}
            disabled={isPreloadingCapture || isPageLoading}
            className="rounded border border-border px-1.5 py-0.5 text-[11px] hover:bg-accent disabled:opacity-50"
          >
            跳转
          </button>
        </div>
        <div className="flex items-center gap-1 rounded-md border border-border bg-background px-2 py-1 text-xs">
          <input
            value={packetIdInput}
            onChange={(event) => setPacketIdInput(event.target.value.replace(/[^0-9]/g, ""))}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                const packetId = Number(packetIdInput);
                if (packetId > 0) {
                  void locatePacketById(packetId);
                }
              }
            }}
            className="w-20 border-none bg-transparent text-center font-mono text-foreground outline-none"
            placeholder="分组号"
            disabled={isPreloadingCapture || isPageLoading}
          />
          <button
            onClick={() => {
              const packetId = Number(packetIdInput);
              if (packetId > 0) {
                void locatePacketById(packetId);
              }
            }}
            disabled={isPreloadingCapture || isPageLoading}
            className="rounded border border-border px-1.5 py-0.5 text-[11px] hover:bg-accent disabled:opacity-50"
          >
            定位
          </button>
        </div>
        <div className="flex items-center gap-1 rounded-md border border-border bg-background px-1 py-1 text-xs">
          <button
            onClick={() => void jumpToPage(1)}
            disabled={isPreloadingCapture || isPageLoading || currentPage <= 1}
            className="rounded border border-border px-1.5 py-0.5 hover:bg-accent disabled:opacity-50"
          >
            «
          </button>
          {pagerItems.map((p) => (
            <button
              key={p}
              onClick={() => void jumpToPage(p)}
              disabled={isPreloadingCapture || isPageLoading}
              className={`rounded border px-1.5 py-0.5 font-mono ${p === currentPage ? "border-blue-600 bg-blue-600 text-white" : "border-border hover:bg-accent"}`}
            >
              {p}
            </button>
          ))}
          <button
            onClick={() => void jumpToPage(totalPages)}
            disabled={isPreloadingCapture || isPageLoading || currentPage >= totalPages}
            className="rounded border border-border px-1.5 py-0.5 hover:bg-accent disabled:opacity-50"
          >
            »
          </button>
        </div>
      </div>
      <div className="flex items-center gap-2 border-b border-border bg-background px-3 py-2 shrink-0">
        <Filter className="h-4 w-4 text-muted-foreground" />
        <span className="text-xs text-muted-foreground">显示过滤器</span>
        <div className="flex flex-1 items-center overflow-hidden rounded-md border border-border bg-card shadow-sm transition-all focus-within:border-blue-500 focus-within:ring-1 focus-within:ring-blue-500">
          <input
            id="display-filter-input"
            list="gshark-filter-suggestions"
            ref={filterInputRef}
            type="text"
            name="display-filter-input"
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="none"
            spellCheck={false}
            aria-autocomplete="list"
            value={displayFilter}
            onChange={(event) => setDisplayFilter(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") applyFilterWithHistory();
            }}
            className="flex-1 border-none bg-transparent px-3 py-1 text-xs font-mono text-foreground placeholder:text-muted-foreground focus:outline-none"
            placeholder={'例如: http.request.method == "POST" and ip.addr == 192.168.1.10'}
          />
          <datalist id="gshark-filter-suggestions">
            {filterSuggestions.map((item) => (
              <option key={item} value={item} />
            ))}
          </datalist>
          {displayFilter && (
            <button onClick={clearFilter} className="px-2 text-muted-foreground transition-colors hover:text-rose-500" title="清空过滤">
              <XCircle className="h-4 w-4" />
            </button>
          )}
        </div>
        <button
          onClick={() => applyFilterWithHistory()}
          disabled={isPreloadingCapture || isPageLoading}
          className="flex items-center gap-1 rounded-md border border-border bg-card px-3 py-1 text-xs text-foreground shadow-sm transition-all hover:bg-accent disabled:opacity-60"
        >
          <Play className="h-3 w-3 text-blue-600" /> 应用
        </button>
        <button
          onClick={clearFilter}
          disabled={isPreloadingCapture || isPageLoading}
          className="flex items-center gap-1 rounded-md border border-border bg-card px-3 py-1 text-xs text-muted-foreground transition-all hover:bg-accent disabled:opacity-60"
        >
          <RefreshCw className="h-3 w-3" /> 清除
        </button>
        <button
          onClick={() => persistRecentFilters([])}
          className="rounded-md border border-border bg-card px-2 py-1 text-[11px] text-muted-foreground transition-all hover:bg-accent"
          title="清空最近过滤历史"
        >
          清空历史
        </button>
      </div>
      <div className="border-b border-border bg-accent/20 px-3 py-1 text-[11px] text-muted-foreground shrink-0">
        {'过滤器已切换为 tshark display filter 原生语法，支持 "http.request"、"tcp.stream eq 3"、"frame.number >= 100"、"ip.addr == 192.168.1.10" 等表达式。'}
      </div>

      {isPreloadingCapture && (
        <div className="border-b border-border bg-accent/30 px-3 py-2">
          <div className="mb-1 flex items-center justify-between text-[11px] text-muted-foreground">
            <span>正在预加载全部流量</span>
            <span>{preloadProcessed.toLocaleString()} / {Math.max(preloadTotal, totalPackets).toLocaleString()} ({preloadPercent}%)</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded bg-muted">
            <div className="h-full bg-blue-600 transition-all" style={{ width: `${preloadPercent}%` }} />
          </div>
        </div>
      )}

      <PanelGroup direction="vertical" className="flex min-h-0 flex-1 flex-col">
        <Panel defaultSize={50} minSize={20} className="bg-card">
          <PacketVirtualTable
            packets={filteredPackets}
            selectedPacketId={selectedPacketId}
            onSelect={selectPacket}
            onDoubleClickHttp={() => navigate("/http-stream")}
            onFollowStream={handleFollowStream}
            hasMorePackets={hasMorePackets}
            onLoadMorePackets={() => void loadMorePackets()}
          />
        </Panel>

        <PanelResizeHandle className="z-20 h-1 cursor-row-resize bg-border transition-colors hover:bg-blue-300 active:bg-blue-500" />

        <Panel defaultSize={50} className="flex">
          <PanelGroup direction="horizontal">
            <Panel defaultSize={50} minSize={20} className="flex flex-col border-r border-border bg-card">
              <div className="flex shrink-0 items-center gap-2 border-b border-border bg-accent/40 px-3 py-1.5 text-xs font-semibold text-foreground">
                <Network className="h-4 w-4 text-emerald-600" /> 协议解析树
              </div>
              <div className="flex-1 overflow-auto p-2 font-mono text-xs">
                {protocolTree.length === 0 ? (
                  <div className="px-2 py-2 text-muted-foreground">暂无数据包，无法显示协议树</div>
                ) : (
                  protocolTree.map((node) => (
                    <TreeNode
                      key={node.id}
                      node={node}
                      selectedId={selectedTreeNode}
                      onSelect={handleSelectTreeNode}
                      registerNodeRef={(id, el) => {
                        if (el) {
                          treeRefs.current.set(id, el);
                        } else {
                          treeRefs.current.delete(id);
                        }
                      }}
                    />
                  ))
                )}
              </div>
            </Panel>

            <PanelResizeHandle className="z-20 w-1 cursor-col-resize bg-border transition-colors hover:bg-blue-300 active:bg-blue-500" />

            <Panel defaultSize={50} minSize={20} className="flex flex-col bg-card">
              <div className="flex shrink-0 items-center gap-2 border-b border-border bg-accent/40 px-3 py-1.5 text-xs font-semibold text-foreground">
                <FileText className="h-4 w-4 text-amber-600" /> 十六进制与 ASCII 视图
                {selectedPacket && (
                  <span className="ml-2 rounded bg-blue-50 px-2 py-0.5 text-[10px] text-blue-600">
                    Packet #{selectedPacket.id}
                  </span>
                )}
              </div>
              <div ref={hexPanelRef} className="flex-1 overflow-auto p-3 font-mono text-xs leading-5">
                {frameBytes.length === 0 ? (
                  <div className="text-muted-foreground">暂无 hex 数据</div>
                ) : (
                  <div className="space-y-0.5">
                    {buildHexRows(frameBytes).map((row) => (
                      <div key={row.offset} className="grid grid-cols-[44px_1fr_136px] gap-1 text-foreground">
                        <span className="text-muted-foreground">{row.offset}</span>
                        <span>
                          {row.bytes.map((item) => {
                            const inRange =
                              selectedByteRange && item.index >= selectedByteRange[0] && item.index <= selectedByteRange[1];
                            const isCursor = selectedByteOffset === item.index;
                            return (
                              <button
                                key={item.index}
                                data-byte={item.index}
                                className={`inline-block rounded px-[1px] font-mono text-[11px] leading-4 font-normal ${
                                  isCursor
                                    ? "bg-blue-700 text-white"
                                    : inRange
                                      ? "bg-amber-100 text-amber-800"
                                        : "text-foreground"
                                }`}
                                onClick={() => handleSelectByte(item.index)}
                              >
                                {item.hex}
                              </button>
                            );
                          })}
                        </span>
                        <span>
                          {row.bytes.map((item) => {
                            const inRange =
                              selectedByteRange && item.index >= selectedByteRange[0] && item.index <= selectedByteRange[1];
                            const isCursor = selectedByteOffset === item.index;
                            return (
                              <button
                                key={`ascii-${item.index}`}
                                data-byte={item.index}
                                className={`inline-block rounded px-[1px] text-[11px] leading-4 font-normal ${
                                  isCursor
                                    ? "bg-blue-700 text-white"
                                    : inRange
                                      ? "bg-amber-100 text-amber-800"
                                        : "text-muted-foreground"
                                }`}
                                onClick={() => handleSelectByte(item.index)}
                              >
                                {item.ascii}
                              </button>
                            );
                          })}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Panel>
          </PanelGroup>
        </Panel>
      </PanelGroup>
    </div>
  );
}

function parsePayloadBytes(payload: string): number[] {
  const raw = (payload ?? "").trim();
  if (!raw) return [];

  if (/^([0-9a-fA-F]{2})(:[0-9a-fA-F]{2})*$/.test(raw)) {
    return raw
      .split(":")
      .map((part) => Number.parseInt(part, 16))
      .filter((v) => Number.isFinite(v));
  }

  return Array.from(new TextEncoder().encode(raw));
}

function ipv4ToBytes(ip: string): number[] {
  const parts = ip.split(".").map((s) => Number.parseInt(s, 10));
  if (parts.length !== 4 || parts.some((v) => Number.isNaN(v) || v < 0 || v > 255)) {
    return [0, 0, 0, 0];
  }
  return parts;
}

function buildFrameBytes(packet: Packet | null, selectedRawHex?: string): number[] {
  if (!packet) return [];

  const rawHex = selectedRawHex && selectedRawHex.trim() ? selectedRawHex : packet.rawHex;
  if (rawHex && rawHex.trim()) {
    const cleaned = rawHex.replace(/[^0-9a-fA-F]/g, "");
    if (cleaned.length >= 2) {
      const evenHex = cleaned.length % 2 === 0 ? cleaned : cleaned.slice(0, -1);
      const out: number[] = [];
      for (let i = 0; i < evenHex.length; i += 2) {
        const byte = Number.parseInt(evenHex.slice(i, i + 2), 16);
        if (Number.isFinite(byte)) {
          out.push(byte);
        }
      }
      if (out.length > 0) {
        return out;
      }
    }
  }

  // Never synthesize bytes with zero padding; only render true frame bytes.
  return [];
}

function buildHexRows(bytes: number[]) {
  const rows: { offset: string; bytes: { index: number; hex: string; ascii: string }[] }[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.slice(i, i + 16);
    rows.push({
      offset: i.toString(16).padStart(4, "0"),
      bytes: slice.map((value, idx) => ({
        index: i + idx,
        hex: value.toString(16).padStart(2, "0"),
        ascii: value >= 32 && value <= 126 ? String.fromCharCode(value) : ".",
      })),
    });
  }
  return rows;
}

function findClosestNodeByOffset(offset: number, nodes: ProtocolTreeNode[]): string | null {
  const matches: { id: string; span: number }[] = [];

  const walk = (node: ProtocolTreeNode) => {
    if (node.byteRange && offset >= node.byteRange[0] && offset <= node.byteRange[1]) {
      matches.push({ id: node.id, span: node.byteRange[1] - node.byteRange[0] });
    }
    node.children?.forEach(walk);
  };

  nodes.forEach(walk);
  if (matches.length === 0) return null;
  matches.sort((a, b) => a.span - b.span);
  return matches[0].id;
}

function TreeNode({
  node,
  depth = 0,
  selectedId,
  onSelect,
  registerNodeRef,
}: {
  node: ProtocolTreeNode;
  depth?: number;
  selectedId: string;
  onSelect: (id: string) => void;
  registerNodeRef: (id: string, el: HTMLDivElement | null) => void;
}) {
  const [expanded, setExpanded] = useState(true);
  const hasChildren = (node.children?.length ?? 0) > 0;
  const selected = selectedId === node.id;

  return (
    <div className="flex flex-col">
      <div
        ref={(el) => registerNodeRef(node.id, el)}
        className={`flex cursor-pointer items-center rounded px-1 py-0.5 ${selected ? "bg-blue-100 text-blue-700" : "text-foreground hover:bg-blue-50/70"}`}
        style={{ paddingLeft: `${depth * 16}px` }}
        onClick={() => {
          onSelect(node.id);
          if (hasChildren) setExpanded((v) => !v);
        }}
      >
        <span className="mr-1 flex w-4 select-none justify-center font-bold text-muted-foreground">
          {hasChildren ? (expanded ? "[-]" : "[+]") : ""}
        </span>
        <span className="break-all">{node.label}</span>
      </div>
      {expanded && hasChildren && (
        <div className="flex flex-col">
          {node.children?.map((child) => (
            <TreeNode
              key={child.id}
              node={child}
              depth={depth + 1}
              selectedId={selectedId}
              onSelect={onSelect}
              registerNodeRef={registerNodeRef}
            />
          ))}
        </div>
      )}
    </div>
  );
}
