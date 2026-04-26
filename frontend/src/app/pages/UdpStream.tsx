import { memo, useEffect, useMemo, useRef, useState } from "react";
import { ArrowLeftRight, Download, ChevronLeft, ChevronRight, ArrowLeft } from "lucide-react";
import { useLocation, useNavigate } from "react-router";
import { useSentinel } from "../state/SentinelContext";
import { cn } from "../components/ui/utils";
import { bridge } from "../integrations/wailsBridge";
import type { StreamLoadMeta } from "../core/types";
import { StreamDecoderWorkbench } from "../components/StreamDecoderWorkbench";
import { parseChunkBytes, bytesToAscii, bytesToHexDump, estimatePayloadBytes } from "../core/stream-utils";

type RawViewMode = "ascii" | "hex" | "raw";
type RawChunk = { packetId: number; direction: string; body: string };

const STREAM_PAGE_SIZE = 96;
const MAX_PREVIEW_BYTES = 4096;

export default function UdpStream() {
  const [viewMode, setViewMode] = useState<RawViewMode>("ascii");
  const [streamInput, setStreamInput] = useState("");
  const [loadError, setLoadError] = useState("");
  const [selectedChunkIndex, setSelectedChunkIndex] = useState(0);
  const [streamView, setStreamView] = useState(() => ({
    id: -1,
    protocol: "UDP" as const,
    from: "",
    to: "",
    chunks: [] as RawChunk[],
    loadMeta: undefined as StreamLoadMeta | undefined,
    nextCursor: 0,
    totalChunks: 0,
    hasMore: false,
  }));
  const [loadingMore, setLoadingMore] = useState(false);
  const consumedRouteStreamIdRef = useRef<number | null>(null);
  const navigate = useNavigate();
  const location = useLocation();
  const { udpStream, selectedPacket, streamIds, setActiveStream, persistStreamPayloads, streamSwitchMetrics } = useSentinel();
  const currentIndex = streamIds.udp.findIndex((id) => id === streamView.id);
  const ordinalLabel = currentIndex >= 0 ? `${currentIndex + 1} / ${streamIds.udp.length || 1}` : `-- / ${streamIds.udp.length || 0}`;
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex >= 0 && currentIndex < streamIds.udp.length - 1;
  const visibleChunks = useMemo(() => streamView.chunks, [streamView.chunks]);
  const selectedChunk = streamView.chunks[selectedChunkIndex] ?? null;
  const selectedChunkRendered = useMemo(
    () => renderStreamChunk(selectedChunk?.body ?? "", viewMode),
    [selectedChunk, viewMode],
  );

  useEffect(() => {
    setStreamView({
      id: udpStream.id,
      protocol: "UDP" as const,
      from: udpStream.from,
      to: udpStream.to,
      chunks: udpStream.chunks,
      loadMeta: udpStream.loadMeta,
      nextCursor: udpStream.nextCursor ?? udpStream.chunks.length,
      totalChunks: udpStream.totalChunks ?? udpStream.chunks.length,
      hasMore: udpStream.hasMore ?? false,
    });
  }, [udpStream]);

  useEffect(() => {
    setStreamInput(udpStream.id >= 0 ? String(udpStream.id) : "");
    setLoadError("");
    setSelectedChunkIndex(0);
  }, [udpStream.id]);

  useEffect(() => {
    if (streamView.chunks.length === 0) {
      setSelectedChunkIndex(0);
      return;
    }
    setSelectedChunkIndex((prev) => Math.min(prev, streamView.chunks.length - 1));
  }, [streamView.chunks]);

  useEffect(() => {
    const state = location.state as { streamId?: number } | null;
    const routeStreamId = Number(state?.streamId ?? -1);
    const selectedStreamId = Number(selectedPacket?.streamId ?? -1);
    const hasPendingRouteStream = routeStreamId >= 0 && routeStreamId !== consumedRouteStreamIdRef.current;
    const streamId = hasPendingRouteStream ? routeStreamId : streamView.id < 0 ? selectedStreamId : -1;
    if (streamId < 0 || !streamIds.udp.includes(streamId) || streamView.id === streamId) {
      return;
    }
    if (hasPendingRouteStream) {
      consumedRouteStreamIdRef.current = routeStreamId;
    }
    void setActiveStream("UDP", streamId);
  }, [location.state, selectedPacket?.streamId, setActiveStream, streamIds.udp, streamView.id]);

  async function loadMore() {
    if (loadingMore || !streamView.hasMore) return;
    setLoadingMore(true);
    setLoadError("");
    try {
      const page = await bridge.getRawStreamPage("UDP", streamView.id, streamView.nextCursor ?? streamView.chunks.length, STREAM_PAGE_SIZE);
      setStreamView((prev) => {
        if (prev.id !== page.id) return prev;
        return {
          ...prev,
          from: page.from,
          to: page.to,
          chunks: [...prev.chunks, ...page.chunks],
          loadMeta: page.loadMeta ?? prev.loadMeta,
          nextCursor: page.nextCursor ?? prev.chunks.length + page.chunks.length,
          totalChunks: page.totalChunks ?? prev.totalChunks,
          hasMore: page.hasMore ?? false,
        };
      });
    } catch (error) {
      setLoadError(error instanceof Error && error.message ? error.message : "加载更多流片段失败");
    } finally {
      setLoadingMore(false);
    }
  }

  function applyLocalPatches(patches: Array<{ index: number; body: string }>) {
    if (patches.length === 0) return;
    const patchMap = new Map<number, string>(patches.map((patch) => [patch.index, patch.body]));
    setStreamView((prev) => ({
      ...prev,
      chunks: prev.chunks.map((chunk, index) => (
        patchMap.has(index) ? { ...chunk, body: patchMap.get(index) ?? chunk.body } : chunk
      )),
    }));
  }

  function exportAll() {
    const content = streamView.chunks
      .map((chunk) => `--- ${chunk.direction === "client" ? "CLIENT -> SERVER" : "SERVER -> CLIENT"} [packet:${chunk.packetId}] ---\n${chunk.body}`)
      .join("\n\n");
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `udp-stream-${streamView.id}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="bg-background relative flex h-full flex-col overflow-hidden text-sm text-foreground">
      <div className="flex shrink-0 items-center justify-between border-b border-border bg-accent/40 px-4 py-2">
        <div className="flex items-center gap-3">
          <button onClick={() => navigate(-1)} className="rounded p-1 text-foreground transition-colors hover:bg-accent" title="返回上一页">
            <ArrowLeft className="h-4 w-4" />
          </button>
          <div className="h-4 w-px bg-border" />
          <h1 className="flex items-center gap-2 font-semibold text-foreground">
            UDP 流追踪 (stream eq {streamView.id})
            <span className="ml-2 flex items-center gap-1 font-mono text-xs text-muted-foreground">
              {streamView.from} <ArrowLeftRight className="h-3 w-3" /> {streamView.to}
            </span>
          </h1>
        </div>
        <div className="flex items-center gap-2">
          <span className="rounded-md border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground">
            已载入 {streamView.chunks.length}/{streamView.totalChunks || streamView.chunks.length}
          </span>
          <span className="rounded-md border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground">
            {formatLoadMeta(streamView.loadMeta)}
          </span>
        </div>
      </div>

      <div className="grid min-h-0 flex-1 gap-4 bg-transparent p-4 xl:grid-cols-[minmax(0,1.45fr)_minmax(360px,0.95fr)]">
        <div className="min-h-0 overflow-auto rounded-xl border border-border bg-background p-4 font-mono text-sm leading-relaxed shadow-sm">
          {loadError && (
            <div className="mb-3 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
              {loadError}
            </div>
          )}
          {streamView.loadMeta?.loading && streamView.chunks.length === 0 && (
            <div className="mb-3 rounded-md border border-blue-500/30 bg-blue-500/10 px-3 py-2 text-xs text-blue-700 dark:text-blue-300">
              正在解析 udp.stream eq {streamView.id}，当前只先加载这一条流。
            </div>
          )}
          <div className="flex max-w-4xl flex-col gap-2">
            {visibleChunks.map((chunk, index) => (
              <RawStreamChunkCard
                key={`${chunk.packetId}-${chunk.direction}-${index}`}
                chunk={chunk}
                mode={viewMode}
                clientTone="border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400"
                serverTone="border-cyan-500/30 bg-cyan-500/10 text-cyan-700 dark:text-cyan-400"
                selected={selectedChunkIndex === index}
                onSelect={() => setSelectedChunkIndex(index)}
              />
            ))}
            {streamView.hasMore && (
              <button
                className="mt-2 self-start rounded border border-border bg-background px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-60"
                onClick={() => void loadMore()}
                disabled={loadingMore}
              >
                {loadingMore ? "正在加载..." : `加载更多 (${streamView.chunks.length}/${streamView.totalChunks || streamView.chunks.length})`}
              </button>
            )}
          </div>
        </div>
        <div className="space-y-4 xl:sticky xl:top-0">
          <div className="rounded-xl border border-border bg-card p-4 shadow-sm">
            <div className="mb-3 flex items-center justify-between gap-3">
              <div>
                <div className="text-sm font-semibold text-foreground">当前片段</div>
                <div className="text-[11px] text-muted-foreground">固定查看当前 UDP payload，便于快速对照解码结果</div>
              </div>
              {selectedChunk && (
                <span className={cn(
                  "rounded-full border px-2.5 py-1 text-[11px] font-semibold",
                  selectedChunk.direction === "client"
                    ? "border-amber-200 bg-amber-50 text-amber-700"
                    : "border-cyan-200 bg-cyan-50 text-cyan-700",
                )}>
                  {selectedChunk.direction === "client" ? "客户端 -> 服务端" : "服务端 -> 客户端"}
                </span>
              )}
            </div>
            {selectedChunk ? (
              <>
                <div className="mb-3 flex flex-wrap gap-2 text-[11px]">
                  <span className="rounded-md border border-border bg-background px-2 py-1 text-muted-foreground">packet #{selectedChunk.packetId}</span>
                  <span className="rounded-md border border-border bg-background px-2 py-1 text-muted-foreground">{estimatePayloadBytes(selectedChunk.body)} bytes</span>
                  <span className="rounded-md border border-border bg-background px-2 py-1 text-muted-foreground">chunk #{selectedChunkIndex + 1}</span>
                </div>
                <div className="max-h-[360px] overflow-auto rounded-lg border border-border bg-background/80 p-3">
                  <pre className="whitespace-pre-wrap break-all font-mono text-xs leading-5 text-foreground">{selectedChunkRendered || "(empty payload)"}</pre>
                </div>
              </>
            ) : (
              <div className="rounded-lg border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground">
                选择左侧片段后，可在这里固定查看详情。
              </div>
            )}
          </div>
          <StreamDecoderWorkbench
            payload={selectedChunk?.body ?? ""}
            chunkLabel={
              selectedChunk
                ? `UDP 片段 #${selectedChunk.packetId} / ${selectedChunk.direction === "client" ? "客户端 -> 服务端" : "服务端 -> 客户端"}`
                : `UDP 流 stream eq ${streamView.id}`
            }
            tone="amber"
            onApplyDecoded={selectedChunk && selectedChunkIndex >= 0
              ? async (body) => {
                  const patches = [{ index: selectedChunkIndex, body }];
                  await persistStreamPayloads("UDP", streamView.id, patches);
                  applyLocalPatches(patches);
                }
              : undefined}
            batchItems={streamView.chunks.map((chunk, index) => ({
              index,
              payload: chunk.body,
              label: `#${chunk.packetId} ${chunk.direction === "client" ? "client->server" : "server->client"}`,
            }))}
            selectedBatchIndex={selectedChunkIndex}
            onApplyDecodedBatch={async (patches) => {
              await persistStreamPayloads("UDP", streamView.id, patches);
              applyLocalPatches(patches);
            }}
          />
        </div>
      </div>

      <div className="grid shrink-0 grid-cols-[250px_280px_420px_minmax(120px,1fr)] items-center gap-4 border-t border-border bg-card px-4 py-3 shadow-sm">
        <div className="rounded-md border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground">
          切流 last {streamSwitchMetrics.byProtocol.UDP.lastMs}ms / p50 {streamSwitchMetrics.byProtocol.UDP.p50Ms}ms / p95 {streamSwitchMetrics.byProtocol.UDP.p95Ms}ms / fast-path {streamSwitchMetrics.byProtocol.UDP.cacheHitRate}%
        </div>
        <div className="flex items-center gap-3 text-xs font-medium text-muted-foreground">
          显示方式:
          <label className="flex cursor-pointer items-center gap-1 hover:text-foreground">
            <input type="radio" name="viewMode" checked={viewMode === "ascii"} onChange={() => setViewMode("ascii")} className="accent-blue-600" /> ASCII
          </label>
          <label className="flex cursor-pointer items-center gap-1 hover:text-foreground">
            <input type="radio" name="viewMode" checked={viewMode === "hex"} onChange={() => setViewMode("hex")} className="accent-blue-600" /> Hex Dump
          </label>
          <label className="flex cursor-pointer items-center gap-1 hover:text-foreground">
            <input type="radio" name="viewMode" checked={viewMode === "raw"} onChange={() => setViewMode("raw")} className="accent-blue-600" /> Raw
          </label>
        </div>
        <div className="grid h-full grid-cols-[auto_28px_minmax(220px,1fr)_28px_72px_120px] items-center gap-2">
          <span className="text-xs text-muted-foreground">流切换</span>
          <button
            className="rounded border border-border bg-accent p-1 text-muted-foreground hover:bg-accent/80 hover:text-foreground disabled:opacity-40"
            onClick={() => {
              if (!hasPrev) return;
              void setActiveStream("UDP", streamIds.udp[currentIndex - 1]);
            }}
            disabled={!hasPrev}
            title={`UDP 流总数: ${streamIds.udp.length}`}
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <span className="px-2 text-center font-mono text-xs text-foreground" title={`UDP 流总数: ${streamIds.udp.length}`}>
            第 {ordinalLabel} 条 / stream eq {streamView.id}
          </span>
          <button
            className="rounded border border-border bg-accent p-1 text-muted-foreground hover:bg-accent/80 hover:text-foreground disabled:opacity-40"
            onClick={() => {
              if (!hasNext) return;
              void setActiveStream("UDP", streamIds.udp[currentIndex + 1]);
            }}
            disabled={!hasNext}
            title={`UDP 流总数: ${streamIds.udp.length}`}
          >
            <ChevronRight className="h-4 w-4" />
          </button>
          <input
            value={streamInput}
            onChange={(event) => setStreamInput(event.target.value.replace(/[^0-9]/g, ""))}
            onKeyDown={(event) => {
              if (event.key !== "Enter") return;
              const id = Number(streamInput);
              if (id >= 0) {
                void setActiveStream("UDP", id);
              }
            }}
            className="w-16 rounded border border-border bg-background px-1 py-0.5 text-center text-xs font-mono outline-none"
            placeholder="stream"
            title={`UDP 流总数: ${streamIds.udp.length}`}
          />
          <span className="text-right text-[11px] text-muted-foreground">
            已载入 {streamView.chunks.length}/{streamView.totalChunks || streamView.chunks.length}
          </span>
        </div>
        <div className="justify-self-end">
          <div className="flex items-center gap-3">
            <button onClick={exportAll} className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 text-xs text-foreground shadow-sm transition-all hover:bg-accent">
              <Download className="h-3.5 w-3.5" /> 导出为文件
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function formatLoadMeta(meta?: StreamLoadMeta): string {
  if (!meta) return "来源 unknown";
  if (meta.loading) return "正在解析当前 UDP 流...";
  const source = meta.source || "unknown";
  const tshark = meta.tsharkMs && meta.tsharkMs > 0 ? `${meta.tsharkMs}ms` : "0ms";
  const overrides = meta.overrideCount && meta.overrideCount > 0 ? ` / overrides ${meta.overrideCount}` : "";
  return `来源 ${source} / cache ${meta.cacheHit ? "yes" : "no"} / index ${meta.indexHit ? "yes" : "no"} / fallback ${meta.fileFallback ? "yes" : "no"} / tshark ${tshark}${overrides}`;
}

const RawStreamChunkCard = memo(function RawStreamChunkCard({
  chunk,
  mode,
  clientTone,
  serverTone,
  selected,
  onSelect,
}: {
  chunk: RawChunk;
  mode: RawViewMode;
  clientTone: string;
  serverTone: string;
  selected: boolean;
  onSelect: () => void;
}) {
  const rendered = useMemo(() => renderStreamChunk(chunk.body, mode), [chunk.body, mode]);
  const tone = chunk.direction === "client" ? clientTone : serverTone;

  return (
    <div className={cn("cursor-pointer rounded-md border px-3 py-2 transition-shadow", tone, selected && "ring-2 ring-blue-300 shadow-sm")} onClick={onSelect}>
      <span className="mr-2 select-none text-xs font-semibold opacity-60">
        {chunk.direction === "client" ? "[客户端 -> 服务端]" : "[服务端 -> 客户端]"}
      </span>
      <pre className="whitespace-pre-wrap break-all text-xs leading-5">{rendered}</pre>
    </div>
  );
});

function renderStreamChunk(body: string, mode: RawViewMode): string {
  const raw = body || "";
  if (mode === "raw") {
    if (!raw) return "(empty payload)";
    if (raw.length <= MAX_PREVIEW_BYTES * 3) {
      return raw;
    }
    return `${raw.slice(0, MAX_PREVIEW_BYTES * 3)}\n\n... 已截断`;
  }

  const bytes = parseChunkBytes(raw, MAX_PREVIEW_BYTES);
  if (mode === "hex") {
    return bytesToHexDump(bytes);
  }
  return bytesToAscii(bytes);
}
