import { useEffect, useMemo, useState } from "react";
import { ArrowLeftRight, Download, Minimize2, ChevronLeft, ChevronRight, ArrowLeft } from "lucide-react";
import { useNavigate } from "react-router";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { useSentinel } from "../state/SentinelContext";

function cn(...inputs: (string | undefined | null | false)[]) {
  return twMerge(clsx(inputs));
}

export default function UdpStream() {
  const [viewMode, setViewMode] = useState("ascii");
  const [streamInput, setStreamInput] = useState("");
  const [renderLimit, setRenderLimit] = useState(200);
  const navigate = useNavigate();
  const { udpStream, streamIds, setActiveStream, streamSwitchMetrics } = useSentinel();
  const currentIndex = streamIds.udp.findIndex((id) => id === udpStream.id);
  const ordinalLabel = currentIndex >= 0 ? `${currentIndex + 1} / ${streamIds.udp.length || 1}` : `-- / ${streamIds.udp.length || 0}`;
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex >= 0 && currentIndex < streamIds.udp.length - 1;
  const visibleChunks = useMemo(() => udpStream.chunks.slice(0, renderLimit), [udpStream.chunks, renderLimit]);

  useEffect(() => {
    setRenderLimit(200);
  }, [udpStream.id]);

  return (
    <div className="relative flex h-full flex-col overflow-hidden bg-background text-sm text-foreground">
      <div className="flex shrink-0 items-center justify-between border-b border-border bg-accent/40 px-4 py-2">
        <div className="flex items-center gap-3">
          <button onClick={() => navigate(-1)} className="rounded p-1 text-foreground transition-colors hover:bg-accent" title="返回上一页">
            <ArrowLeft className="h-4 w-4" />
          </button>
          <div className="h-4 w-px bg-border" />
          <h1 className="flex items-center gap-2 font-semibold text-foreground">
            追踪 UDP 流 (Stream eq {udpStream.id})
            <span className="ml-2 flex items-center gap-1 font-mono text-xs text-muted-foreground">
              {udpStream.from} <ArrowLeftRight className="h-3 w-3" /> {udpStream.to}
            </span>
          </h1>
        </div>
        <button className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground"><Minimize2 className="h-4 w-4" /></button>
      </div>

      <div className="flex-1 overflow-auto bg-card p-4 font-mono text-sm leading-relaxed">
        <div className="flex max-w-4xl flex-col gap-1">
          {visibleChunks.map((chunk) => (
            <div
              key={chunk.packetId}
              className={cn(
                "rounded-md border px-3 py-2",
                chunk.direction === "client" ? "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400" : "border-cyan-500/30 bg-cyan-500/10 text-cyan-700 dark:text-cyan-400",
              )}
            >
              <span className="mr-2 select-none text-xs font-semibold opacity-60">
                {chunk.direction === "client" ? "[客户端 -> 服务端]" : "[服务端 -> 客户端]"}
              </span>
              <pre className="whitespace-pre-wrap break-all text-xs leading-5">
                {renderStreamChunk(chunk.body, viewMode)}
              </pre>
            </div>
          ))}
          {renderLimit < udpStream.chunks.length && (
            <button
              className="mt-2 self-start rounded border border-border bg-background px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
              onClick={() => setRenderLimit((prev) => Math.min(prev + 400, udpStream.chunks.length))}
            >
              加载更多 ({renderLimit}/{udpStream.chunks.length})
            </button>
          )}
        </div>
      </div>

      <div className="grid shrink-0 grid-cols-[250px_280px_420px_minmax(120px,1fr)] items-center gap-4 border-t border-border bg-card px-4 py-3 shadow-sm">
        <div className="rounded-md border border-border bg-background px-2 py-1 text-[11px] text-muted-foreground">
          切流 last {streamSwitchMetrics.byProtocol.UDP.lastMs}ms / p50 {streamSwitchMetrics.byProtocol.UDP.p50Ms}ms / p95 {streamSwitchMetrics.byProtocol.UDP.p95Ms}ms / cache {streamSwitchMetrics.byProtocol.UDP.cacheHitRate}%
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
        <div className="grid h-full grid-cols-[auto_28px_minmax(220px,1fr)_28px_72px] items-center gap-2">
          <span className="text-xs text-muted-foreground">流切换:</span>
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
            第 {ordinalLabel} 条 · stream eq {udpStream.id}
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
              if (id > 0) {
                void setActiveStream("UDP", id);
              }
            }}
            className="w-16 rounded border border-border bg-background px-1 py-0.5 text-center text-xs font-mono outline-none"
            placeholder="stream"
            title={`UDP 流总数: ${streamIds.udp.length}`}
          />
        </div>
        <div className="justify-self-end">
          <button className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 text-xs text-foreground shadow-sm transition-all hover:bg-accent">
            <Download className="h-3.5 w-3.5" /> 导出为文件
          </button>
        </div>
      </div>
    </div>
  );
}

function parseChunkBytes(body: string): number[] {
  const raw = (body ?? "").trim();
  if (!raw) return [];
  const isHex = /^([0-9a-fA-F]{2})(:[0-9a-fA-F]{2})*$/.test(raw);
  if (!isHex) {
    return Array.from(new TextEncoder().encode(raw));
  }
  return raw
    .split(":")
    .map((part) => Number.parseInt(part, 16))
    .filter((v) => Number.isFinite(v));
}

function bytesToAscii(bytes: number[]): string {
  if (bytes.length === 0) return "(empty payload)";
  return bytes.map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("");
}

function bytesToHexDump(bytes: number[]): string {
  if (bytes.length === 0) return "(empty payload)";
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = chunk.map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = chunk.map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${i.toString(16).padStart(4, "0")}  ${hex.padEnd(47, " ")}  ${ascii}`);
  }
  return lines.join("\n");
}

function renderStreamChunk(body: string, mode: string): string {
  if (mode === "raw") {
    return body || "(empty payload)";
  }

  const bytes = parseChunkBytes(body);
  if (mode === "hex") {
    return bytesToHexDump(bytes);
  }
  return bytesToAscii(bytes);
}
