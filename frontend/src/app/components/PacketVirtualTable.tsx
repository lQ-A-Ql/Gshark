import { useEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent } from "react";
import type { Packet } from "../core/types";
import { getPacketColorStyle } from "../core/packetColoring";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { Settings2 } from "lucide-react";
import { FloatingSurface } from "./ui/FloatingSurface";
import { useViewportSafePosition } from "../hooks/useViewportSafePosition";

function cn(...inputs: (string | undefined | null | false)[]) {
  return twMerge(clsx(inputs));
}

interface PacketVirtualTableProps {
  packets: Packet[];
  selectedPacketId: number | null;
  onSelect: (id: number) => void;
  onDoubleClickHttp: () => void;
  onFollowStream: (packet: Packet, target: "http" | "tcp" | "udp") => void;
  hasMorePackets?: boolean;
  onLoadMorePackets?: () => void;
}

type CommFailureLevel = "critical" | "major" | "warn" | null;

function getCommunicationFailureLevel(packet: Packet): CommFailureLevel {
  const info = `${packet.info ?? ""} ${packet.payload ?? ""}`.toLowerCase();
  const tlsLike = packet.proto === "TLS" || packet.proto === "HTTPS" || info.includes("tls") || info.includes("ssl");
  const tlsFail = tlsLike && (
    info.includes("handshake failure") ||
    info.includes("fatal alert") ||
    info.includes("decrypt error") ||
    info.includes("bad certificate") ||
    info.includes("unknown ca") ||
    info.includes("certificate unknown") ||
    info.includes("protocol version")
  );
  if (tlsFail) return "critical";

  const tcpFail =
    info.includes("tcp reset") ||
    info.includes("[rst") ||
    info.includes("retransmission") ||
    info.includes("duplicate ack") ||
    info.includes("out-of-order") ||
    info.includes("previous segment not captured") ||
    info.includes("connection refused") ||
    info.includes("timeout");
  if (tcpFail) return "major";

  const dnsFail =
    info.includes("nxdomain") ||
    info.includes("servfail") ||
    info.includes("refused") ||
    info.includes("format error") ||
    info.includes("no such name");
  if (dnsFail) return "warn";

  const httpFail =
    /http\/\d\.\d\s+5\d\d/.test(info) ||
    /http\/\d\.\d\s+4\d\d/.test(info) ||
    info.includes("bad gateway") ||
    info.includes("gateway timeout") ||
    info.includes("service unavailable");
  if (httpFail) return "major";

  const icmpFail = info.includes("destination unreachable") || info.includes("time-to-live exceeded") || info.includes("ttl exceeded");
  if (icmpFail) return "warn";

  return null;
}

type ColumnId = "id" | "time" | "src" | "dst" | "proto" | "length" | "info";

interface ColumnSpec {
  id: ColumnId;
  label: string;
  width: number;
  visible: boolean;
}

const COLUMN_STORAGE_KEY = "gshark.packet-table.columns.v1";

const DEFAULT_COLUMNS: ColumnSpec[] = [
  { id: "id", label: "No.", width: 72, visible: true },
  { id: "time", label: "Time", width: 170, visible: true },
  { id: "src", label: "Source", width: 220, visible: true },
  { id: "dst", label: "Destination", width: 220, visible: true },
  { id: "proto", label: "Protocol", width: 100, visible: true },
  { id: "length", label: "Length", width: 90, visible: true },
  { id: "info", label: "Info", width: 420, visible: true },
];

function loadSavedColumns(): ColumnSpec[] {
  if (typeof window === "undefined") return DEFAULT_COLUMNS;

  try {
    const raw = window.localStorage.getItem(COLUMN_STORAGE_KEY);
    if (!raw) return DEFAULT_COLUMNS;

    const parsed = JSON.parse(raw) as Partial<ColumnSpec>[];
    if (!Array.isArray(parsed)) return DEFAULT_COLUMNS;

    const merged = DEFAULT_COLUMNS.map((defaults) => {
      const saved = parsed.find((item) => item.id === defaults.id);
      if (!saved) return defaults;
      return {
        ...defaults,
        label: typeof saved.label === "string" && saved.label.trim() ? saved.label : defaults.label,
        width: typeof saved.width === "number" && Number.isFinite(saved.width) ? Math.max(64, saved.width) : defaults.width,
        visible: typeof saved.visible === "boolean" ? saved.visible : defaults.visible,
      };
    });

    if (merged.every((col) => !col.visible)) {
      return DEFAULT_COLUMNS;
    }
    return merged;
  } catch {
    return DEFAULT_COLUMNS;
  }
}

const ROW_HEIGHT = 30;
const BUFFER = 10;
const CONTEXT_MENU_WIDTH = 192;
const CONTEXT_MENU_HEIGHT = 118;
const CONTEXT_MENU_MARGIN = 12;
const CONTEXT_MENU_SIZE = { width: CONTEXT_MENU_WIDTH, height: CONTEXT_MENU_HEIGHT };

export function PacketVirtualTable({
  packets,
  selectedPacketId,
  onSelect,
  onDoubleClickHttp,
  onFollowStream,
  hasMorePackets = false,
  onLoadMorePackets,
}: PacketVirtualTableProps) {
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(360);
  const [showColumnPanel, setShowColumnPanel] = useState(false);
  const [columns, setColumns] = useState<ColumnSpec[]>(() => loadSavedColumns());
  const {
    position: menuPosition,
    openAtEvent: openMenuAtEvent,
    close: closeMenu,
    isOpen: menuIsOpen,
  } = useViewportSafePosition<Packet>({
    floating: CONTEXT_MENU_SIZE,
    margin: CONTEXT_MENU_MARGIN,
  });
  const viewportRef = useRef<HTMLDivElement | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const resizingRef = useRef<{ id: ColumnId; startX: number; startWidth: number } | null>(null);
  const loadMoreThrottleRef = useRef(0);

  const totalHeight = packets.length * ROW_HEIGHT;
  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - BUFFER);
  const endIndex = Math.min(packets.length - 1, Math.ceil((scrollTop + viewportHeight) / ROW_HEIGHT) + BUFFER);

  const rows = useMemo(() => packets.slice(startIndex, endIndex + 1), [packets, startIndex, endIndex]);
  const visibleColumns = useMemo(() => columns.filter((col) => col.visible), [columns]);
  const gridTemplateColumns = useMemo(
    () => visibleColumns.map((col) => `${col.width}px`).join(" "),
    [visibleColumns],
  );

  useEffect(() => {
    const handleMove = (event: MouseEvent) => {
      const resizing = resizingRef.current;
      if (!resizing) return;

      const diff = event.clientX - resizing.startX;
      const nextWidth = Math.max(64, resizing.startWidth + diff);
      setColumns((prev) =>
        prev.map((col) => (col.id === resizing.id ? { ...col, width: nextWidth } : col)),
      );
    };

    const handleUp = () => {
      resizingRef.current = null;
    };

    window.addEventListener("mousemove", handleMove);
    window.addEventListener("mouseup", handleUp);
    return () => {
      window.removeEventListener("mousemove", handleMove);
      window.removeEventListener("mouseup", handleUp);
    };
  }, []);

  useEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport || typeof ResizeObserver === "undefined") return;

    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) return;
      const h = Math.max(120, Math.floor(entry.contentRect.height));
      setViewportHeight(h);
    });

    observer.observe(viewport);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(COLUMN_STORAGE_KEY, JSON.stringify(columns));
  }, [columns]);

  useEffect(() => {
    if (!menuIsOpen || typeof window === "undefined") return;

    const closeFloatingMenu = () => closeMenu();
    const handlePointerDown = (event: PointerEvent) => {
      if (!menuRef.current?.contains(event.target as Node)) {
        closeMenu();
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        closeMenu();
      }
    };

    // The menu is viewport-positioned; any scroll/resize invalidates the anchor point.
    window.addEventListener("pointerdown", handlePointerDown, true);
    window.addEventListener("resize", closeFloatingMenu);
    window.addEventListener("scroll", closeFloatingMenu, true);
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("pointerdown", handlePointerDown, true);
      window.removeEventListener("resize", closeFloatingMenu);
      window.removeEventListener("scroll", closeFloatingMenu, true);
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [closeMenu, menuIsOpen]);

  const startResize = (id: ColumnId, event: ReactMouseEvent<HTMLDivElement>) => {
    event.preventDefault();
    const col = columns.find((item) => item.id === id);
    if (!col) return;
    resizingRef.current = { id, startX: event.clientX, startWidth: col.width };
  };

  const updateLabel = (id: ColumnId, label: string) => {
    setColumns((prev) => prev.map((col) => (col.id === id ? { ...col, label } : col)));
  };

  const toggleColumnVisible = (id: ColumnId) => {
    setColumns((prev) => {
      const visibleCount = prev.filter((col) => col.visible).length;
      return prev.map((col) => {
        if (col.id !== id) return col;
        if (col.visible && visibleCount <= 1) return col;
        return { ...col, visible: !col.visible };
      });
    });
  };

  const resetColumns = () => {
    setColumns(DEFAULT_COLUMNS);
  };

  const renderCell = (packet: Packet, colId: ColumnId) => {
    const protocolLabel = packet.displayProtocol?.trim() || packet.proto;
    switch (colId) {
      case "id":
        return (
          <div className="px-3 py-1.5 tabular-nums">
            <span className="inline-flex items-center gap-1">
              {getCommunicationFailureLevel(packet) && (
                <span
                  className={cn(
                    "inline-block h-2 w-2 rounded-full",
                    getCommunicationFailureLevel(packet) === "critical"
                      ? "bg-rose-600"
                      : getCommunicationFailureLevel(packet) === "major"
                        ? "bg-orange-500"
                        : "bg-amber-500",
                  )}
                  title="通讯异常"
                />
              )}
              <span>{packet.id}</span>
            </span>
          </div>
        );
      case "time":
        return <div className="px-3 py-1.5 whitespace-nowrap font-mono font-normal">{packet.time}</div>;
      case "src":
        return <div className="px-3 py-1.5 truncate">{packet.src}:{packet.srcPort}</div>;
      case "dst":
        return <div className="px-3 py-1.5 truncate">{packet.dst}:{packet.dstPort}</div>;
      case "proto":
        return <div className="px-3 py-1.5">{protocolLabel}</div>;
      case "length":
        return <div className="px-3 py-1.5 tabular-nums">{packet.length}</div>;
      case "info":
      default:
        return <div className="px-3 py-1.5 truncate">{packet.info}</div>;
    }
  };

  return (
    <div
      className="flex h-full flex-col overflow-hidden"
      onClick={closeMenu}
      onContextMenu={(event) => {
        event.preventDefault();
        closeMenu();
      }}
    >
      <div className="sticky top-0 z-10 bg-accent text-muted-foreground shadow-[0_1px_0_0_var(--color-border)]">
        <div className="flex items-center justify-end border-b border-border px-2 py-1">
          <button
            className="inline-flex items-center gap-1 rounded border border-border bg-card px-2 py-0.5 text-[11px] text-muted-foreground hover:bg-accent"
            onClick={() => setShowColumnPanel((v) => !v)}
          >
            <Settings2 className="h-3.5 w-3.5" /> 列设置
          </button>
        </div>
        {showColumnPanel && (
          <div className="grid grid-cols-2 gap-2 border-b border-border bg-card p-2 text-[11px]">
            {columns.map((col) => (
              <label key={col.id} className="flex items-center gap-2 rounded border border-border px-2 py-1">
                <input
                  type="checkbox"
                  checked={col.visible}
                  onChange={() => toggleColumnVisible(col.id)}
                  className="accent-blue-600"
                />
                <input
                  value={col.label}
                  onChange={(event) => updateLabel(col.id, event.target.value)}
                  className="w-full border-none bg-transparent text-[11px] outline-none"
                />
              </label>
            ))}
            <button
              className="col-span-2 rounded border border-border bg-accent px-2 py-1 text-muted-foreground hover:bg-accent/80"
              onClick={resetColumns}
            >
              恢复默认列配置
            </button>
          </div>
        )}
        <div className="grid text-xs font-medium" style={{ gridTemplateColumns }}>
          {visibleColumns.map((col) => (
            <div key={col.id} className="relative border-r border-border px-3 py-2 last:border-r-0">
              {col.label}
              <div
                className="absolute right-0 top-0 h-full w-1.5 cursor-col-resize"
                onMouseDown={(event) => startResize(col.id, event)}
              />
            </div>
          ))}
        </div>
      </div>

      <div
        ref={viewportRef}
        className="flex-1 overflow-auto"
        onScroll={(event) => {
          const el = event.currentTarget;
          setScrollTop(el.scrollTop);
          const nearBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - ROW_HEIGHT * 8;
          if (nearBottom && hasMorePackets && onLoadMorePackets) {
            const now = Date.now();
            if (now >= loadMoreThrottleRef.current) {
              loadMoreThrottleRef.current = now + 180;
              onLoadMorePackets();
            }
          }
        }}
      >
        <div style={{ height: totalHeight, position: "relative" }}>
          {rows.map((packet, index) => {
            const absoluteIndex = startIndex + index;
            const top = absoluteIndex * ROW_HEIGHT;
            const selected = selectedPacketId === packet.id;
            const failureLevel = getCommunicationFailureLevel(packet);
            const packetColor = getPacketColorStyle(packet);

            return (
              <div
                key={`${packet.id}-${absoluteIndex}`}
                onClick={() => onSelect(packet.id)}
                onDoubleClick={() => packet.proto === "HTTP" && onDoubleClickHttp()}
                onContextMenu={(event) => {
                  event.preventDefault();
                  event.stopPropagation();
                  onSelect(packet.id);
                  openMenuAtEvent(event, packet);
                }}
                className={cn(
                  "grid border-b border-border/60 text-xs transition-colors",
                  selected
                    ? "bg-blue-600 text-white"
                    : packetColor
                      ? ""
                      : failureLevel === "critical"
                      ? "bg-rose-50 text-rose-900 hover:bg-rose-100"
                      : failureLevel === "major"
                        ? "bg-orange-50 text-orange-900 hover:bg-orange-100"
                        : failureLevel === "warn"
                          ? "bg-amber-50 text-amber-900 hover:bg-amber-100"
                          : "hover:bg-accent text-foreground",
                )}
                style={{
                  position: "absolute",
                  top,
                  left: 0,
                  right: 0,
                  height: ROW_HEIGHT,
                  gridTemplateColumns,
                  ...(selected
                    ? null
                    : packetColor
                      ? {
                        backgroundImage: packetColor.backgroundGradient,
                        backgroundColor: "transparent",
                        color: packetColor.color,
                      }
                      : null),
                }}
                title={selected ? undefined : packetColor?.ruleName}
              >
                {visibleColumns.map((col) => (
                  <div key={col.id} className="border-r border-border/60 last:border-r-0">
                    {renderCell(packet, col.id)}
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      </div>

      {menuPosition ? (
        <FloatingSurface
          floatingRef={menuRef}
          role="menu"
          className="w-48 py-1.5"
          x={menuPosition.x}
          y={menuPosition.y}
          onContextMenu={(event) => {
            event.preventDefault();
            event.stopPropagation();
          }}
          onPointerDown={(event) => event.stopPropagation()}
          onClick={(event) => event.stopPropagation()}
        >
          <button
            type="button"
            role="menuitem"
            className="w-full px-3 py-2 text-left font-medium text-slate-700 transition hover:bg-cyan-50 hover:text-cyan-700"
            onClick={() => {
              onFollowStream(menuPosition.context, "tcp");
              closeMenu();
            }}
          >
            追踪 TCP 流
          </button>
          <button
            type="button"
            role="menuitem"
            className="w-full px-3 py-2 text-left font-medium text-slate-700 transition hover:bg-cyan-50 hover:text-cyan-700"
            onClick={() => {
              onFollowStream(menuPosition.context, "udp");
              closeMenu();
            }}
          >
            追踪 UDP 流
          </button>
          <button
            type="button"
            role="menuitem"
            className="w-full px-3 py-2 text-left font-medium text-slate-700 transition hover:bg-cyan-50 hover:text-cyan-700"
            onClick={() => {
              onFollowStream(menuPosition.context, "http");
              closeMenu();
            }}
          >
            追踪 HTTP 会话
          </button>
        </FloatingSurface>
      ) : null}
    </div>
  );
}
