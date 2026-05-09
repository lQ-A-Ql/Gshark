import { useEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent } from "react";
import type { Packet } from "../core/types";
import { useViewportSafePosition } from "../hooks/useViewportSafePosition";
import {
  DEFAULT_COLUMNS,
  loadSavedColumns,
  saveColumns,
  type ColumnId,
  type ColumnSpec,
} from "./PacketVirtualTableColumns";
import { PacketVirtualTableHeader } from "./PacketVirtualTableHeader";
import { PacketVirtualTableMenu } from "./PacketVirtualTableMenu";
import { PacketVirtualTableRows } from "./PacketVirtualTableRows";

interface PacketVirtualTableProps {
  packets: Packet[];
  selectedPacketId: number | null;
  onSelect: (id: number) => void;
  onDoubleClickHttp: () => void;
  onFollowStream: (packet: Packet, target: "http" | "tcp" | "udp") => void;
  hasMorePackets?: boolean;
  onLoadMorePackets?: () => void;
}

const ROW_HEIGHT = 30;
const BUFFER = 10;
const CONTEXT_MENU_MARGIN = 12;
const CONTEXT_MENU_SIZE = { width: 192, height: 118 };

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
  const gridTemplateColumns = useMemo(() => visibleColumns.map((col) => `${col.width}px`).join(" "), [visibleColumns]);

  useEffect(() => {
    const handleMove = (event: MouseEvent) => {
      const resizing = resizingRef.current;
      if (!resizing) return;

      const diff = event.clientX - resizing.startX;
      const nextWidth = Math.max(64, resizing.startWidth + diff);
      setColumns((prev) => prev.map((col) => (col.id === resizing.id ? { ...col, width: nextWidth } : col)));
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
    saveColumns(columns);
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

  const openPacketContextMenu = (event: ReactMouseEvent<HTMLDivElement>, packet: Packet) => {
    event.preventDefault();
    event.stopPropagation();
    onSelect(packet.id);
    openMenuAtEvent(event, packet);
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
      <PacketVirtualTableHeader
        columns={columns}
        visibleColumns={visibleColumns}
        gridTemplateColumns={gridTemplateColumns}
        showColumnPanel={showColumnPanel}
        onToggleColumnPanel={() => setShowColumnPanel((value) => !value)}
        onToggleColumnVisible={toggleColumnVisible}
        onUpdateLabel={updateLabel}
        onResetColumns={resetColumns}
        onStartResize={startResize}
      />

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
          <PacketVirtualTableRows
            rows={rows}
            rowHeight={ROW_HEIGHT}
            startIndex={startIndex}
            selectedPacketId={selectedPacketId}
            visibleColumns={visibleColumns}
            gridTemplateColumns={gridTemplateColumns}
            onSelect={onSelect}
            onDoubleClickHttp={onDoubleClickHttp}
            onOpenContextMenu={openPacketContextMenu}
          />
        </div>
      </div>

      <PacketVirtualTableMenu
        menuRef={menuRef}
        menuPosition={menuPosition}
        onFollowStream={onFollowStream}
        onClose={closeMenu}
      />
    </div>
  );
}
