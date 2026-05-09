import { clsx } from "clsx";
import type { MouseEvent as ReactMouseEvent } from "react";
import { twMerge } from "tailwind-merge";
import type { Packet } from "../core/types";
import { getPacketColorStyle } from "../core/packetColoring";
import { getCommunicationFailureLevel, renderPacketCell, type ColumnSpec } from "./PacketVirtualTableColumns";

function cn(...inputs: (string | undefined | null | false)[]) {
  return twMerge(clsx(inputs));
}

type PacketVirtualTableRowsProps = {
  rows: Packet[];
  rowHeight: number;
  startIndex: number;
  selectedPacketId: number | null;
  visibleColumns: ColumnSpec[];
  gridTemplateColumns: string;
  onSelect: (id: number) => void;
  onDoubleClickHttp: () => void;
  onOpenContextMenu: (event: ReactMouseEvent<HTMLDivElement>, packet: Packet) => void;
};

export function PacketVirtualTableRows({
  rows,
  rowHeight,
  startIndex,
  selectedPacketId,
  visibleColumns,
  gridTemplateColumns,
  onSelect,
  onDoubleClickHttp,
  onOpenContextMenu,
}: PacketVirtualTableRowsProps) {
  return (
    <>
      {rows.map((packet, index) => {
        const absoluteIndex = startIndex + index;
        const top = absoluteIndex * rowHeight;
        const selected = selectedPacketId === packet.id;
        const failureLevel = getCommunicationFailureLevel(packet);
        const packetColor = getPacketColorStyle(packet);

        return (
          <div
            key={`${packet.id}-${absoluteIndex}`}
            onClick={() => onSelect(packet.id)}
            onDoubleClick={() => packet.proto === "HTTP" && onDoubleClickHttp()}
            onContextMenu={(event) => onOpenContextMenu(event, packet)}
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
              height: rowHeight,
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
                {renderPacketCell(packet, col.id)}
              </div>
            ))}
          </div>
        );
      })}
    </>
  );
}
