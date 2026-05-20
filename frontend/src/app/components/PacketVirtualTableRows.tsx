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
              "gshark-packet-row grid text-xs transition-[box-shadow,background-color,background-image,color]",
              packetColor
                ? "gshark-packet-row-colored"
                : failureLevel === "critical"
                  ? "gshark-packet-row-failure-critical"
                  : failureLevel === "major"
                    ? "gshark-packet-row-failure-major"
                    : failureLevel === "warn"
                      ? "gshark-packet-row-failure-warn"
                      : "text-foreground",
              !selected && !packetColor && !failureLevel && "gshark-packet-row-neutral",
              selected && "gshark-packet-row-selected",
            )}
            style={{
              position: "absolute",
              top,
              left: 0,
              right: 0,
              height: rowHeight,
              gridTemplateColumns,
              ...(packetColor
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
              <div key={col.id} className="gshark-packet-cell">
                {renderPacketCell(packet, col.id)}
              </div>
            ))}
          </div>
        );
      })}
    </>
  );
}
