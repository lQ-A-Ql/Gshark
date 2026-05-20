import type { USBMouseEvent } from "../../core/types";
import { UsbHidEmptyState } from "./UsbHidEmptyState";
import { mouseActionBadge } from "./usbHidRules";

export function MouseBehaviorList({ rows }: { rows: USBMouseEvent[] }) {
  if (rows.length === 0) {
    return <UsbHidEmptyState>暂无鼠标行为</UsbHidEmptyState>;
  }
  return (
    <div className="max-h-[320px] divide-y divide-slate-200/45 overflow-auto">
      {rows.map((row) => (
        <div
          key={`${row.packetId}-${row.positionX}-${row.positionY}`}
          className="px-3 py-2 text-xs"
        >
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono text-muted-foreground">
              #{row.packetId} {row.time}
            </span>
            <span className="rounded border border-border px-2 py-0.5 text-[11px]">{mouseActionBadge(row)}</span>
          </div>
          <div className="mt-1 text-foreground">{row.summary}</div>
          <div className="mt-1 font-mono text-[11px] text-muted-foreground">
            pos=({row.positionX}, {row.positionY}) / delta=({row.xDelta}, {row.yDelta})
          </div>
        </div>
      ))}
    </div>
  );
}
