import { Settings2 } from "lucide-react";
import type { MouseEvent as ReactMouseEvent } from "react";
import type { ColumnId, ColumnSpec } from "./PacketVirtualTableColumns";

type PacketVirtualTableHeaderProps = {
  columns: ColumnSpec[];
  visibleColumns: ColumnSpec[];
  gridTemplateColumns: string;
  showColumnPanel: boolean;
  onToggleColumnPanel: () => void;
  onToggleColumnVisible: (id: ColumnId) => void;
  onUpdateLabel: (id: ColumnId, label: string) => void;
  onResetColumns: () => void;
  onStartResize: (id: ColumnId, event: ReactMouseEvent<HTMLDivElement>) => void;
};

export function PacketVirtualTableHeader({
  columns,
  visibleColumns,
  gridTemplateColumns,
  showColumnPanel,
  onToggleColumnPanel,
  onToggleColumnVisible,
  onUpdateLabel,
  onResetColumns,
  onStartResize,
}: PacketVirtualTableHeaderProps) {
  return (
    <div className="sticky top-0 z-10 bg-accent text-muted-foreground shadow-[0_1px_0_0_var(--color-border)]">
      <div className="flex items-center justify-end border-b border-border px-2 py-1">
        <button
          className="inline-flex items-center gap-1 rounded border border-border bg-card px-2 py-0.5 text-[11px] text-muted-foreground hover:bg-accent"
          onClick={onToggleColumnPanel}
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
                onChange={() => onToggleColumnVisible(col.id)}
                className="accent-blue-600"
              />
              <input
                value={col.label}
                onChange={(event) => onUpdateLabel(col.id, event.target.value)}
                className="w-full border-none bg-transparent text-[11px] outline-none"
              />
            </label>
          ))}
          <button
            className="col-span-2 rounded border border-border bg-accent px-2 py-1 text-muted-foreground hover:bg-accent/80"
            onClick={onResetColumns}
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
              onMouseDown={(event) => onStartResize(col.id, event)}
            />
          </div>
        ))}
      </div>
    </div>
  );
}
