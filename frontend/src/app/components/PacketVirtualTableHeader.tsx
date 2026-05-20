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
    <div className="gshark-packet-header sticky top-0 z-10 text-muted-foreground">
      <div className="gshark-packet-header-toolbar flex items-center justify-end px-2 py-1">
        <button
          className="gshark-control gshark-packet-action inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium transition"
          onClick={onToggleColumnPanel}
        >
          <Settings2 className="h-3.5 w-3.5" /> 列设置
        </button>
      </div>
      {showColumnPanel && (
        <div className="gshark-packet-column-panel grid grid-cols-2 gap-2 p-2 text-[11px]">
          {columns.map((col) => (
            <label key={col.id} className="gshark-packet-column-row flex items-center gap-2 px-2 py-1">
              <input
                type="checkbox"
                checked={col.visible}
                onChange={() => onToggleColumnVisible(col.id)}
                className="gshark-checkbox"
              />
              <input
                value={col.label}
                onChange={(event) => onUpdateLabel(col.id, event.target.value)}
                className="w-full border-none bg-transparent text-[11px] outline-none"
              />
            </label>
          ))}
          <button
            className="gshark-control gshark-packet-action col-span-2 px-2 py-1 text-muted-foreground transition"
            onClick={onResetColumns}
          >
            恢复默认列配置
          </button>
        </div>
      )}
      <div className="grid text-xs font-medium" style={{ gridTemplateColumns }}>
        {visibleColumns.map((col) => (
          <div key={col.id} className="gshark-packet-header-cell relative px-3 py-2">
            {col.label}
            <div
              className="gshark-packet-resize-handle absolute right-0 top-0 h-full w-1.5 cursor-col-resize"
              onMouseDown={(event) => onStartResize(col.id, event)}
            />
          </div>
        ))}
      </div>
    </div>
  );
}
