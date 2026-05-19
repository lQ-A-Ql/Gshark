import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import type { USBKeyboardEvent } from "../../core/types";
import { HIDTableShell, useVisibleRows } from "./UsbHidTablesShell";
import {
  USB_MONO_CELL_CLASS,
  USB_TABLE_HEADER_CLASS,
  USB_TABLE_ROW_CLASS,
  USB_TABLE_WRAPPER_CLASS,
} from "./UsbTableStyles";
export { MouseEventTable } from "./UsbMouseEventTable";

export function KeyboardEventTable({ rows, resetKey = "" }: { rows: USBKeyboardEvent[]; resetKey?: string }) {
  const visibleState = useVisibleRows(rows, resetKey);

  return (
    <HIDTableShell visibleState={visibleState}>
      <DataTable<USBKeyboardEvent>
        data={visibleState.visibleRows}
        rowKey={(row, index) => `${row.packetId}-${row.summary}-${index}`}
        maxHeightClassName="max-h-[520px]"
        wrapperClassName={USB_TABLE_WRAPPER_CLASS}
        headerClassName={USB_TABLE_HEADER_CLASS}
        tableClassName="min-w-[1180px]"
        rowClassName={USB_TABLE_ROW_CLASS}
        emptyText="暂无键盘行为"
        columns={[
          {
            key: "packet",
            header: "包号",
            widthClassName: "w-20",
            cellClassName: USB_MONO_CELL_CLASS,
            render: (row) => row.packetId,
          },
          {
            key: "time",
            header: "时间",
            widthClassName: "w-28",
            cellClassName: USB_MONO_CELL_CLASS,
            render: (row) => row.time || "--",
          },
          {
            key: "device",
            header: "设备",
            widthClassName: "w-40",
            render: (row) => row.device || row.endpoint || "--",
          },
          {
            key: "modifiers",
            header: "当前修饰键",
            widthClassName: "w-28",
            render: (row) => row.modifiers.join(", ") || "--",
          },
          {
            key: "pressedModifiers",
            header: "按下修饰键",
            widthClassName: "w-28",
            render: (row) => row.pressedModifiers.join(", ") || "--",
          },
          {
            key: "releasedModifiers",
            header: "释放修饰键",
            widthClassName: "w-28",
            render: (row) => row.releasedModifiers.join(", ") || "--",
          },
          { key: "keys", header: "当前按键", widthClassName: "w-32", render: (row) => row.keys.join(", ") || "--" },
          {
            key: "pressedKeys",
            header: "按下键",
            widthClassName: "w-32",
            render: (row) => row.pressedKeys.join(", ") || "--",
          },
          {
            key: "releasedKeys",
            header: "释放键",
            widthClassName: "w-32",
            render: (row) => row.releasedKeys.join(", ") || "--",
          },
          {
            key: "text",
            header: "文本",
            widthClassName: "w-24",
            cellClassName: "whitespace-pre-wrap font-mono text-slate-600",
            render: (row) => row.text || "--",
          },
          { key: "summary", header: "摘要", render: (row) => row.summary || "--" },
        ]}
      />
    </HIDTableShell>
  );
}
