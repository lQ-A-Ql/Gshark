import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import type { USBMouseEvent } from "../../core/types";
import { HIDTableShell, useVisibleRows } from "./UsbHidTablesShell";
import {
  USB_MONO_CELL_CLASS,
  USB_TABLE_HEADER_CLASS,
  USB_TABLE_ROW_CLASS,
  USB_TABLE_WRAPPER_CLASS,
} from "./UsbTableStyles";

export function MouseEventTable({ rows, resetKey = "" }: { rows: USBMouseEvent[]; resetKey?: string }) {
  const visibleState = useVisibleRows(rows, resetKey);

  return (
    <HIDTableShell visibleState={visibleState}>
      <DataTable<USBMouseEvent>
        data={visibleState.visibleRows}
        rowKey={(row, index) => `${row.packetId}-${row.positionX}-${row.positionY}-${index}`}
        maxHeightClassName="max-h-[520px]"
        wrapperClassName={USB_TABLE_WRAPPER_CLASS}
        headerClassName={USB_TABLE_HEADER_CLASS}
        tableClassName="min-w-[1420px]"
        rowClassName={USB_TABLE_ROW_CLASS}
        emptyText="暂无鼠标行为"
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
          { key: "device", header: "设备", widthClassName: "w-36", render: (row) => row.device || row.endpoint || "--" },
          { key: "buttons", header: "当前按钮", widthClassName: "w-28", render: (row) => row.buttons.join(", ") || "--" },
          { key: "source", header: "来源", widthClassName: "w-32", render: (row) => row.source || "--" },
          { key: "layout", header: "布局", widthClassName: "w-28", render: (row) => row.layout || "--" },
          {
            key: "pressedButtons",
            header: "按下按钮",
            widthClassName: "w-28",
            render: (row) => row.pressedButtons.join(", ") || "--",
          },
          {
            key: "releasedButtons",
            header: "释放按钮",
            widthClassName: "w-28",
            render: (row) => row.releasedButtons.join(", ") || "--",
          },
          {
            key: "xDelta",
            header: "dX",
            widthClassName: "w-20",
            cellClassName: USB_MONO_CELL_CLASS,
            render: (row) => row.xDelta,
          },
          {
            key: "yDelta",
            header: "dY",
            widthClassName: "w-20",
            cellClassName: USB_MONO_CELL_CLASS,
            render: (row) => row.yDelta,
          },
          {
            key: "wheelVertical",
            header: "滚轮V",
            widthClassName: "w-20",
            cellClassName: USB_MONO_CELL_CLASS,
            render: (row) => row.wheelVertical,
          },
          {
            key: "wheelHorizontal",
            header: "滚轮H",
            widthClassName: "w-20",
            cellClassName: USB_MONO_CELL_CLASS,
            render: (row) => row.wheelHorizontal,
          },
          {
            key: "positionX",
            header: "X",
            widthClassName: "w-24",
            cellClassName: USB_MONO_CELL_CLASS,
            render: (row) => row.positionX,
          },
          {
            key: "positionY",
            header: "Y",
            widthClassName: "w-24",
            cellClassName: USB_MONO_CELL_CLASS,
            render: (row) => row.positionY,
          },
          { key: "summary", header: "摘要", render: (row) => row.summary || "--" },
        ]}
      />
    </HIDTableShell>
  );
}
