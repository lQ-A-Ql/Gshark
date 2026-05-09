import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import type { USBPacketRecord } from "../../core/types";
import {
  USB_MONO_CELL_CLASS,
  USB_TABLE_HEADER_CLASS,
  USB_TABLE_ROW_CLASS,
  USB_TABLE_WRAPPER_CLASS,
} from "./UsbTableStyles";
import { joinParts } from "./UsbTableUtils";

export { KeyboardEventTable, MouseEventTable } from "./UsbHidTables";
export { MassStorageFilters, MassStorageOperationTable } from "./UsbMassStorageTables";

export function ControlRequestTable({ rows }: { rows: USBPacketRecord[] }) {
  return (
    <DataTable<USBPacketRecord>
      data={rows}
      rowKey={(row, index) => `${row.packetId}-${row.summary}-${index}`}
      maxHeightClassName="max-h-[560px]"
      wrapperClassName={USB_TABLE_WRAPPER_CLASS}
      headerClassName={USB_TABLE_HEADER_CLASS}
      tableClassName="min-w-[880px]"
      rowClassName={USB_TABLE_ROW_CLASS}
      emptyText="暂无控制请求"
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
          widthClassName: "w-24",
          render: (row) => joinParts(row.busId, row.deviceAddress),
        },
        { key: "direction", header: "方向", widthClassName: "w-24", render: (row) => row.direction || "--" },
        { key: "status", header: "状态", widthClassName: "w-28", render: (row) => row.status || "--" },
        { key: "setup", header: "Setup 请求", widthClassName: "w-44", render: (row) => row.setupRequest || "--" },
        {
          key: "summary",
          header: "摘要 / Payload",
          render: (row) => (
            <div>
              <div>{row.summary || "--"}</div>
              {row.payloadPreview && (
                <div className="mt-1 break-all font-mono text-[11px] text-slate-500">{row.payloadPreview}</div>
              )}
            </div>
          ),
        },
      ]}
    />
  );
}

export function USBRecordTable({ rows }: { rows: USBPacketRecord[] }) {
  return (
    <DataTable<USBPacketRecord>
      data={rows}
      rowKey={(item, index) => `${item.packetId}-${item.endpoint}-${item.summary}-${index}`}
      maxHeightClassName="max-h-[560px]"
      wrapperClassName={USB_TABLE_WRAPPER_CLASS}
      headerClassName={USB_TABLE_HEADER_CLASS}
      tableClassName="min-w-[1160px]"
      rowClassName={USB_TABLE_ROW_CLASS}
      emptyText="暂无其他 USB 记录"
      columns={[
        {
          key: "packet",
          header: "包号",
          widthClassName: "w-20",
          cellClassName: USB_MONO_CELL_CLASS,
          render: (item) => item.packetId,
        },
        {
          key: "time",
          header: "时间",
          widthClassName: "w-28",
          cellClassName: USB_MONO_CELL_CLASS,
          render: (item) => item.time || "--",
        },
        { key: "protocol", header: "协议", widthClassName: "w-24", render: (item) => item.protocol || "--" },
        {
          key: "device",
          header: "设备",
          widthClassName: "w-28",
          render: (item) => joinParts(item.busId, item.deviceAddress),
        },
        {
          key: "endpoint",
          header: "端点",
          widthClassName: "w-28",
          cellClassName: USB_MONO_CELL_CLASS,
          render: (item) => item.endpoint || "--",
        },
        { key: "direction", header: "方向", widthClassName: "w-20", render: (item) => item.direction || "--" },
        { key: "transfer", header: "传输", widthClassName: "w-24", render: (item) => item.transferType || "--" },
        { key: "urb", header: "URB", widthClassName: "w-24", render: (item) => item.urbType || "--" },
        { key: "status", header: "状态", widthClassName: "w-24", render: (item) => item.status || "--" },
        {
          key: "length",
          header: "长度",
          widthClassName: "w-20",
          cellClassName: USB_MONO_CELL_CLASS,
          render: (item) => item.dataLength,
        },
        { key: "setup", header: "Setup", widthClassName: "w-28", render: (item) => item.setupRequest || "--" },
        {
          key: "summary",
          header: "摘要",
          render: (item) => (
            <div>
              <div>{item.summary || "--"}</div>
              {item.payloadPreview && (
                <div className="mt-1 break-all font-mono text-[11px] text-slate-500">{item.payloadPreview}</div>
              )}
            </div>
          ),
        },
      ]}
    />
  );
}
