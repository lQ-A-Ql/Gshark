import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import type { USBKeyboardEvent, USBMassStorageOperation, USBMouseEvent, USBPacketRecord } from "../../core/types";

const USB_TABLE_WRAPPER_CLASS = "border-slate-200 bg-white shadow-sm";
const USB_TABLE_HEADER_CLASS = "bg-gradient-to-r from-slate-100 to-blue-50 text-slate-700";
const USB_TABLE_ROW_CLASS = "last:border-b-0 odd:bg-white even:bg-slate-50/45 hover:bg-blue-50/45";
const USB_MONO_CELL_CLASS = "font-mono text-slate-600";

export function KeyboardEventTable({ rows }: { rows: USBKeyboardEvent[] }) {
  return (
    <DataTable<USBKeyboardEvent>
      data={rows}
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
        { key: "device", header: "设备", widthClassName: "w-40", render: (row) => row.device || row.endpoint || "--" },
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
  );
}

export function MouseEventTable({ rows }: { rows: USBMouseEvent[] }) {
  return (
    <DataTable<USBMouseEvent>
      data={rows}
      rowKey={(row, index) => `${row.packetId}-${row.positionX}-${row.positionY}-${index}`}
      maxHeightClassName="max-h-[520px]"
      wrapperClassName={USB_TABLE_WRAPPER_CLASS}
      headerClassName={USB_TABLE_HEADER_CLASS}
      tableClassName="min-w-[1260px]"
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
  );
}

export function MassStorageFilters({
  devices,
  luns,
  activeDevice,
  activeLun,
  onDeviceChange,
  onLunChange,
}: {
  devices: string[];
  luns: string[];
  activeDevice: string;
  activeLun: string;
  onDeviceChange: (value: string) => void;
  onLunChange: (value: string) => void;
}) {
  return (
    <div className="grid grid-cols-1 gap-4 rounded-xl border border-border bg-card p-4 shadow-sm md:grid-cols-2">
      <SelectField
        label="设备"
        value={activeDevice}
        onChange={onDeviceChange}
        options={["all", ...devices]}
        labels={{ all: "全部设备" }}
      />
      <SelectField
        label="LUN"
        value={activeLun}
        onChange={onLunChange}
        options={["all", ...luns]}
        labels={{ all: "全部 LUN" }}
      />
    </div>
  );
}

function SelectField({
  label,
  value,
  onChange,
  options,
  labels = {},
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: string[];
  labels?: Record<string, string>;
}) {
  return (
    <label className="flex flex-col gap-2 text-xs text-muted-foreground">
      <span>{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground outline-none ring-0 transition-colors focus:border-blue-500"
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {labels[option] ?? option}
          </option>
        ))}
      </select>
    </label>
  );
}

export function MassStorageOperationTable({ rows }: { rows: USBMassStorageOperation[] }) {
  return (
    <DataTable<USBMassStorageOperation>
      data={rows}
      rowKey={(row, index) => `${row.packetId}-${row.requestFrame}-${row.responseFrame}-${index}`}
      maxHeightClassName="max-h-[560px]"
      wrapperClassName={USB_TABLE_WRAPPER_CLASS}
      headerClassName={USB_TABLE_HEADER_CLASS}
      tableClassName="min-w-[1180px]"
      rowClassName={USB_TABLE_ROW_CLASS}
      emptyText="暂无读写行为记录"
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
          widthClassName: "w-24",
          cellClassName: USB_MONO_CELL_CLASS,
          render: (row) => row.time || "--",
        },
        { key: "device", header: "设备", widthClassName: "w-36", render: (row) => row.device || "--" },
        {
          key: "endpoint",
          header: "端点",
          widthClassName: "w-24",
          cellClassName: USB_MONO_CELL_CLASS,
          render: (row) => row.endpoint || "--",
        },
        { key: "lun", header: "LUN", widthClassName: "w-20", render: (row) => row.lun || "--" },
        { key: "command", header: "命令", widthClassName: "w-28", render: (row) => row.command || "--" },
        {
          key: "length",
          header: "长度",
          widthClassName: "w-16",
          cellClassName: USB_MONO_CELL_CLASS,
          render: (row) => row.transferLength,
        },
        { key: "status", header: "状态", widthClassName: "w-20", render: (row) => row.status || "--" },
        {
          key: "requestFrame",
          header: "请求帧",
          widthClassName: "w-20",
          cellClassName: USB_MONO_CELL_CLASS,
          render: (row) => row.requestFrame ?? "--",
        },
        {
          key: "responseFrame",
          header: "响应帧",
          widthClassName: "w-20",
          cellClassName: USB_MONO_CELL_CLASS,
          render: (row) => row.responseFrame ?? "--",
        },
        {
          key: "latency",
          header: "延迟",
          widthClassName: "w-20",
          cellClassName: USB_MONO_CELL_CLASS,
          render: (row) => (row.latencyMs == null ? "--" : `${row.latencyMs.toFixed(2)} ms`),
        },
        {
          key: "summary",
          header: "摘要",
          render: (row) => (
            <div>
              <div>{row.summary || "--"}</div>
              {row.dataResidue != null && row.dataResidue > 0 && (
                <div className="mt-1 font-mono text-[11px] text-amber-600">residue={row.dataResidue}</div>
              )}
            </div>
          ),
        },
      ]}
    />
  );
}

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

function joinParts(busId: string, deviceAddress: string) {
  const parts = [busId && `bus ${busId}`, deviceAddress && `dev ${deviceAddress}`].filter(Boolean);
  return parts.length > 0 ? parts.join(" / ") : "--";
}
