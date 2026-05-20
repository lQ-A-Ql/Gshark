import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import { SelectField as GlobalSelectField, type SelectOption } from "../../components/ui/select";
import type { USBMassStorageOperation } from "../../core/types";
import {
  USB_MONO_CELL_CLASS,
  USB_TABLE_HEADER_CLASS,
  USB_TABLE_ROW_CLASS,
  USB_TABLE_WRAPPER_CLASS,
} from "./UsbTableStyles";

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
    <div className="gshark-tile-toolbar grid grid-cols-1 gap-3 p-3 md:grid-cols-2">
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
  const selectOptions: SelectOption[] = options.map((option) => ({
    value: option,
    label: labels[option] ?? option,
  }));

  return (
    <GlobalSelectField
      label={label}
      value={value}
      onValueChange={onChange}
      options={selectOptions}
      tone="blue"
      triggerClassName="bg-transparent text-sm"
      labelClassName="font-medium text-muted-foreground"
    />
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
