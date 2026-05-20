import { Workflow } from "lucide-react";
import {
  AnalysisCallout,
  AnalysisDataTable as DataTable,
  AnalysisPanel as Panel,
} from "../../components/analysis/AnalysisPrimitives";
import type { ModbusDecodedInput } from "../../core/types";
import { EvidenceActions } from "../../misc/EvidenceActions";

export function ModbusDecodedInputsPanel({ decodedInputs }: { decodedInputs: ModbusDecodedInput[] }) {
  return (
    <Panel title={`Modbus UTF-8 输入重组 (${decodedInputs.length})`} className="mt-0">
      <AnalysisCallout className="mb-2" tone="blue" icon={<Workflow className="h-4 w-4" />}>
        将连续写寄存器中的 ASCII 数值按时间顺序重组；若重组结果本身是十六进制文本，则继续转为 UTF-8 显示。
      </AnalysisCallout>
      <DataTable
        columns={[
          {
            key: "range",
            header: "包范围",
            widthClassName: "w-28",
            cellClassName: "font-mono text-slate-500",
            render: (item) => `${item.startPacketId}-${item.endPacketId}`,
          },
          { key: "source", header: "源", widthClassName: "w-36", render: (item) => item.source || "--" },
          { key: "destination", header: "目标", widthClassName: "w-36", render: (item) => item.destination || "--" },
          {
            key: "function",
            header: "功能码",
            widthClassName: "w-28",
            render: (item) => (
              <div>
                <div className="font-mono">{item.functionCode || "--"}</div>
                <div className="text-slate-500">{item.functionName || "--"}</div>
              </div>
            ),
          },
          {
            key: "encoding",
            header: "编码",
            widthClassName: "w-32",
            cellClassName: "font-mono text-blue-700",
            render: (item) => item.encoding || "--",
          },
          {
            key: "text",
            header: "输入内容",
            render: (item) => (
              <div className="max-h-32 overflow-y-auto rounded border border-emerald-100 bg-emerald-50/70 px-2 py-1 font-mono text-[11px] text-emerald-800">
                <div className="whitespace-pre-wrap break-words">{item.text}</div>
                {item.rawText && item.rawText !== item.text && (
                  <div className="mt-1 border-t border-emerald-100 pt-1 text-emerald-700/75">
                    原始 ASCII: <span className="whitespace-pre-wrap break-words">{item.rawText}</span>
                  </div>
                )}
              </div>
            ),
          },
          {
            key: "actions",
            header: "定位",
            widthClassName: "w-16",
            render: (item) => (item.startPacketId ? <EvidenceActions packetId={item.startPacketId} /> : "--"),
          },
        ]}
        data={decodedInputs}
        rowKey={(item, idx) => `decoded-input-${item.startPacketId}-${item.endPacketId}-${idx}`}
        maxHeightClassName="max-h-[420px]"
        tableClassName="min-w-[1120px]"
        emptyText="暂无可重组 UTF-8 输入"
      />
    </Panel>
  );
}
