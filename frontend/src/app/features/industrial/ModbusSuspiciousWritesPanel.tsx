import { AlertTriangle } from "lucide-react";
import {
  AnalysisCallout,
  AnalysisDataTable as DataTable,
  AnalysisPanel as Panel,
} from "../../components/analysis/AnalysisPrimitives";
import type { ModbusSuspiciousWrite } from "../../core/types";
import { EvidenceActions } from "../../misc/EvidenceActions";

export function ModbusSuspiciousWritesPanel({ suspiciousWrites }: { suspiciousWrites: ModbusSuspiciousWrite[] }) {
  return (
    <Panel title={`Modbus 可疑写操作 (${suspiciousWrites.length})`} className="mt-4">
      <AnalysisCallout className="mb-2" tone="amber" icon={<AlertTriangle className="h-4 w-4" />}>
        以下为按写入次数排序的 Modbus 写操作聚合，高频写入可能对应灯控、阀门切换或寄存器篡改。
      </AnalysisCallout>
      <DataTable
        columns={[
          {
            key: "target",
            header: "目标地址",
            widthClassName: "w-36",
            cellClassName: "font-mono",
            render: (sw) => sw.target,
          },
          {
            key: "unit",
            header: "Unit ID",
            widthClassName: "w-20",
            cellClassName: "font-mono",
            render: (sw) => sw.unitId || "--",
          },
          {
            key: "function",
            header: "功能码",
            widthClassName: "w-28",
            render: (sw) => (
              <div>
                <div className="font-mono">{String(sw.functionCode).padStart(2, "0")}</div>
                <div className="text-slate-500">{sw.functionName}</div>
              </div>
            ),
          },
          {
            key: "count",
            header: "写入次数",
            widthClassName: "w-20",
            cellClassName: "font-mono font-semibold text-amber-700",
            render: (sw) => sw.writeCount,
          },
          {
            key: "sources",
            header: "来源 IP",
            widthClassName: "w-36",
            cellClassName: "font-mono",
            render: (sw) => sw.sources.join(", ") || "--",
          },
          {
            key: "first",
            header: "首次时间",
            widthClassName: "w-28",
            cellClassName: "font-mono",
            render: (sw) => sw.firstTime || "--",
          },
          {
            key: "last",
            header: "末次时间",
            widthClassName: "w-28",
            cellClassName: "font-mono",
            render: (sw) => sw.lastTime || "--",
          },
          {
            key: "samples",
            header: "样本值",
            render: (sw) =>
              sw.sampleValues.length > 0 ? (
                <div className="space-y-0.5">
                  {sw.sampleValues.map((value, valueIndex) => (
                    <div key={valueIndex} className="break-all font-mono text-[11px] text-slate-500">
                      {value}
                    </div>
                  ))}
                </div>
              ) : (
                "--"
              ),
          },
          {
            key: "actions",
            header: "定位",
            widthClassName: "w-16",
            render: (sw) => (sw.samplePacketId ? <EvidenceActions packetId={sw.samplePacketId} /> : "--"),
          },
        ]}
        data={suspiciousWrites}
        rowKey={(_sw, idx) => `sw-${idx}`}
        maxHeightClassName="max-h-[420px]"
        tableClassName="min-w-[920px]"
        emptyText="暂无可疑写操作"
      />
    </Panel>
  );
}
