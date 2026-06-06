import { Shield } from "lucide-react";
import type { IndustrialControlCommand } from "../../core/types";
import { AnalysisBadge, AnalysisCallout, AnalysisDataTable as DataTable, AnalysisPanel as Panel } from "../../components/analysis/AnalysisPrimitives";

export function IndustrialControlCommandsPanel({ commands }: { commands: IndustrialControlCommand[] }) {
  if (commands.length === 0) return null;
  return (
    <Panel title={`控制指令 (${commands.length})`} className="mt-0">
      <AnalysisCallout className="mb-2" tone="rose" icon={<Shield className="h-4 w-4" />}>
        以下为从 IEC 104、DNP3、BACnet 等协议中提取的控制/操作类指令，可能涉及遥控、设点或设备重启。
      </AnalysisCallout>
      <DataTable
        columns={[
          { key: "packet", header: "包号", widthClassName: "w-20", cellClassName: "font-mono text-slate-500", render: (cmd) => cmd.packetId },
          { key: "time", header: "时间", widthClassName: "w-28", cellClassName: "font-mono", render: (cmd) => cmd.time || "--" },
          { key: "protocol", header: "协议", widthClassName: "w-20", render: (cmd) => <AnalysisBadge tone="blue">{cmd.protocol}</AnalysisBadge> },
          { key: "source", header: "源", widthClassName: "w-32", render: (cmd) => cmd.source || "--" },
          { key: "destination", header: "目标", widthClassName: "w-32", render: (cmd) => cmd.destination || "--" },
          { key: "operation", header: "操作", widthClassName: "w-36", cellClassName: "font-mono font-semibold text-rose-700", render: (cmd) => cmd.operation || "--" },
          { key: "target", header: "对象", widthClassName: "w-28", cellClassName: "font-mono", render: (cmd) => cmd.target || "--" },
          { key: "value", header: "值", widthClassName: "w-24", cellClassName: "font-mono", render: (cmd) => cmd.value || "--" },
          { key: "result", header: "结果", widthClassName: "w-24", render: (cmd) => cmd.result || "--" },
          { key: "summary", header: "摘要", render: (cmd) => cmd.summary || "--" },
        ]}
        data={commands}
        rowKey={(_cmd, idx) => `cmd-${idx}`}
        maxHeightClassName="max-h-[520px]"
        tableClassName="min-w-[1120px]"
        emptyText="暂无控制指令"
      />
    </Panel>
  );
}
