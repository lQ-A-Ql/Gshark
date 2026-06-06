import { Shield } from "lucide-react";
import type { IndustrialRuleHit } from "../../core/types";
import { AnalysisBadge, AnalysisCallout, AnalysisDataTable as DataTable, AnalysisPanel as Panel } from "../../components/analysis/AnalysisPrimitives";
import { toneForIndustrialRuleLevel } from "./industrialToneRules";

export function IndustrialRuleHitsPanel({ ruleHits }: { ruleHits: IndustrialRuleHit[] }) {
  if (ruleHits.length === 0) return null;
  return (
    <Panel title={`规则检测 / Modbus 异常命中 (${ruleHits.length})`} className="mt-0">
      <AnalysisCallout className="mb-2" tone="blue" icon={<Shield className="h-4 w-4" />}>
        基于主从角色、功能码、数量字段、位长度一致性和高频写入行为生成规则命中，可直接定位可疑包与目标地址。
      </AnalysisCallout>
      <DataTable
        columns={[
          { key: "level", header: "等级", widthClassName: "w-20", render: (item) => <AnalysisBadge tone={toneForIndustrialRuleLevel(item.level)}>{item.level || "info"}</AnalysisBadge> },
          { key: "rule", header: "规则", widthClassName: "w-28", cellClassName: "font-medium", render: (item) => item.rule },
          { key: "packet", header: "包号", widthClassName: "w-20", cellClassName: "font-mono text-slate-500", render: (item) => item.packetId || "--" },
          { key: "time", header: "时间", widthClassName: "w-28", cellClassName: "font-mono", render: (item) => item.time || "--" },
          { key: "source", header: "源", widthClassName: "w-32", cellClassName: "break-all", render: (item) => item.source || "--" },
          { key: "destination", header: "目标", widthClassName: "w-32", cellClassName: "break-all", render: (item) => item.destination || "--" },
          { key: "function", header: "功能码", widthClassName: "w-24", render: (item) => item.functionCode != null ? <div><div className="font-mono">{String(item.functionCode).padStart(2, "0")}</div>{item.functionName && <div className="text-slate-500">{item.functionName}</div>}</div> : "--" },
          { key: "target", header: "对象", widthClassName: "w-32", cellClassName: "break-all font-mono", render: (item) => item.target || "--" },
          { key: "evidence", header: "证据", widthClassName: "w-40", cellClassName: "break-all font-mono text-[11px] text-slate-500", render: (item) => item.evidence || "--" },
          { key: "summary", header: "摘要", render: (item) => item.summary || "--" },
        ]}
        data={ruleHits}
        rowKey={(item, idx) => `${item.rule}-${item.packetId}-${idx}`}
        maxHeightClassName="max-h-[460px]"
        tableClassName="min-w-[1120px]"
        emptyText="暂无规则命中"
      />
    </Panel>
  );
}
