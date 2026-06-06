import { Shield } from "lucide-react";
import type { IndustrialControlCommand, IndustrialProtocolDetail, IndustrialRuleHit } from "../../core/types";
import {
  AnalysisBadge,
  AnalysisBucketChart as BucketChart,
  AnalysisCallout,
  AnalysisDataTable as DataTable,
  AnalysisPanel as Panel,
  AnalysisStatCard as StatCard,
} from "../../components/analysis/AnalysisPrimitives";
import { deriveIndustrialDnp3Section } from "./industrialDnp3SectionModel";
import { toneForDnp3Source } from "./industrialToneRules";

export function IndustrialDnp3Panel({
  details,
  commands,
  ruleHits,
}: {
  details: IndustrialProtocolDetail[];
  commands: IndustrialControlCommand[];
  ruleHits: IndustrialRuleHit[];
}) {
  const dnp3 = deriveIndustrialDnp3Section(details, commands, ruleHits);
  if (!dnp3) return null;
  return (
    <Panel title={`DNP3 专项 (${dnp3.rowCount})`} className="mt-0">
      <AnalysisCallout className="mb-3" tone="blue" icon={<Shield className="h-4 w-4" />}>
        基于现有工业分析结果中的 DNP3 协议明细、控制指令和规则命中聚合，突出遥控、目标点位与执行结果，不重复整页通用工控表格。
      </AnalysisCallout>
      <div className="mb-3 grid grid-cols-2 gap-0 lg:grid-cols-4">
        <StatCard title="明细记录" value={String(dnp3.detailRecordCount)} />
        <StatCard title="控制指令" value={String(dnp3.commandCount)} />
        <StatCard title="规则命中" value={String(dnp3.ruleCount)} />
        <StatCard title="操作类型" value={String(dnp3.operationKinds)} />
      </div>
      <div className="grid grid-cols-1 gap-0 xl:grid-cols-3">
        <Panel title="操作分布"><BucketChart data={dnp3.operations} barClassName="bg-blue-500" /></Panel>
        <Panel title="目标对象"><BucketChart data={dnp3.targets} barClassName="bg-emerald-500" /></Panel>
        <Panel title="结果 / 状态"><BucketChart data={dnp3.results} barClassName="bg-amber-500" /></Panel>
      </div>
      <div className="mt-0">
        <DataTable
          columns={[
            { key: "sourceType", header: "来源", widthClassName: "w-24", render: (item) => <AnalysisBadge tone={toneForDnp3Source(item.sourceType)}>{item.sourceLabel}</AnalysisBadge> },
            { key: "packet", header: "包号", widthClassName: "w-20", cellClassName: "font-mono text-slate-500", render: (item) => item.packetId || "--" },
            { key: "time", header: "时间", widthClassName: "w-28", cellClassName: "font-mono", render: (item) => item.time || "--" },
            { key: "source", header: "源", widthClassName: "w-32", cellClassName: "break-all", render: (item) => item.source || "--" },
            { key: "destination", header: "目标", widthClassName: "w-32", cellClassName: "break-all", render: (item) => item.destination || "--" },
            { key: "operation", header: "操作", widthClassName: "w-32", cellClassName: "font-mono", render: (item) => item.operation || "--" },
            { key: "target", header: "对象", widthClassName: "w-28", cellClassName: "break-all font-mono", render: (item) => item.target || "--" },
            { key: "result", header: "结果", widthClassName: "w-24", render: (item) => item.result || "--" },
            { key: "value", header: "值", widthClassName: "w-24", cellClassName: "break-all font-mono", render: (item) => item.value || "--" },
            { key: "summary", header: "摘要", render: (item) => item.summary || "--" },
          ]}
          data={dnp3.rows}
          rowKey={(item, idx) => `${item.sourceType}-${item.packetId}-${idx}`}
          maxHeightClassName="max-h-[520px]"
          tableClassName="min-w-[1120px]"
          emptyText="暂无 DNP3 专项记录"
        />
      </div>
    </Panel>
  );
}
