import type { IndustrialProtocolDetail } from "../../core/types";
import {
  AnalysisBucketChart as BucketChart,
  AnalysisDataTable as DataTable,
  AnalysisPanel as Panel,
  AnalysisStatCard as StatCard,
} from "../../components/analysis/AnalysisPrimitives";

export function IndustrialProtocolDetailsPanel({ details }: { details: IndustrialProtocolDetail[] }) {
  return (
    <>
      {details.map((detail) => (
        <Panel key={detail.name} title={`${detail.name} 明细 (${detail.records.length})`} className="mt-0">
          <div className="mb-3 grid grid-cols-2 gap-0 lg:grid-cols-4">
            <StatCard title="总帧数" value={detail.totalFrames.toLocaleString()} />
            <StatCard title="操作类型" value={String(detail.operations.length)} />
            <StatCard title="目标对象" value={String(detail.targets.length)} />
            <StatCard title="结果项" value={String(detail.results.length)} />
          </div>
          <div className="grid grid-cols-1 gap-0 xl:grid-cols-3">
            <Panel title="操作分布"><BucketChart data={detail.operations} barClassName="bg-blue-500" /></Panel>
            <Panel title="目标对象"><BucketChart data={detail.targets} barClassName="bg-emerald-500" /></Panel>
            <Panel title="结果 / 状态"><BucketChart data={detail.results} barClassName="bg-amber-500" /></Panel>
          </div>
          <div className="mt-0">
            <DataTable
              headers={["包号", "时间", "源", "目标", "操作", "对象", "结果", "值", "摘要"]}
              rows={detail.records.map((item) => [
                item.packetId, item.time || "--", item.source || "--", item.destination || "--", item.operation || "--",
                item.target || "--", item.result || "--", item.value || "--", item.summary || "--",
              ])}
            />
          </div>
        </Panel>
      ))}
    </>
  );
}
