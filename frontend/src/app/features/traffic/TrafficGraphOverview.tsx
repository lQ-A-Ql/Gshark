import { Activity, BarChart3, Clock3 } from "lucide-react";
import type { GlobalTrafficStats, TrafficBucket } from "../../core/types";
import { StatusHint } from "../../components/DesignSystem";
import { AnalysisStatCard } from "../../components/analysis/AnalysisPrimitives";

type AnalysisBucket = TrafficBucket;

type TrafficGraphOverviewProps = {
  error: string;
  loading: boolean;
  stats: GlobalTrafficStats;
  timeline: AnalysisBucket[];
  onRetry: () => void;
};

export function TrafficGraphOverview({ error, loading, stats, timeline, onRetry }: TrafficGraphOverviewProps) {
  const timeWindow = timeline.length > 0 ? `${timeline[0].label} ~ ${timeline[timeline.length - 1].label}` : "--";

  return (
    <>
      {loading && (
        <StatusHint tone="slate" className="mb-3">
          正在加载全局流量统计...
        </StatusHint>
      )}
      {!loading && error ? (
        <StatusHint tone="amber" className="mb-3 flex items-center justify-between">
          <span>{error}</span>
          <button
            className="border border-amber-200 bg-amber-50/80 px-3 py-1 font-semibold transition-all hover:bg-amber-100"
            onClick={onRetry}
          >
            重试
          </button>
        </StatusHint>
      ) : null}
      <div className="meow-tile-grid grid grid-cols-1 lg:grid-cols-3">
        <AnalysisStatCard
          title="总包数"
          value={stats.totalPackets.toLocaleString()}
          icon={<Activity className="h-4 w-4 text-emerald-600" />}
          tone="amber"
        />
        <AnalysisStatCard
          title="协议种类"
          value={String(stats.protocolKinds)}
          icon={<BarChart3 className="h-4 w-4 text-indigo-600" />}
          tone="amber"
        />
        <AnalysisStatCard
          title="时间窗口"
          value={timeWindow}
          icon={<Clock3 className="h-4 w-4 text-amber-600" />}
          tone="amber"
        />
      </div>
    </>
  );
}
