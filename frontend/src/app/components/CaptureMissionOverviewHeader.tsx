import { Activity, FileWarning, Network, ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";
import type { CaptureOverviewSnapshot } from "../core/captureOverview";
import { formatBytes } from "../state/formatBytes";
import { MetricCard } from "./DesignSystem";

type CaptureMetricCard = {
  label: string;
  value: string;
  detail: string;
  icon: ReactNode;
  tone: "emerald" | "rose" | "blue" | "amber";
};

type CaptureMissionOverviewHeaderProps = {
  extractedObjectCount: number;
  fileName: string;
  fileSizeBytes: number;
  overview: CaptureOverviewSnapshot;
  overviewLoading: boolean;
  streamCounts: {
    http: number;
    tcp: number;
    udp: number;
  };
  threatHighCount: number;
  threatTotal: number;
  totalPackets: number;
  onOpenHunting: () => void;
  onOpenTrafficGraph: () => void;
};

export function CaptureMissionOverviewHeader({
  extractedObjectCount,
  fileName,
  fileSizeBytes,
  overview,
  overviewLoading,
  streamCounts,
  threatHighCount,
  threatTotal,
  totalPackets,
  onOpenHunting,
  onOpenTrafficGraph,
}: CaptureMissionOverviewHeaderProps) {
  const metricCards = buildCaptureMetricCards({
    extractedObjectCount,
    fileSizeBytes,
    streamCounts,
    threatHighCount,
    threatTotal,
    totalPackets,
  });

  return (
    <>
      <div className="gshark-tile-toolbar flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="text-[11px] font-semibold tracking-[0.18em] text-blue-700">ANALYSIS COCKPIT</div>
          <h2 className="mt-2 text-2xl font-semibold text-slate-950">{overview.headline}</h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">{overview.summary}</p>
          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-500">
            <span className="rounded-sm border border-slate-200 bg-slate-50/70 px-3 py-1">{fileName}</span>
            {overview.topProtocols.map((item) => (
              <span key={item.label} className="rounded-sm border border-blue-100 bg-blue-50/80 px-3 py-1 text-blue-700">
                {item.label} {item.count}
              </span>
            ))}
            {overviewLoading && (
              <span className="rounded-sm border border-amber-200 bg-amber-50/80 px-3 py-1 text-amber-700">
                正在汇总专项分析
              </span>
            )}
          </div>
        </div>

        <div className="gshark-tile-toolbar flex flex-wrap items-center gap-2 border-0 bg-transparent p-0">
          <button
            onClick={onOpenHunting}
            className="inline-flex items-center gap-2 rounded-sm border border-rose-200 bg-rose-50/80 px-4 py-2 text-sm font-medium text-rose-700 transition-all hover:bg-rose-100"
          >
            <ShieldAlert className="h-4 w-4" />
            威胁狩猎
          </button>
          <button
            onClick={onOpenTrafficGraph}
            className="inline-flex items-center gap-2 rounded-sm border border-slate-200 bg-white/65 px-4 py-2 text-sm font-medium text-slate-700 transition-all hover:bg-slate-100"
          >
            <Network className="h-4 w-4" />
            流量图
          </button>
        </div>
      </div>

      <div className="gshark-tile-grid mt-5 grid md:grid-cols-2 xl:grid-cols-4">
        {metricCards.map((item) => (
          <MetricCard
            key={item.label}
            label={item.label}
            value={item.value}
            hint={item.detail}
            icon={item.icon}
            tone={item.tone}
          />
        ))}
      </div>
    </>
  );
}

function buildCaptureMetricCards({
  extractedObjectCount,
  fileSizeBytes,
  streamCounts,
  threatHighCount,
  threatTotal,
  totalPackets,
}: {
  extractedObjectCount: number;
  fileSizeBytes: number;
  streamCounts: { http: number; tcp: number; udp: number };
  threatHighCount: number;
  threatTotal: number;
  totalPackets: number;
}): CaptureMetricCard[] {
  return [
    {
      label: "总包数",
      value: totalPackets.toLocaleString(),
      detail: `当前文件 ${formatBytes(fileSizeBytes)}`,
      icon: <Activity className="h-4 w-4 text-emerald-600" />,
      tone: "emerald",
    },
    {
      label: "可疑命中",
      value: threatTotal.toLocaleString(),
      detail: `${threatHighCount} 条高危`,
      icon: <ShieldAlert className="h-4 w-4 text-rose-600" />,
      tone: "rose",
    },
    {
      label: "流数量",
      value: (streamCounts.http + streamCounts.tcp + streamCounts.udp).toLocaleString(),
      detail: `HTTP ${streamCounts.http} / TCP ${streamCounts.tcp} / UDP ${streamCounts.udp}`,
      icon: <Network className="h-4 w-4 text-blue-600" />,
      tone: "blue",
    },
    {
      label: "提取对象",
      value: extractedObjectCount.toLocaleString(),
      detail: extractedObjectCount > 0 ? "可直接跳转附件提取页" : "暂未发现可导出对象",
      icon: <FileWarning className="h-4 w-4 text-amber-600" />,
      tone: "amber",
    },
  ];
}
