import { ArrowRight, Binary, Car, Clapperboard, Factory, Network, Usb } from "lucide-react";
import type { ReactNode } from "react";
import type { CaptureOverviewSnapshot, CaptureRecommendation } from "../core/captureOverview";

type CaptureRecommendationsPanelProps = {
  recommendations: CaptureOverviewSnapshot["recommendations"];
  onOpenRecommendation: (item: CaptureRecommendation) => Promise<void>;
  onApplyFilter: (filter: string) => void;
};

export function CaptureRecommendationsPanel({
  recommendations,
  onOpenRecommendation,
  onApplyFilter,
}: CaptureRecommendationsPanelProps) {
  return (
    <div className="gshark-tile border-slate-200 bg-slate-50/80 p-3.5">
      <div className="mb-3 text-sm font-semibold text-slate-900">推荐入口</div>
      <div className="grid gap-3 md:grid-cols-2">
        {recommendations.map((item) => (
          <RecommendationCard
            key={item.key}
            title={item.label}
            summary={item.summary}
            score={item.score}
            icon={iconForRecommendation(item.key)}
            onOpen={() => void onOpenRecommendation(item)}
            onFilter={item.filter ? () => onApplyFilter(item.filter!) : undefined}
          />
        ))}
      </div>
    </div>
  );
}

function iconForRecommendation(key: CaptureRecommendation["key"]) {
  if (key === "industrial") return <Factory className="h-4 w-4 text-blue-600" />;
  if (key === "vehicle") return <Car className="h-4 w-4 text-emerald-600" />;
  if (key === "usb") return <Usb className="h-4 w-4 text-amber-600" />;
  if (key === "media") return <Clapperboard className="h-4 w-4 text-violet-600" />;
  if (key === "payload") return <Binary className="h-4 w-4 text-rose-600" />;
  return <Network className="h-4 w-4 text-sky-600" />;
}

function RecommendationCard({
  title,
  summary,
  score,
  icon,
  onOpen,
  onFilter,
}: {
  title: string;
  summary: string;
  score: number;
  icon: ReactNode;
  onOpen: () => void;
  onFilter?: () => void;
}) {
  return (
    <div className="gshark-tile border-slate-200 px-3.5 py-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
          {icon}
          {title}
        </div>
        <div className="rounded-full border border-blue-100 bg-blue-50 px-2 py-0.5 text-[11px] font-medium text-blue-700">
          匹配度 {score}
        </div>
      </div>
      <p className="mt-2 text-xs leading-5 text-slate-600">{summary}</p>
      <div className="mt-3 flex items-center gap-2">
        <button
          onClick={onOpen}
          className="inline-flex items-center gap-2 rounded-xl border border-blue-200 bg-blue-50 px-3 py-1.5 text-xs font-medium text-blue-700 hover:bg-blue-100"
        >
          进入模块
          <ArrowRight className="h-3.5 w-3.5" />
        </button>
        {onFilter && (
          <button
            onClick={onFilter}
            className="rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-100"
          >
            先应用过滤器
          </button>
        )}
      </div>
    </div>
  );
}
