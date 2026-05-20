import { Filter } from "lucide-react";
import type { CaptureOverviewSnapshot } from "../core/captureOverview";

type CaptureQuickFiltersPanelProps = {
  quickFilters: CaptureOverviewSnapshot["quickFilters"];
  onApplyFilter: (filter: string) => void;
};

export function CaptureQuickFiltersPanel({ quickFilters, onApplyFilter }: CaptureQuickFiltersPanelProps) {
  if (quickFilters.length === 0) {
    return null;
  }

  return (
    <div className="gshark-tile-toolbar mt-4 border-slate-200 bg-slate-50/80 p-3.5">
      <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
        <Filter className="h-4 w-4 text-blue-600" />
        推荐过滤器
      </div>
      <div className="mt-2.5 flex flex-wrap gap-2">
        {quickFilters.map((item) => (
          <button
            key={`${item.label}-${item.filter}`}
            onClick={() => onApplyFilter(item.filter)}
            className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs text-slate-700 transition-all hover:border-blue-200 hover:bg-blue-50 hover:text-blue-700"
            title={item.reason}
          >
            <span className="font-medium">{item.label}</span>
            <span className="font-mono text-slate-500">{item.filter}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
