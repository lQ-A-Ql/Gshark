import { AnalysisEmptyState } from "../../components/analysis/AnalysisPrimitives";

export interface TrafficBucket {
  label: string;
  count: number;
}

interface SimpleBarChartProps {
  data: TrafficBucket[];
  color: string;
  onSelect?: (row: TrafficBucket) => void;
}

export function SimpleBarChart({ data, color, onSelect }: SimpleBarChartProps) {
  const max = Math.max(1, ...data.map((x) => x.count));

  if (data.length === 0) {
    return <AnalysisEmptyState>暂无数据</AnalysisEmptyState>;
  }

  return (
    <div className="gshark-tile-table max-h-[480px] overflow-auto">
      <div className="divide-y divide-slate-100">
        {data.map((row) => (
          <button
            key={row.label}
            type="button"
            onClick={() => onSelect?.(row)}
            className={`grid w-full grid-cols-[180px_1fr_64px] items-center gap-3 px-2 py-2 text-left text-xs ${onSelect ? "transition-all hover:bg-amber-50/70" : ""}`}
          >
            <div className="truncate font-medium text-slate-500" title={row.label}>
              {row.label}
            </div>
            <div className="h-2 bg-slate-100">
              <div className={`h-2 ${color}`} style={{ width: `${Math.max(2, (row.count / max) * 100)}%` }} />
            </div>
            <div className="text-right font-mono font-semibold text-slate-700">{row.count}</div>
          </button>
        ))}
      </div>
    </div>
  );
}
