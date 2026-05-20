import { type ReactNode } from "react";
import { BarChart2, Flag, FolderCog, Shield } from "lucide-react";
import { AnalysisBadge, AnalysisPanel } from "../../components/analysis/AnalysisPrimitives";
import { Progress } from "../../components/ui/progress";
import { ScrollArea } from "../../components/ui/scroll-area";
import { cn } from "../../components/ui/utils";
import type { ThreatHuntingProgressView, ThreatHuntingStats } from "./ThreatHuntingPanels";

export function ThreatHuntingProgressPanel({ progress }: { progress: ThreatHuntingProgressView }) {
  return (
    <div className="gshark-tile mb-3 border-blue-200 bg-blue-50/70 p-3.5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-slate-900">{progress.title}</div>
          <div className="mt-1 text-xs leading-5 text-slate-500">{progress.detail}</div>
        </div>
        <div className="flex flex-col items-end gap-1">
          <AnalysisBadge tone="blue" className="bg-blue-100/80 px-2.5 py-1">
            {progress.phaseLabel}
          </AnalysisBadge>
          <span className="text-[11px] font-medium text-slate-500">{Math.round(progress.value)}%</span>
        </div>
      </div>
      <div className="mt-3">
        <Progress value={progress.value} className="h-2.5 bg-blue-100 [&_[data-slot=progress-indicator]]:bg-blue-600" />
      </div>
      <div className="mt-2 text-[11px] text-slate-500">
        {progress.total > 0
          ? `${progress.current.toLocaleString()} / ${progress.total.toLocaleString()}`
          : `${progress.current.toLocaleString()}`}
      </div>
    </div>
  );
}

export function ThreatHuntingCategoryPanel({ stats }: { stats: ThreatHuntingStats }) {
  return (
    <AnalysisPanel
      title={
        <span className="flex items-center gap-2">
          <FolderCog className="h-4 w-4 text-blue-600" />
          规则分类
        </span>
      }
      tone="blue"
      className="gshark-tile flex min-h-0 flex-col"
    >
      <div className="border-b border-slate-100 pb-3 text-xs leading-5 text-slate-500">
        这里把命中结果按常见分析语义收在一起看，左侧能快速判断当前更偏 CTF、OWASP 还是异常流量。
      </div>
      <ScrollArea className="min-h-0 flex-1">
        <div className="space-y-3 p-3">
          <CategoryCard
            title="CTF Flags"
            count={stats.ctf}
            icon={<Flag className="h-4 w-4 text-blue-600" />}
            accent="blue"
          />
          <CategoryCard
            title="OWASP"
            count={stats.owasp}
            icon={<Shield className="h-4 w-4 text-rose-600" />}
            accent="rose"
          />
          <CategoryCard
            title="异常统计"
            count={stats.anomaly}
            icon={<BarChart2 className="h-4 w-4 text-amber-600" />}
            accent="amber"
          />
        </div>
      </ScrollArea>
    </AnalysisPanel>
  );
}

function CategoryCard({
  title,
  count,
  icon,
  accent,
}: {
  title: string;
  count: number;
  icon: ReactNode;
  accent: "blue" | "rose" | "amber";
}) {
  const accentClass =
    accent === "blue"
      ? "border-blue-200 bg-blue-50/70"
      : accent === "rose"
        ? "border-rose-200 bg-rose-50/70"
        : "border-amber-200 bg-amber-50/70";

  return (
    <div className={cn("gshark-tile px-3 py-3", accentClass)}>
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-medium text-slate-800">
          {icon}
          {title}
        </div>
        <AnalysisBadge tone={accent} className="px-2 text-xs">
          {count}
        </AnalysisBadge>
      </div>
    </div>
  );
}
