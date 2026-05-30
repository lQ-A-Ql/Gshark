import type { ReactNode } from "react";
import { cn } from "../ui/utils";
import { toneBadge, toneCallout, toneMiniText, toneTileBorder, type AnalysisTone } from "./analysisTone";
import type { MeowCatVariant } from "../MeowEmptyState";

export function AnalysisStatCard({
  title,
  value,
  icon,
  tone = "slate",
  className,
}: {
  title: string;
  value: ReactNode;
  icon?: ReactNode;
  tone?: AnalysisTone;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "meow-tile meow-tile-strong meow-evidence-accent p-3 transition-colors duration-200 hover:border-slate-300/24",
        toneTileBorder[tone],
        className,
      )}
    >
      <div className="mb-1.5 flex items-center justify-between gap-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400">
        <span>{title}</span>
        {icon ? <span className="meow-diffuse-chip meow-evidence-accent p-1.5">{icon}</span> : null}
      </div>
      <div className="text-[22px] font-semibold tracking-tight text-slate-950">{value}</div>
    </div>
  );
}

export function AnalysisPanel({
  title,
  children,
  tone = "slate",
  className,
  actions,
}: {
  title: ReactNode;
  children: ReactNode;
  tone?: AnalysisTone;
  className?: string;
  actions?: ReactNode;
}) {
  return (
    <div
      className={cn(
        "meow-tile meow-workbench-panel overflow-hidden p-3.5 transition-colors duration-200 hover:border-slate-300/24",
        toneTileBorder[tone],
        className,
      )}
    >
      <div className="meow-tile-header -mx-3.5 -mt-3.5 mb-3 flex items-center justify-between gap-3 px-3.5 py-2.5">
        <div className="text-sm font-semibold tracking-tight text-slate-900">{title}</div>
        {actions ? <div className="shrink-0">{actions}</div> : null}
      </div>
      {children}
    </div>
  );
}

export function AnalysisMiniStat({
  title,
  value,
  tone = "slate",
  className,
}: {
  title: string;
  value: ReactNode;
  tone?: AnalysisTone;
  className?: string;
}) {
  return (
    <div className={cn("meow-soft-fill meow-evidence-accent px-3 py-2", className)}>
      <div className="text-[11px] font-medium text-slate-400">{title}</div>
      <div className={cn("text-sm font-semibold", toneMiniText[tone])}>{value}</div>
    </div>
  );
}

export function AnalysisBadge({
  children,
  tone = "slate",
  className,
}: {
  children: ReactNode;
  tone?: AnalysisTone;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "meow-diffuse-chip inline-flex items-center px-2 py-0.5 text-[11px] font-semibold tracking-[0.01em]",
        toneBadge[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

export function AnalysisEmptyState({
  children,
  className,
  cat,
}: {
  children: ReactNode;
  className?: string;
  cat?: MeowCatVariant;
}) {
  return (
    <div className={cn("px-3 py-6 text-center text-xs leading-6 text-slate-500", className)}>
      {cat && (
        <div
          className={cn("meow-empty-cat-figure mx-auto mb-2 text-slate-300", `meow-empty-cat-${cat}`)}
          role="img"
          aria-hidden
        />
      )}
      {children}
    </div>
  );
}

export function AnalysisCallout({
  children,
  icon,
  tone = "slate",
  className,
}: {
  children: ReactNode;
  icon?: ReactNode;
  tone?: AnalysisTone;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "meow-soft-fill meow-evidence-accent flex items-start gap-2 px-3 py-2 text-xs",
        toneCallout[tone],
        className,
      )}
    >
      {icon ? <span className="mt-0.5 shrink-0">{icon}</span> : null}
      <span>{children}</span>
    </div>
  );
}
