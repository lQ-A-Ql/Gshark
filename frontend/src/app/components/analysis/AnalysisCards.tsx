import type { ReactNode } from "react";
import { cn } from "../ui/utils";
import {
  toneBadge,
  toneCallout,
  toneMiniText,
  tonePanelShadow,
  toneShadow,
  type AnalysisTone,
} from "./analysisTone";

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
        "rounded-[24px] border border-white/80 bg-white/88 p-4 shadow-[0_22px_55px_rgba(148,163,184,0.16)] backdrop-blur-xl transition-all duration-300 hover:-translate-y-0.5",
        toneShadow[tone],
        className,
      )}
    >
      <div className="mb-2 flex items-center justify-between gap-3 text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">
        <span>{title}</span>
        {icon ? <span className="rounded-2xl border border-slate-100 bg-slate-50 p-2 shadow-sm">{icon}</span> : null}
      </div>
      <div className="text-2xl font-semibold tracking-tight text-slate-950">{value}</div>
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
        "overflow-hidden rounded-[24px] border border-white/80 bg-white/88 p-5 shadow-[0_22px_55px_rgba(148,163,184,0.16)] backdrop-blur-xl transition-all duration-300",
        tonePanelShadow[tone],
        className,
      )}
    >
      <div className="mb-4 flex items-center justify-between gap-3 border-b border-slate-100 pb-3">
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
    <div className={cn("rounded-2xl border border-slate-100 bg-slate-50/75 px-3 py-2 shadow-sm", className)}>
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
        "inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold",
        toneBadge[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

export function AnalysisEmptyState({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        "rounded-2xl border border-dashed border-slate-200 bg-slate-50/70 px-3 py-8 text-center text-xs leading-6 text-slate-500",
        className,
      )}
    >
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
        "flex items-start gap-2 rounded-2xl border px-3 py-2 text-xs shadow-sm",
        toneCallout[tone],
        className,
      )}
    >
      {icon ? <span className="mt-0.5 shrink-0">{icon}</span> : null}
      <span>{children}</span>
    </div>
  );
}
