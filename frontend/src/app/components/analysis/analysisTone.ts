export type AnalysisTone = "amber" | "blue" | "cyan" | "emerald" | "rose" | "slate" | "violet";

export type AnalysisBucket = {
  label: string;
  count: number;
};

export const toneShadow: Record<AnalysisTone, string> = {
  amber: "hover:shadow-[0_28px_72px_rgba(245,158,11,0.14)]",
  blue: "hover:shadow-[0_28px_72px_rgba(59,130,246,0.14)]",
  cyan: "hover:shadow-[0_28px_72px_rgba(6,182,212,0.14)]",
  emerald: "hover:shadow-[0_28px_72px_rgba(16,185,129,0.14)]",
  rose: "hover:shadow-[0_28px_72px_rgba(244,63,94,0.14)]",
  slate: "hover:shadow-[0_28px_72px_rgba(148,163,184,0.16)]",
  violet: "hover:shadow-[0_28px_72px_rgba(139,92,246,0.14)]",
};

export const tonePanelShadow: Record<AnalysisTone, string> = {
  amber: "hover:shadow-[0_28px_72px_rgba(245,158,11,0.12)]",
  blue: "hover:shadow-[0_28px_72px_rgba(59,130,246,0.12)]",
  cyan: "hover:shadow-[0_28px_72px_rgba(6,182,212,0.12)]",
  emerald: "hover:shadow-[0_28px_72px_rgba(16,185,129,0.12)]",
  rose: "hover:shadow-[0_28px_72px_rgba(244,63,94,0.12)]",
  slate: "hover:shadow-[0_28px_72px_rgba(148,163,184,0.14)]",
  violet: "hover:shadow-[0_28px_72px_rgba(139,92,246,0.12)]",
};

export const toneCallout: Record<AnalysisTone, string> = {
  amber: "border-amber-200 bg-amber-50/88 text-amber-700",
  blue: "border-blue-200 bg-blue-50/88 text-blue-700",
  cyan: "border-cyan-200 bg-cyan-50/88 text-cyan-700",
  emerald: "border-emerald-200 bg-emerald-50/88 text-emerald-700",
  rose: "border-rose-200 bg-rose-50/88 text-rose-700",
  slate: "border-slate-200 bg-slate-50/88 text-slate-600",
  violet: "border-violet-200 bg-violet-50/88 text-violet-700",
};

export const toneMiniText: Record<AnalysisTone, string> = {
  amber: "text-amber-700",
  blue: "text-blue-700",
  cyan: "text-cyan-700",
  emerald: "text-emerald-700",
  rose: "text-rose-700",
  slate: "text-slate-800",
  violet: "text-violet-700",
};

export const toneBadge: Record<AnalysisTone, string> = {
  amber: "border-amber-200 bg-amber-50 text-amber-700",
  blue: "border-blue-200 bg-blue-50 text-blue-700",
  cyan: "border-cyan-200 bg-cyan-50 text-cyan-700",
  emerald: "border-emerald-200 bg-emerald-50 text-emerald-700",
  rose: "border-rose-200 bg-rose-50 text-rose-700",
  slate: "border-slate-200 bg-slate-50 text-slate-600",
  violet: "border-violet-200 bg-violet-50 text-violet-700",
};
