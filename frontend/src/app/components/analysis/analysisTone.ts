export type AnalysisTone = "amber" | "blue" | "cyan" | "emerald" | "rose" | "slate" | "violet";

export type AnalysisBucket = {
  label: string;
  count: number;
};

export const toneTileBorder: Record<AnalysisTone, string> = {
  amber: "border-amber-200/24",
  blue: "border-blue-200/24",
  cyan: "border-cyan-200/24",
  emerald: "border-emerald-200/24",
  rose: "border-rose-200/24",
  slate: "border-slate-200/28",
  violet: "border-violet-200/24",
};

export const toneCallout: Record<AnalysisTone, string> = {
  amber: "border-amber-200/30 bg-amber-50/16 text-amber-700",
  blue: "border-blue-200/30 bg-blue-50/16 text-blue-700",
  cyan: "border-cyan-200/30 bg-cyan-50/16 text-cyan-700",
  emerald: "border-emerald-200/30 bg-emerald-50/16 text-emerald-700",
  rose: "border-rose-200/30 bg-rose-50/16 text-rose-700",
  slate: "border-slate-200/30 bg-slate-50/14 text-slate-600",
  violet: "border-violet-200/30 bg-violet-50/16 text-violet-700",
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
  amber: "border-amber-200/32 bg-amber-50/18 text-amber-700",
  blue: "border-blue-200/32 bg-blue-50/18 text-blue-700",
  cyan: "border-cyan-200/32 bg-cyan-50/18 text-cyan-700",
  emerald: "border-emerald-200/32 bg-emerald-50/18 text-emerald-700",
  rose: "border-rose-200/32 bg-rose-50/18 text-rose-700",
  slate: "border-slate-200/32 bg-slate-50/16 text-slate-600",
  violet: "border-violet-200/32 bg-violet-50/18 text-violet-700",
};
