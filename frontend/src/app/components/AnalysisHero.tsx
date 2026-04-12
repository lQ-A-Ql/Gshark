import { RefreshCw } from "lucide-react";
import type { ReactNode } from "react";
import { Badge } from "./ui/badge";
import { cn } from "./ui/utils";

type AnalysisHeroTheme = "blue" | "emerald" | "rose" | "cyan" | "amber";

interface AnalysisHeroProps {
  icon: ReactNode;
  title: string;
  subtitle: string;
  tags: string[];
  tagsLabel?: string;
  onRefresh?: () => void;
  refreshLabel?: string;
  theme?: AnalysisHeroTheme;
}

const themeClasses: Record<
  AnalysisHeroTheme,
  {
    shell: string;
    iconWrap: string;
    iconColor: string;
    refreshButton: string;
    badgePalette: string[];
  }
> = {
  blue: {
    shell: "border-slate-200/80 bg-gradient-to-r from-white via-slate-50 to-blue-50/60",
    iconWrap: "border-blue-200 bg-blue-100/80",
    iconColor: "text-blue-700",
    refreshButton: "border-slate-200 bg-white/90 text-slate-600 hover:bg-slate-100 hover:text-slate-900",
    badgePalette: [
      "border-blue-200 bg-blue-50 text-blue-700 hover:bg-blue-100/80",
      "border-cyan-200 bg-cyan-50 text-cyan-700 hover:bg-cyan-100/80",
      "border-indigo-200 bg-indigo-50 text-indigo-700 hover:bg-indigo-100/80",
      "border-sky-200 bg-sky-50 text-sky-700 hover:bg-sky-100/80",
    ],
  },
  emerald: {
    shell: "border-emerald-200/80 bg-gradient-to-r from-white via-emerald-50/60 to-teal-50/80",
    iconWrap: "border-emerald-200 bg-emerald-100/80",
    iconColor: "text-emerald-700",
    refreshButton: "border-emerald-200 bg-white/90 text-emerald-700 hover:bg-emerald-50 hover:text-emerald-900",
    badgePalette: [
      "border-emerald-200 bg-emerald-50 text-emerald-700 hover:bg-emerald-100/80",
      "border-teal-200 bg-teal-50 text-teal-700 hover:bg-teal-100/80",
      "border-lime-200 bg-lime-50 text-lime-700 hover:bg-lime-100/80",
      "border-cyan-200 bg-cyan-50 text-cyan-700 hover:bg-cyan-100/80",
    ],
  },
  rose: {
    shell: "border-rose-200/80 bg-gradient-to-r from-white via-rose-50/70 to-fuchsia-50/70",
    iconWrap: "border-rose-200 bg-rose-100/80",
    iconColor: "text-rose-700",
    refreshButton: "border-rose-200 bg-white/90 text-rose-700 hover:bg-rose-50 hover:text-rose-900",
    badgePalette: [
      "border-rose-200 bg-rose-50 text-rose-700 hover:bg-rose-100/80",
      "border-fuchsia-200 bg-fuchsia-50 text-fuchsia-700 hover:bg-fuchsia-100/80",
      "border-violet-200 bg-violet-50 text-violet-700 hover:bg-violet-100/80",
      "border-amber-200 bg-amber-50 text-amber-700 hover:bg-amber-100/80",
    ],
  },
  cyan: {
    shell: "border-cyan-200/80 bg-gradient-to-r from-white via-cyan-50/60 to-sky-50/80",
    iconWrap: "border-cyan-200 bg-cyan-100/80",
    iconColor: "text-cyan-700",
    refreshButton: "border-cyan-200 bg-white/90 text-cyan-700 hover:bg-cyan-50 hover:text-cyan-900",
    badgePalette: [
      "border-cyan-200 bg-cyan-50 text-cyan-700 hover:bg-cyan-100/80",
      "border-sky-200 bg-sky-50 text-sky-700 hover:bg-sky-100/80",
      "border-blue-200 bg-blue-50 text-blue-700 hover:bg-blue-100/80",
      "border-slate-200 bg-slate-50 text-slate-700 hover:bg-slate-100/80",
    ],
  },
  amber: {
    shell: "border-amber-200/80 bg-gradient-to-r from-white via-amber-50/60 to-orange-50/80",
    iconWrap: "border-amber-200 bg-amber-100/80",
    iconColor: "text-amber-700",
    refreshButton: "border-amber-200 bg-white/90 text-amber-700 hover:bg-amber-50 hover:text-amber-900",
    badgePalette: [
      "border-amber-200 bg-amber-50 text-amber-700 hover:bg-amber-100/80",
      "border-orange-200 bg-orange-50 text-orange-700 hover:bg-orange-100/80",
      "border-yellow-200 bg-yellow-50 text-yellow-700 hover:bg-yellow-100/80",
      "border-stone-200 bg-stone-50 text-stone-700 hover:bg-stone-100/80",
    ],
  },
};

export function AnalysisHero({
  icon,
  title,
  subtitle,
  tags,
  tagsLabel = "协议族",
  onRefresh,
  refreshLabel = "刷新",
  theme = "blue",
}: AnalysisHeroProps) {
  const themeConfig = themeClasses[theme];

  return (
    <div className={cn("mb-4 flex flex-col gap-3 rounded-2xl border p-4 shadow-sm", themeConfig.shell)}>
      <div className="flex flex-wrap items-center gap-2 text-lg font-semibold">
        <div className={cn("flex h-9 w-9 items-center justify-center rounded-xl border shadow-sm", themeConfig.iconWrap)}>
          <div className={themeConfig.iconColor}>{icon}</div>
        </div>
        <div className="flex flex-col">
          <span className="text-slate-900">{title}</span>
          <span className="text-xs font-medium tracking-[0.16em] text-slate-500">{subtitle}</span>
        </div>
        {onRefresh && (
          <button
            className={cn(
              "ml-auto inline-flex items-center gap-1 rounded-xl border px-3 py-1.5 text-xs font-medium shadow-sm transition-colors",
              themeConfig.refreshButton,
            )}
            onClick={onRefresh}
          >
            <RefreshCw className="h-3.5 w-3.5" />
            {refreshLabel}
          </button>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">{tagsLabel}</span>
        {tags.map((tag, index) => (
          <Badge
            key={tag}
            variant="outline"
            className={cn(
              "rounded-full px-2.5 py-1 text-[11px] font-semibold shadow-sm transition-colors",
              themeConfig.badgePalette[index % themeConfig.badgePalette.length],
            )}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-current/70" />
            {tag}
          </Badge>
        ))}
      </div>
    </div>
  );
}
