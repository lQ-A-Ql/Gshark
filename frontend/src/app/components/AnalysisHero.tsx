import { RefreshCw } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "./ui/utils";

type AnalysisHeroTheme = "blue" | "emerald" | "rose" | "cyan" | "amber" | "indigo";

interface AnalysisHeroProps {
  icon: ReactNode;
  title: string;
  subtitle: string;
  tags: string[];
  description?: string;
  tagsLabel?: string;
  onRefresh?: () => void;
  refreshLabel?: string;
  theme?: AnalysisHeroTheme;
}

const themeClasses: Record<
  AnalysisHeroTheme,
  {
    iconWrap: string;
    iconText: string;
    badgeStyle: string;
    accent: string;
    action: string;
  }
> = {
  blue: {
    iconWrap: "border-blue-200 bg-blue-50/90",
    iconText: "text-blue-600",
    badgeStyle: "border-blue-100 bg-blue-50/90 text-blue-700",
    accent: "from-blue-400/18 via-indigo-400/10 to-transparent",
    action: "border-blue-200/80 bg-blue-50/80 text-blue-700 hover:border-blue-300 hover:bg-blue-100/80",
  },
  indigo: {
    iconWrap: "border-indigo-200 bg-indigo-50/90",
    iconText: "text-indigo-600",
    badgeStyle: "border-indigo-100 bg-indigo-50/90 text-indigo-700",
    accent: "from-indigo-400/18 via-violet-400/10 to-transparent",
    action: "border-indigo-200/80 bg-indigo-50/80 text-indigo-700 hover:border-indigo-300 hover:bg-indigo-100/80",
  },
  emerald: {
    iconWrap: "border-emerald-200 bg-emerald-50/90",
    iconText: "text-emerald-600",
    badgeStyle: "border-emerald-100 bg-emerald-50/90 text-emerald-700",
    accent: "from-emerald-400/18 via-teal-400/10 to-transparent",
    action: "border-emerald-200/80 bg-emerald-50/80 text-emerald-700 hover:border-emerald-300 hover:bg-emerald-100/80",
  },
  rose: {
    iconWrap: "border-rose-200 bg-rose-50/90",
    iconText: "text-rose-600",
    badgeStyle: "border-rose-100 bg-rose-50/90 text-rose-700",
    accent: "from-rose-400/18 via-pink-400/10 to-transparent",
    action: "border-rose-200/80 bg-rose-50/80 text-rose-700 hover:border-rose-300 hover:bg-rose-100/80",
  },
  cyan: {
    iconWrap: "border-cyan-200 bg-cyan-50/90",
    iconText: "text-cyan-600",
    badgeStyle: "border-cyan-100 bg-cyan-50/90 text-cyan-700",
    accent: "from-cyan-400/18 via-sky-400/10 to-transparent",
    action: "border-cyan-200/80 bg-cyan-50/80 text-cyan-700 hover:border-cyan-300 hover:bg-cyan-100/80",
  },
  amber: {
    iconWrap: "border-amber-200 bg-amber-50/90",
    iconText: "text-amber-600",
    badgeStyle: "border-amber-100 bg-amber-50/90 text-amber-700",
    accent: "from-amber-400/18 via-orange-400/10 to-transparent",
    action: "border-amber-200/80 bg-amber-50/80 text-amber-700 hover:border-amber-300 hover:bg-amber-100/80",
  },
};

export function AnalysisHero({
  icon,
  title,
  subtitle,
  tags,
  description,
  tagsLabel = "标签",
  onRefresh,
  refreshLabel = "刷新",
  theme = "blue",
}: AnalysisHeroProps) {
  const themeConfig = themeClasses[theme];

  return (
    <section className="overflow-hidden rounded-[28px] border border-white/80 bg-white/88 shadow-[0_24px_68px_rgba(148,163,184,0.16)] backdrop-blur-xl">
      <div className={cn("pointer-events-none h-px w-full bg-gradient-to-r", themeConfig.accent)} />
      <div className="flex flex-col gap-5 px-6 py-6 sm:px-8 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 flex-1 space-y-4">
          <div className="flex min-w-0 flex-wrap items-center gap-4">
            <div
              className={cn(
                "flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border shadow-sm",
                themeConfig.iconWrap,
                themeConfig.iconText,
              )}
            >
              {icon}
            </div>

            <div className="min-w-0">
              <div className="flex flex-wrap items-baseline gap-2">
                <h1 className="truncate text-[19px] font-bold tracking-tight text-slate-900 sm:text-[22px]">{title}</h1>
                <span className="truncate text-[11px] font-semibold uppercase tracking-[0.32em] text-slate-400">{subtitle}</span>
              </div>
            </div>
          </div>

          <div className="grid gap-3 text-[13px] text-slate-500 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
            <div className="space-y-3">
              {description ? <p className="max-w-3xl leading-7 text-slate-500">{description}</p> : null}
              {tags.length > 0 ? (
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-400">{tagsLabel}</span>
                  {tags.map((tag) => (
                    <span
                      key={tag}
                      className={cn(
                        "rounded-full border px-3 py-1 text-[11px] font-semibold shadow-sm transition-colors",
                        themeConfig.badgeStyle,
                      )}
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              ) : null}
            </div>

            {onRefresh ? (
              <div className="flex items-center justify-start sm:justify-end">
                <button
                  type="button"
                  onClick={onRefresh}
                  className={cn(
                    "inline-flex h-11 items-center gap-2 rounded-full border px-4 text-sm font-semibold shadow-sm transition-all active:scale-[0.98]",
                    themeConfig.action,
                  )}
                >
                  <RefreshCw className="h-4 w-4" />
                  <span>{refreshLabel}</span>
                </button>
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </section>
  );
}
