import { RefreshCw } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "./ui/utils";

type AnalysisHeroTheme = "blue" | "emerald" | "rose" | "cyan" | "amber" | "indigo";

interface AnalysisHeroProps {
  actions?: ReactNode;
  children?: ReactNode;
  icon: ReactNode;
  title: string;
  subtitle: string;
  tags: string[];
  description?: string;
  tagsLabel?: string;
  onRefresh?: () => void;
  refreshLabel?: string;
  theme?: AnalysisHeroTheme;
  variant?: "tile" | "cell" | "card";
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
    iconWrap: "border-blue-200/24 bg-blue-50/16",
    iconText: "text-blue-600",
    badgeStyle: "border-blue-200/22 bg-blue-50/14 text-blue-700",
    accent: "from-blue-400/18 via-indigo-400/10 to-transparent",
    action: "border-blue-200/24 bg-blue-50/12 text-blue-700 hover:border-blue-300/40 hover:bg-blue-500/10",
  },
  indigo: {
    iconWrap: "border-indigo-200/24 bg-indigo-50/16",
    iconText: "text-indigo-600",
    badgeStyle: "border-indigo-200/22 bg-indigo-50/14 text-indigo-700",
    accent: "from-indigo-400/18 via-violet-400/10 to-transparent",
    action: "border-indigo-200/24 bg-indigo-50/12 text-indigo-700 hover:border-indigo-300/40 hover:bg-indigo-500/10",
  },
  emerald: {
    iconWrap: "border-emerald-200/24 bg-emerald-50/16",
    iconText: "text-emerald-600",
    badgeStyle: "border-emerald-200/22 bg-emerald-50/14 text-emerald-700",
    accent: "from-emerald-400/18 via-teal-400/10 to-transparent",
    action:
      "border-emerald-200/24 bg-emerald-50/12 text-emerald-700 hover:border-emerald-300/40 hover:bg-emerald-500/10",
  },
  rose: {
    iconWrap: "border-rose-200/24 bg-rose-50/16",
    iconText: "text-rose-600",
    badgeStyle: "border-rose-200/22 bg-rose-50/14 text-rose-700",
    accent: "from-rose-400/18 via-pink-400/10 to-transparent",
    action: "border-rose-200/24 bg-rose-50/12 text-rose-700 hover:border-rose-300/40 hover:bg-rose-500/10",
  },
  cyan: {
    iconWrap: "border-cyan-200/24 bg-cyan-50/16",
    iconText: "text-cyan-600",
    badgeStyle: "border-cyan-200/22 bg-cyan-50/14 text-cyan-700",
    accent: "from-cyan-400/18 via-sky-400/10 to-transparent",
    action: "border-cyan-200/24 bg-cyan-50/12 text-cyan-700 hover:border-cyan-300/40 hover:bg-cyan-500/10",
  },
  amber: {
    iconWrap: "border-amber-200/24 bg-amber-50/16",
    iconText: "text-amber-600",
    badgeStyle: "border-amber-200/22 bg-amber-50/14 text-amber-700",
    accent: "from-amber-400/18 via-orange-400/10 to-transparent",
    action: "border-amber-200/24 bg-amber-50/12 text-amber-700 hover:border-amber-300/40 hover:bg-amber-500/10",
  },
};

export function AnalysisHero({
  actions,
  children,
  icon,
  title,
  subtitle,
  tags,
  description,
  tagsLabel = "标签",
  onRefresh,
  refreshLabel = "刷新",
  theme = "blue",
  variant = "tile",
}: AnalysisHeroProps) {
  const themeConfig = themeClasses[theme];
  const isTile = variant === "tile";

  return (
    <section
      className={cn("gshark-forensic-scan overflow-hidden", isTile ? "gshark-tile gshark-tile-strong" : "gshark-tile")}
    >
      <div className={cn("pointer-events-none h-px w-full bg-gradient-to-r", themeConfig.accent)} />
      <div className="flex flex-col gap-3 px-4 py-3 sm:px-5 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 flex-1 space-y-3">
          <div className="flex min-w-0 flex-wrap items-center gap-3">
            <div
              className={cn(
                "gshark-soft-fill gshark-evidence-accent flex h-10 w-10 shrink-0 items-center justify-center border",
                isTile ? "rounded-sm" : "rounded-none",
                themeConfig.iconWrap,
                themeConfig.iconText,
              )}
            >
              {icon}
            </div>

            <div className="min-w-0">
              <div className="flex flex-wrap items-baseline gap-2">
                <h1 className="truncate text-[18px] font-bold tracking-tight text-slate-950 sm:text-[20px]">{title}</h1>
                <span className="truncate text-[10px] font-semibold uppercase tracking-[0.28em] text-slate-400">
                  {subtitle}
                </span>
              </div>
            </div>
          </div>

          <div className="grid gap-3 text-[12px] text-slate-500 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
            <div className="space-y-3">
              {description ? <p className="max-w-3xl leading-6 text-slate-500">{description}</p> : null}
              {tags.length > 0 ? (
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[10px] font-semibold uppercase tracking-[0.22em] text-slate-400">
                    {tagsLabel}
                  </span>
                  {tags.map((tag) => (
                    <span
                      key={tag}
                      className={cn(
                        "gshark-diffuse-chip px-2.5 py-0.5 text-[11px] font-semibold transition-colors",
                        isTile ? "rounded-sm" : "rounded-none",
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
                    "gshark-diffuse-chip inline-flex h-9 items-center gap-2 px-3 text-xs font-semibold transition-all active:scale-[0.98]",
                    isTile ? "rounded-sm" : "rounded-none",
                    themeConfig.action,
                  )}
                >
                  <RefreshCw className="h-4 w-4" />
                  <span>{refreshLabel}</span>
                </button>
              </div>
            ) : null}
          </div>
          {children ? <div className="pt-1">{children}</div> : null}
        </div>
        {actions ? <div className="shrink-0">{actions}</div> : null}
      </div>
    </section>
  );
}
