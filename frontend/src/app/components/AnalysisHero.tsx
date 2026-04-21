import { RefreshCw } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "./ui/utils";

type AnalysisHeroTheme = "blue" | "emerald" | "rose" | "cyan" | "amber";

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
  }
> = {
  blue: {
    iconWrap: "bg-blue-50 border-blue-200/60",
    iconText: "text-blue-600",
    badgeStyle: "bg-blue-50/80 text-blue-700 border-blue-100/60",
  },
  emerald: {
    iconWrap: "bg-emerald-50 border-emerald-200/60",
    iconText: "text-emerald-600",
    badgeStyle: "bg-emerald-50/80 text-emerald-700 border-emerald-100/60",
  },
  rose: {
    iconWrap: "bg-rose-50 border-rose-200/60",
    iconText: "text-rose-600",
    badgeStyle: "bg-rose-50/80 text-rose-700 border-rose-100/60",
  },
  cyan: {
    iconWrap: "bg-cyan-50 border-cyan-200/60",
    iconText: "text-cyan-600",
    badgeStyle: "bg-cyan-50/80 text-cyan-700 border-cyan-100/60",
  },
  amber: {
    iconWrap: "bg-amber-50 border-amber-200/60",
    iconText: "text-amber-600",
    badgeStyle: "bg-amber-50/80 text-amber-700 border-amber-100/60",
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
    <div className="flex min-h-[56px] w-full flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200/80 bg-white/95 px-4 py-2.5 shadow-sm backdrop-blur-sm sm:flex-nowrap sm:px-5">
      <div className="flex min-w-0 flex-1 items-center gap-3.5">
        {/* Left: Icon container */}
        <div
          className={cn(
            "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border shadow-sm",
            themeConfig.iconWrap,
            themeConfig.iconText
          )}
        >
          {icon}
        </div>

        {/* Title Block */}
        <div className="flex min-w-0 shrink-0 flex-col justify-center sm:flex-row sm:items-baseline sm:gap-2.5">
          <h1 className="truncate text-[15px] font-bold text-slate-900 leading-tight">
            {title}
          </h1>
          <span className="truncate text-[11px] font-extrabold tracking-widest text-slate-400 uppercase leading-tight mt-0.5 sm:mt-0">
            {subtitle}
          </span>
        </div>

        {/* Divider (visible on sm and larger) */}
        <div className="hidden h-4 w-[1px] shrink-0 bg-slate-200 sm:block" />

        {/* Metadata section (Tags & Description) */}
        <div className="hidden min-w-0 flex-1 items-center gap-2.5 xl:flex">
          {tags.length > 0 && (
            <div className="flex shrink-0 items-center gap-1.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                {tagsLabel}
              </span>
              {tags.map((tag) => (
                <span
                  key={tag}
                  className={cn(
                    "rounded-md border px-1.5 py-0.5 text-[10px] font-semibold leading-none shadow-sm transition-colors",
                    themeConfig.badgeStyle
                  )}
                >
                  {tag}
                </span>
              ))}
            </div>
          )}

          {description && (
            <>
              {tags.length > 0 && (
                <div className="h-1 w-1 shrink-0 rounded-full bg-slate-300 ml-1" />
              )}
              <span
                className="truncate text-xs font-medium text-slate-500"
                title={description}
              >
                {description}
              </span>
            </>
          )}
        </div>
      </div>

      {/* Action Block */}
      <div className="flex shrink-0 items-center justify-end w-full sm:w-auto mt-1 sm:mt-0">
        {tags.length > 0 && (
          <div className="flex shrink-0 items-center gap-1.5 xl:hidden mr-auto">
             <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                {tagsLabel}
             </span>
             {tags.map((tag) => (
                <span
                  key={tag}
                  className={cn(
                    "rounded-md border px-1.5 py-0.5 text-[10px] font-semibold leading-none shadow-sm transition-colors",
                    themeConfig.badgeStyle
                  )}
                >
                  {tag}
                </span>
             ))}
          </div>
        )}
        
        {onRefresh && (
          <button
            onClick={onRefresh}
            className="flex h-8 items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 text-[13px] font-semibold text-slate-600 shadow-sm transition-colors hover:bg-slate-50 hover:text-slate-900 active:scale-95"
          >
            <RefreshCw className="h-4 w-4" />
            <span>{refreshLabel}</span>
          </button>
        )}
      </div>
    </div>
  );
}
