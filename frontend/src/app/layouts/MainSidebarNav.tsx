import { Link } from "react-router";
import { cn } from "../components/ui/utils";
import { NAV_ITEMS } from "./mainLayoutConfig";
import type { MainLayoutChromeProps } from "./mainLayoutChromeTypes";

export function MainSidebarNav({ activeTheme, pathname }: Pick<MainLayoutChromeProps, "activeTheme" | "pathname">) {
  return (
    <aside className="z-40 flex w-16 shrink-0 flex-col items-center gap-4 border-r border-slate-200 bg-white/88 py-4 shadow-[8px_0_24px_-24px_rgba(15,23,42,0.28)] backdrop-blur">
      {NAV_ITEMS.map((item) => {
        const Icon = item.icon;
        const isActive = pathname === item.path;
        return (
          <Link
            key={item.path}
            to={item.path}
            title={item.label}
            className={cn(
              "group relative rounded-2xl p-3 transition-all",
              isActive ? activeTheme.active : "text-muted-foreground hover:bg-slate-100 hover:text-slate-900",
            )}
          >
            <Icon className="h-5 w-5" />
            {isActive && (
              <div className={cn("absolute left-0 top-1/2 h-6 w-1 -translate-y-1/2 rounded-r-full", activeTheme.bar)} />
            )}
            <div className="pointer-events-none invisible absolute left-full top-1/2 z-50 ml-3 -translate-y-1/2 whitespace-nowrap rounded-xl border border-slate-200 bg-white/95 px-2.5 py-1.5 text-xs font-semibold text-slate-700 opacity-0 shadow-[0_18px_42px_rgba(15,23,42,0.14)] backdrop-blur transition-all group-hover:visible group-hover:opacity-100">
              {item.label}
            </div>
          </Link>
        );
      })}
    </aside>
  );
}
