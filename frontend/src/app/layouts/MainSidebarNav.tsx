import { Link } from "react-router";
import { cn } from "../components/ui/utils";
import { NAV_ITEMS } from "./mainLayoutConfig";
import type { MainLayoutChromeProps } from "./mainLayoutChromeTypes";

export function MainSidebarNav({ activeTheme, pathname }: Pick<MainLayoutChromeProps, "activeTheme" | "pathname">) {
  return (
    <aside className="z-40 flex w-16 shrink-0 flex-col items-center gap-4 border-r border-white/16 bg-white/34 py-4 shadow-[0_0_34px_rgba(255,255,255,0.12)] backdrop-blur-xl">
      {NAV_ITEMS.map((item) => {
        const Icon = item.icon;
        const isActive = pathname === item.path;
        return (
          <Link
            key={item.path}
            to={item.path}
            title={item.label}
            className={cn(
              "group gshark-control-ghost relative p-3 transition-all",
              isActive ? activeTheme.active : "text-muted-foreground hover:text-slate-900",
            )}
          >
            <Icon className="h-5 w-5" />
            {isActive && (
              <div className={cn("absolute left-0 top-1/2 h-6 w-1 -translate-y-1/2 rounded-r-full", activeTheme.bar)} />
            )}
            <div className="gshark-form-surface pointer-events-none invisible absolute left-full top-1/2 z-50 ml-3 -translate-y-1/2 whitespace-nowrap px-2.5 py-1.5 text-xs font-semibold text-slate-700 opacity-0 shadow-[0_18px_42px_rgba(15,23,42,0.07),0_0_28px_rgba(255,255,255,0.22)] backdrop-blur-xl transition-all group-hover:visible group-hover:opacity-100">
              {item.label}
            </div>
          </Link>
        );
      })}
    </aside>
  );
}
