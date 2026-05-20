import type { ReactNode } from "react";
import type { MiscModuleManifest } from "../../core/types";
import { cn } from "../../components/ui/utils";

type MiscModuleTone = "cyan" | "emerald" | "sky" | "violet" | "amber" | "indigo";

const toneClasses: Record<MiscModuleTone, { header: string; icon: string }> = {
  amber: {
    header: "border-amber-100/24 bg-amber-50/18",
    icon: "border-amber-100/24 bg-amber-50/18 text-amber-700",
  },
  cyan: {
    header: "border-cyan-100/24 bg-cyan-50/18",
    icon: "border-cyan-100/24 bg-cyan-50/18 text-cyan-700",
  },
  emerald: {
    header: "border-emerald-100/24 bg-emerald-50/18",
    icon: "border-emerald-100/24 bg-emerald-50/18 text-emerald-700",
  },
  indigo: {
    header: "border-indigo-100/24 bg-indigo-50/18",
    icon: "border-indigo-100/24 bg-indigo-50/18 text-indigo-700",
  },
  sky: {
    header: "border-sky-100/24 bg-sky-50/18",
    icon: "border-sky-100/24 bg-sky-50/18 text-sky-700",
  },
  violet: {
    header: "border-violet-100/24 bg-violet-50/18",
    icon: "border-violet-100/24 bg-violet-50/18 text-violet-700",
  },
};

export function MiscModuleSurface({
  module,
  embedded,
  icon,
  tone,
  children,
  className,
  bodyClassName,
}: {
  module: MiscModuleManifest;
  embedded: boolean;
  icon: ReactNode;
  tone: MiscModuleTone;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  if (embedded) {
    return <div className={cn("space-y-5 px-0 pt-0", bodyClassName)}>{children}</div>;
  }

  return (
    <section className={cn("gshark-tile gshark-diffuse-edge min-w-0 overflow-hidden", className)}>
      <div className={cn("gshark-tile-header gap-2 border-b px-4 py-3", toneClasses[tone].header)}>
        <div className="flex items-center gap-2">
          <div className={cn("gshark-soft-fill flex h-8 w-8 items-center justify-center", toneClasses[tone].icon)}>
            {icon}
          </div>
          <div className="min-w-0">
            <div className="truncate text-base font-semibold text-slate-800">{module.title}</div>
            <div className="mt-1 text-[13px] leading-relaxed text-slate-600">{module.summary}</div>
          </div>
        </div>
      </div>
      <div className={cn("space-y-5 p-4", bodyClassName)}>{children}</div>
    </section>
  );
}
