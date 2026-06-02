import type { ReactNode } from "react";
import type { MiscModuleManifest } from "../../core/types";
import { cn } from "../../components/ui/utils";

type MiscModuleTone = "cyan" | "emerald" | "sky" | "violet" | "amber" | "indigo" | "rose";

const toneClasses: Record<MiscModuleTone, { header: string; icon: string }> = {
  amber: {
    header: "meow-evidence-accent",
    icon: "meow-evidence-accent text-amber-700",
  },
  cyan: {
    header: "meow-evidence-accent",
    icon: "meow-evidence-accent text-cyan-700",
  },
  emerald: {
    header: "meow-evidence-accent",
    icon: "meow-evidence-accent text-emerald-700",
  },
  indigo: {
    header: "meow-evidence-accent",
    icon: "meow-evidence-accent text-indigo-700",
  },
  rose: {
    header: "meow-risk-accent",
    icon: "meow-risk-accent text-rose-700",
  },
  sky: {
    header: "meow-evidence-accent",
    icon: "meow-evidence-accent text-sky-700",
  },
  violet: {
    header: "meow-evidence-accent",
    icon: "meow-evidence-accent text-violet-700",
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
    <section
      className={cn("meow-tile meow-diffuse-edge meow-workbench-panel min-w-0 overflow-hidden", className)}
    >
      <div className={cn("meow-tile-header gap-2 border-b px-4 py-3", toneClasses[tone].header)}>
        <div className="flex items-center gap-2">
          <div className={cn("meow-soft-fill flex h-8 w-8 items-center justify-center", toneClasses[tone].icon)}>
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
