import type { ReactNode } from "react";
import { cn } from "./ui/utils";

interface PageShellProps {
  children: ReactNode;
  className?: string;
  density?: "compact" | "roomy";
  innerClassName?: string;
  layout?: "stacked" | "tiled";
}

const densityClassName = {
  compact: "mx-auto flex w-full max-w-[1380px] flex-col gap-4 p-4 sm:p-5 lg:p-6",
  roomy: "mx-auto flex w-full max-w-[1400px] flex-col gap-6 p-4 sm:p-6 lg:p-8",
};

const tiledDensityClassName = {
  compact: "gshark-tile-page min-h-full w-full p-0",
  roomy: "gshark-tile-page min-h-full w-full p-0",
};

export function PageShell({
  children,
  className,
  density = "compact",
  innerClassName,
  layout = "tiled",
}: PageShellProps) {
  return (
    <div className={cn("flex h-full flex-col overflow-auto", className)}>
      <div
        className={cn(layout === "tiled" ? tiledDensityClassName[density] : densityClassName[density], innerClassName)}
      >
        {children}
      </div>
    </div>
  );
}
