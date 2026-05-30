import type { ReactNode } from "react";

import { cn } from "../ui/utils";

export function StreamControlBar({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        "meow-tile-toolbar meow-workbench-panel flex shrink-0 flex-wrap items-center gap-3 border-x-0 border-b-0 px-4 py-3",
        className,
      )}
    >
      {children}
    </div>
  );
}
