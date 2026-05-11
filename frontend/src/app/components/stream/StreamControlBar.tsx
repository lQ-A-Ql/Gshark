import type { ReactNode } from "react";

import { cn } from "../ui/utils";

export function StreamControlBar({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        "flex shrink-0 flex-wrap items-center gap-3 border-t border-border bg-white px-4 py-3 shadow-sm",
        className,
      )}
    >
      {children}
    </div>
  );
}
