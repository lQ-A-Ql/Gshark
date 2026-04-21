import type { ReactNode } from "react";
import { cn } from "./ui/utils";

interface PageShellProps {
  children: ReactNode;
  className?: string;
  innerClassName?: string;
}

export function PageShell({ children, className, innerClassName }: PageShellProps) {
  return (
    <div className={cn("flex h-full flex-col overflow-auto bg-slate-50/50", className)}>
      <div className={cn("mx-auto flex w-full max-w-[1400px] flex-col gap-6 p-4 sm:p-6 lg:p-8", innerClassName)}>
        {children}
      </div>
    </div>
  );
}
