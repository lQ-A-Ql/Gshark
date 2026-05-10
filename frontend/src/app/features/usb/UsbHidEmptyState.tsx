import type { ReactNode } from "react";

export function UsbHidEmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="rounded border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground">
      {children}
    </div>
  );
}
