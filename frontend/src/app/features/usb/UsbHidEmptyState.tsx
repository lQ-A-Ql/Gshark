import type { ReactNode } from "react";

export function UsbHidEmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="px-3 py-6 text-center text-xs leading-6 text-muted-foreground">
      {children}
    </div>
  );
}
