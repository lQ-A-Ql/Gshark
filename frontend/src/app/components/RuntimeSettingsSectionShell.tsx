import type { LucideIcon } from "lucide-react";
import type { PropsWithChildren, ReactNode } from "react";

export function RuntimeSettingsSectionShell({ children }: PropsWithChildren) {
  return <section className="gshark-form-surface space-y-3 p-3.5">{children}</section>;
}

export function RuntimeSettingsSectionTitle({
  children,
  Icon,
  iconClassName,
}: {
  children: ReactNode;
  Icon: LucideIcon;
  iconClassName: string;
}) {
  return (
    <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
      <div
        className={`gshark-diffuse-chip gshark-evidence-accent flex h-9 w-9 items-center justify-center ${iconClassName}`}
      >
        <Icon className="h-4 w-4" />
      </div>
      {children}
    </div>
  );
}
