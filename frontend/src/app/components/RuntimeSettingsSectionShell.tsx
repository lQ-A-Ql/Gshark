import type { LucideIcon } from "lucide-react";
import type { PropsWithChildren, ReactNode } from "react";

export function RuntimeSettingsSectionShell({ children }: PropsWithChildren) {
  return (
    <section className="space-y-3 rounded-[20px] border border-slate-200 bg-white p-3.5 shadow-[0_10px_28px_-22px_rgba(15,23,42,0.3)]">
      {children}
    </section>
  );
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
      <div className={`flex h-9 w-9 items-center justify-center rounded-2xl ${iconClassName}`}>
        <Icon className="h-4 w-4" />
      </div>
      {children}
    </div>
  );
}
