import type { LucideIcon } from "lucide-react";

import { statusTone } from "./RuntimeSettingsSidebarParts";

export function RuntimeDependencyCard({
  label,
  value,
  available,
  known = true,
  Icon,
}: {
  label: string;
  value: string;
  available: boolean;
  known?: boolean;
  Icon: LucideIcon;
}) {
  return (
    <div className={`rounded-xl border px-3 py-2 ${statusTone(available, known)}`}>
      <div className="flex items-center gap-1 text-xs font-semibold">
        <Icon className="h-3.5 w-3.5" /> {label}
      </div>
      <div className="mt-1 break-all text-[11px] leading-5">{value}</div>
    </div>
  );
}
