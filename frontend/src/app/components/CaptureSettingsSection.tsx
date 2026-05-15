import { SearchCode } from "lucide-react";

import { capturePathHint } from "./RuntimeSettingsHints";
import { Field, StatusLine } from "./RuntimeSettingsSidebarParts";
import type { RuntimeSettingsSectionProps } from "./RuntimeSettingsSectionTypes";
import { TSharkCapabilityDetails } from "./TSharkCapabilityDetails";

export function CaptureSettingsSection({ backendConnected, form, snapshot, setForm }: RuntimeSettingsSectionProps) {
  return (
    <section className="space-y-4 rounded-[24px] border border-slate-200 bg-white p-4 shadow-[0_12px_32px_-24px_rgba(15,23,42,0.35)]">
      <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
        <div className="flex h-9 w-9 items-center justify-center rounded-2xl bg-blue-50 text-blue-600">
          <SearchCode className="h-4 w-4" />
        </div>
        抓包与解析
      </div>
      <Field
        label="显式配置：tshark 路径"
        hint={capturePathHint(snapshot, form.tsharkPath)}
        value={form.tsharkPath}
        onChange={(value) => setForm((prev) => ({ ...prev, tsharkPath: value }))}
        placeholder="C:\\Program Files\\Wireshark\\tshark.exe"
      />
      <StatusLine
        label="TShark"
        available={snapshot?.tshark.available}
        known={Boolean(snapshot)}
        degraded={Boolean(
          snapshot?.tshark.available &&
          (snapshot.tshark.capabilityCheckDegraded || (snapshot.tshark.missingOptionalFields?.length ?? 0) > 0),
        )}
        message={snapshot?.tshark.message ?? (backendConnected ? "等待检测" : "后端未连接")}
        path={snapshot?.tshark.path}
      />
      <TSharkCapabilityDetails status={snapshot?.tshark} />
    </section>
  );
}
