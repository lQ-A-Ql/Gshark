import { SearchCode } from "lucide-react";

import { capturePathHint } from "./RuntimeSettingsHints";
import { RuntimeSettingsSectionShell, RuntimeSettingsSectionTitle } from "./RuntimeSettingsSectionShell";
import { Field } from "./RuntimeSettingsSidebarParts";
import type { CaptureSettingsSectionProps } from "./CaptureSettingsSectionProps";
import { RuntimeToolStatusLine } from "./RuntimeToolStatusLine";
import { TSharkAllowedDirList } from "./TSharkAllowedDirList";
import { TSharkCapabilityDetails } from "./TSharkCapabilityDetails";
import { TSharkPathAllowWarning } from "./TSharkPathAllowWarning";
import { isTSharkSnapshotDegraded } from "./runtimeTSharkStatus";

export function CaptureSettingsSection(props: CaptureSettingsSectionProps) {
  return (
    <RuntimeSettingsSectionShell>
      <RuntimeSettingsSectionTitle Icon={SearchCode} iconClassName="bg-blue-50 text-blue-600">
        抓包与解析
      </RuntimeSettingsSectionTitle>
      <Field
        label="显式配置：tshark 路径"
        hint={capturePathHint(props.snapshot, props.form.tsharkPath)}
        value={props.form.tsharkPath}
        onChange={(value) => props.setForm((prev) => ({ ...prev, tsharkPath: value }))}
        placeholder="C:\\Program Files\\Wireshark\\tshark.exe"
      />
      <RuntimeToolStatusLine
        label="TShark"
        status={props.snapshot?.tshark}
        known={Boolean(props.snapshot)}
        degraded={isTSharkSnapshotDegraded(props.snapshot)}
        unknownMessage={props.unknownMessage}
        unknownStateText={props.unknownStateText}
      />
      <TSharkPathAllowWarning status={props.snapshot?.tshark} allowTSharkDir={props.allowTSharkDir} />
      <TSharkAllowedDirList
        dirs={props.snapshot?.config?.tsharkAllowedDirs ?? []}
        onRemove={props.removeTSharkAllowedDir}
        onRefresh={props.refreshTSharkAllowedDirs}
      />
      <TSharkCapabilityDetails status={props.snapshot?.tshark} />
    </RuntimeSettingsSectionShell>
  );
}
