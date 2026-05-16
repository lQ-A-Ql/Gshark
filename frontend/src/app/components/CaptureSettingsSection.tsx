import { SearchCode } from "lucide-react";

import { capturePathHint } from "./RuntimeSettingsHints";
import { RuntimeSettingsSectionShell, RuntimeSettingsSectionTitle } from "./RuntimeSettingsSectionShell";
import { Field } from "./RuntimeSettingsSidebarParts";
import type { RuntimeSettingsSectionProps } from "./RuntimeSettingsSectionTypes";
import { RuntimeToolStatusLine } from "./RuntimeToolStatusLine";
import { TSharkCapabilityDetails } from "./TSharkCapabilityDetails";
import { isTSharkSnapshotDegraded } from "./runtimeTSharkStatus";

export function CaptureSettingsSection(props: RuntimeSettingsSectionProps) {
  const { form, snapshot, setForm, unknownMessage, unknownStateText } = props;
  return (
    <RuntimeSettingsSectionShell>
      <RuntimeSettingsSectionTitle Icon={SearchCode} iconClassName="bg-blue-50 text-blue-600">
        抓包与解析
      </RuntimeSettingsSectionTitle>
      <Field
        label="显式配置：tshark 路径"
        hint={capturePathHint(snapshot, form.tsharkPath)}
        value={form.tsharkPath}
        onChange={(value) => setForm((prev) => ({ ...prev, tsharkPath: value }))}
        placeholder="C:\\Program Files\\Wireshark\\tshark.exe"
      />
      <RuntimeToolStatusLine
        label="TShark"
        status={snapshot?.tshark}
        known={Boolean(snapshot)}
        degraded={isTSharkSnapshotDegraded(snapshot)}
        unknownMessage={unknownMessage}
        unknownStateText={unknownStateText}
      />
      <TSharkCapabilityDetails status={snapshot?.tshark} />
    </RuntimeSettingsSectionShell>
  );
}
