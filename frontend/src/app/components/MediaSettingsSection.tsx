import { AudioLines } from "lucide-react";

import { ffmpegPathHint } from "./RuntimeSettingsHints";
import { RuntimeSettingsSectionShell, RuntimeSettingsSectionTitle } from "./RuntimeSettingsSectionShell";
import { Field } from "./RuntimeSettingsSidebarParts";
import type { RuntimeSettingsSectionProps } from "./RuntimeSettingsSectionTypes";
import { RuntimeToolStatusLine } from "./RuntimeToolStatusLine";

export function MediaSettingsSection(props: RuntimeSettingsSectionProps) {
  const { form, snapshot, setForm, unknownMessage, unknownStateText } = props;
  return (
    <RuntimeSettingsSectionShell>
      <RuntimeSettingsSectionTitle Icon={AudioLines} iconClassName="bg-emerald-50 text-emerald-600">
        媒体播放与转码
      </RuntimeSettingsSectionTitle>
      <Field
        label="显式配置：ffmpeg 路径"
        hint={ffmpegPathHint(snapshot, form.ffmpegPath)}
        value={form.ffmpegPath}
        onChange={(value) => setForm((prev) => ({ ...prev, ffmpegPath: value }))}
        placeholder="C:\\ffmpeg\\bin\\ffmpeg.exe"
      />
      <RuntimeToolStatusLine
        label="FFmpeg"
        status={snapshot?.ffmpeg}
        known={Boolean(snapshot)}
        unknownMessage={unknownMessage}
        unknownStateText={unknownStateText}
      />
    </RuntimeSettingsSectionShell>
  );
}
