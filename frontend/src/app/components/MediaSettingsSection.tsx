import { AudioLines } from "lucide-react";

import { Field, StatusLine } from "./RuntimeSettingsSidebarParts";
import type { RuntimeSettingsSectionProps } from "./RuntimeSettingsSectionTypes";

export function MediaSettingsSection({ backendConnected, form, snapshot, setForm }: RuntimeSettingsSectionProps) {
  return (
    <section className="space-y-4 rounded-[24px] border border-slate-200 bg-white p-4 shadow-[0_12px_32px_-24px_rgba(15,23,42,0.35)]">
      <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
        <div className="flex h-9 w-9 items-center justify-center rounded-2xl bg-emerald-50 text-emerald-600">
          <AudioLines className="h-4 w-4" />
        </div>
        媒体播放与转码
      </div>
      <Field
        label="ffmpeg 路径"
        hint="这里会同时影响媒体播放、音频试听，以及离线转写前的 wav 转换。"
        value={form.ffmpegPath}
        onChange={(value) => setForm((prev) => ({ ...prev, ffmpegPath: value }))}
        placeholder="C:\\ffmpeg\\bin\\ffmpeg.exe"
      />
      <StatusLine
        label="FFmpeg"
        available={snapshot?.ffmpeg.available ?? false}
        message={snapshot?.ffmpeg.message ?? (backendConnected ? "等待检测" : "后端未连接")}
        path={snapshot?.ffmpeg.path}
      />
    </section>
  );
}
