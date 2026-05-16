import {
  CaptureSettingsSection,
  MediaSettingsSection,
  SpeechSettingsSection,
  YaraSettingsSection,
} from "./RuntimeSettingsSections";
import { RuntimeSettingsHeader } from "./RuntimeSettingsHeader";
import { RuntimeSettingsActions, RuntimeSettingsFooter } from "./RuntimeSettingsShell";
import { useRuntimeSettingsSidebarModel } from "./useRuntimeSettingsSidebarModel";
import { useSidebar } from "./ui/sidebar";

export function RuntimeSettingsSidebar() {
  const { toggleSidebar } = useSidebar();
  const {
    backendConnected,
    toolRuntimeSnapshot,
    isToolRuntimeLoading,
    toolRuntimeProbeState,
    toolRuntimeProbeTransport,
    lastToolRuntimeProbeError,
    refresh,
    save,
    busy,
    dirty,
    form,
    notice,
    setForm,
    speechIssues,
    speechSummary,
    unknownMessage,
    unknownStateText,
  } = useRuntimeSettingsSidebarModel();

  return (
    <div className="flex h-full flex-col overflow-hidden rounded-[28px] border border-slate-200/80 bg-white/95 shadow-[0_28px_80px_-28px_rgba(15,23,42,0.45)] backdrop-blur">
      <RuntimeSettingsHeader
        form={form}
        snapshot={toolRuntimeSnapshot}
        probeState={toolRuntimeProbeState}
        probeTransport={toolRuntimeProbeTransport}
        probeError={lastToolRuntimeProbeError}
        onClose={toggleSidebar}
      />

      <div className="flex flex-1 flex-col overflow-hidden">
        <RuntimeSettingsActions
          busy={busy}
          loading={isToolRuntimeLoading}
          backendConnected={backendConnected}
          dirty={dirty}
          onRefresh={() => void refresh()}
          onSave={() => void save()}
        />

        <div className="flex-1 space-y-4 overflow-auto bg-[linear-gradient(180deg,rgba(248,250,252,0.5),rgba(255,255,255,0.95))] px-5 py-5">
          <CaptureSettingsSection
            form={form}
            snapshot={toolRuntimeSnapshot}
            unknownMessage={unknownMessage}
            unknownStateText={unknownStateText}
            setForm={setForm}
          />
          <YaraSettingsSection
            form={form}
            snapshot={toolRuntimeSnapshot}
            unknownMessage={unknownMessage}
            unknownStateText={unknownStateText}
            setForm={setForm}
          />
          <MediaSettingsSection
            form={form}
            snapshot={toolRuntimeSnapshot}
            unknownMessage={unknownMessage}
            unknownStateText={unknownStateText}
            setForm={setForm}
          />
          <SpeechSettingsSection
            form={form}
            snapshot={toolRuntimeSnapshot}
            speechIssues={speechIssues}
            speechSummary={speechSummary}
            unknownMessage={unknownMessage}
            unknownStateText={unknownStateText}
            setForm={setForm}
          />
        </div>
      </div>

      <RuntimeSettingsFooter
        notice={notice}
        backendConnected={backendConnected}
        probeState={toolRuntimeProbeState}
        probeTransport={toolRuntimeProbeTransport}
        probeError={lastToolRuntimeProbeError}
      />
    </div>
  );
}
