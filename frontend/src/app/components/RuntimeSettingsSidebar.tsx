import {
  CaptureSettingsSection,
  MCPSettingsSection,
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
    mcpBusy,
    mcpNotice,
    mcpStatus,
    notice,
    probeTransportError,
    setForm,
    speechIssues,
    speechSummary,
    authToken,
    tokenAvailable,
    tokenBusy,
    unknownMessage,
    unknownStateText,
    copyEndpoint,
    copyToken,
    refreshMCP,
    saveMCP,
  } = useRuntimeSettingsSidebarModel();

  return (
    <div className="meow-tile meow-tile-strong flex h-full flex-col overflow-hidden">
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
          loading={isToolRuntimeLoading || toolRuntimeProbeState === "probing_full"}
          backendConnected={backendConnected}
          dirty={dirty}
          onRefresh={() => void refresh()}
          onSave={() => void save()}
        />

        <div className="flex-1 space-y-3 overflow-auto bg-white px-5 py-5">
          <MCPSettingsSection
            backendConnected={backendConnected}
            busy={busy}
            mcpBusy={mcpBusy}
            mcpStatus={mcpStatus}
            mcpNotice={mcpNotice}
            authToken={authToken}
            tokenAvailable={tokenAvailable}
            tokenBusy={tokenBusy}
            onRefresh={() => void refreshMCP()}
            onToggleEnabled={(enabled) => void saveMCP(enabled)}
            onCopyEndpoint={() => void copyEndpoint()}
            onCopyToken={() => void copyToken()}
          />
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
        probeTransportError={probeTransportError}
        snapshot={toolRuntimeSnapshot}
      />
    </div>
  );
}
