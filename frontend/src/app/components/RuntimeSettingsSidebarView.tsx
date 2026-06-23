import type { useRuntimeSettingsSidebarModel } from "./useRuntimeSettingsSidebarModel";
import {
  CaptureSettingsSection,
  MCPSettingsSection,
  MediaSettingsSection,
  SpeechSettingsSection,
  YaraSettingsSection,
} from "./RuntimeSettingsSections";
import { RuntimeSettingsActions, RuntimeSettingsFooter } from "./RuntimeSettingsShell";

type Model = ReturnType<typeof useRuntimeSettingsSidebarModel>;

export function RuntimeSettingsSidebarView({ model }: { model: Model }) {
  return (
    <>
      <div className="flex flex-1 flex-col overflow-hidden">
        <RuntimeSettingsActions
          busy={model.busy}
          loading={model.isToolRuntimeLoading || model.toolRuntimeProbeState === "probing_full"}
          backendConnected={model.backendConnected}
          dirty={model.dirty}
          onRefresh={() => void model.refresh()}
          onSave={() => void model.save()}
        />
        <div className="flex-1 space-y-3 overflow-auto bg-white px-5 py-5">
          <MCPSettingsSection
            backendConnected={model.backendConnected}
            busy={model.busy}
            mcpBusy={model.mcpBusy}
            mcpStatus={model.mcpStatus}
            mcpNotice={model.mcpNotice}
            authToken={model.authToken}
            tokenAvailable={model.tokenAvailable}
            tokenBusy={model.tokenBusy}
            onRefresh={() => void model.refreshMCP()}
            onToggleEnabled={(enabled) => void model.saveMCP(enabled)}
            onCopyEndpoint={() => void model.copyEndpoint()}
            onCopyToken={() => void model.copyToken()}
          />
          <CaptureSettingsSection
            form={model.form}
            snapshot={model.toolRuntimeSnapshot}
            unknownMessage={model.unknownMessage}
            unknownStateText={model.unknownStateText}
            setForm={model.setForm}
            {...model.tsharkDirControls}
          />
          <YaraSettingsSection {...sectionProps(model)} />
          <MediaSettingsSection {...sectionProps(model)} />
          <SpeechSettingsSection
            {...sectionProps(model)}
            speechIssues={model.speechIssues}
            speechSummary={model.speechSummary}
          />
        </div>
      </div>
      <RuntimeSettingsFooter
        notice={model.notice}
        backendConnected={model.backendConnected}
        probeState={model.toolRuntimeProbeState}
        probeTransport={model.toolRuntimeProbeTransport}
        probeError={model.lastToolRuntimeProbeError}
        probeTransportError={model.probeTransportError}
        snapshot={model.toolRuntimeSnapshot}
      />
    </>
  );
}

function sectionProps(model: Model) {
  return {
    form: model.form,
    snapshot: model.toolRuntimeSnapshot,
    unknownMessage: model.unknownMessage,
    unknownStateText: model.unknownStateText,
    allowToolDir: model.allowToolDir,
    setForm: model.setForm,
  };
}
