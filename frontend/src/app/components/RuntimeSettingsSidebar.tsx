import { RuntimeSettingsHeader } from "./RuntimeSettingsHeader";
import { RuntimeSettingsSidebarView } from "./RuntimeSettingsSidebarView";
import { useRuntimeSettingsSidebarModel } from "./useRuntimeSettingsSidebarModel";
import { useSidebar } from "./ui/sidebar";

export function RuntimeSettingsSidebar() {
  const { toggleSidebar } = useSidebar();
  const model = useRuntimeSettingsSidebarModel();

  return (
    <div className="meow-tile meow-tile-strong flex h-full flex-col overflow-hidden">
      <RuntimeSettingsHeader
        form={model.form}
        snapshot={model.toolRuntimeSnapshot}
        probeState={model.toolRuntimeProbeState}
        probeTransport={model.toolRuntimeProbeTransport}
        probeError={model.lastToolRuntimeProbeError}
        onClose={toggleSidebar}
      />
      <RuntimeSettingsSidebarView model={model} />
    </div>
  );
}
