import { RuntimeSettingsSidebar } from "../components/RuntimeSettingsSidebar";
import { Sidebar, SidebarContent, SidebarHeader, SidebarRail } from "../components/ui/sidebar";
import type { MainLayoutChromeProps } from "./mainLayoutChromeTypes";

export function MainSettingsChrome({
  settingsOpen,
  onCloseSettings,
}: Pick<MainLayoutChromeProps, "settingsOpen" | "onCloseSettings">) {
  return (
    <>
      {settingsOpen ? (
        <button
          type="button"
          aria-label="关闭设置侧栏"
          className="fixed inset-0 z-40 bg-slate-100/65 backdrop-blur-[1px]"
          onClick={onCloseSettings}
        />
      ) : null}

      <Sidebar side="right" variant="floating" collapsible="offcanvas" className="z-[60] pt-14 pb-10 pr-3">
        <SidebarHeader className="p-0" />
        <SidebarContent className="p-0">
          <RuntimeSettingsSidebar />
        </SidebarContent>
        <SidebarRail />
      </Sidebar>
    </>
  );
}
