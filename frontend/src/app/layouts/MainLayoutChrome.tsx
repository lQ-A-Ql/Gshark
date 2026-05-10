import { Activity, Box, FolderOpen, KeyRound, RefreshCw, Save, Settings2, ShieldAlert, Upload } from "lucide-react";
import { Link, type Location } from "react-router";
import type { ReactNode } from "react";
import logoImg from "../../assets/logo.png";
import { RuntimeSettingsSidebar } from "../components/RuntimeSettingsSidebar";
import { Sidebar, SidebarContent, SidebarHeader, SidebarRail, useSidebar } from "../components/ui/sidebar";
import { cn } from "../components/ui/utils";
import type { Packet } from "../core/types";
import { formatBytes } from "../state/SentinelContext";
import { NAV_ITEMS, type PageTheme } from "./mainLayoutConfig";

export interface MainLayoutChromeProps {
  activeTheme: PageTheme;
  backendConnected: boolean;
  backendStatus: string;
  decryptionConfigured: boolean;
  fileMeta: { name: string; sizeBytes: number };
  filteredPacketCount: number;
  packets: Packet[];
  settingsOpen: boolean;
  totalPackets: number;
  onApplyHttpFilter: () => void;
  onCloseSettings: () => void;
  onCopySelectedPacket: () => void;
  onExportEndpointStats: () => void;
  onExportPacketsJson: () => void;
  onExportProtocolStats: () => void;
  onFocusFilter: () => void;
  onFollowSelectedStream: () => void;
  onNavigate: (path: string) => void;
  onOpenCapture: () => void;
  onOpenSettings: () => void;
  onOpenTLSDialog: () => void;
  pathname: Location["pathname"];
}

export function MainHeader({
  onApplyHttpFilter,
  onCopySelectedPacket,
  onExportEndpointStats,
  onExportPacketsJson,
  onExportProtocolStats,
  onFocusFilter,
  onFollowSelectedStream,
  onNavigate,
  onOpenCapture,
  onOpenSettings,
  onOpenTLSDialog,
}: Pick<
  MainLayoutChromeProps,
  | "onApplyHttpFilter"
  | "onCopySelectedPacket"
  | "onExportEndpointStats"
  | "onExportPacketsJson"
  | "onExportProtocolStats"
  | "onFocusFilter"
  | "onFollowSelectedStream"
  | "onNavigate"
  | "onOpenCapture"
  | "onOpenSettings"
  | "onOpenTLSDialog"
>) {
  return (
    <header className="relative z-50 flex shrink-0 flex-col border-b border-slate-200 bg-white/92 shadow-[0_12px_32px_-24px_rgba(15,23,42,0.35)] backdrop-blur">
      <div className="flex h-12 items-center justify-between px-4">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <img
              src={logoImg}
              alt="Logo"
              className="h-10 w-auto object-contain drop-shadow-sm transition-[transform_0.2s] hover:scale-105"
            />
          </div>

          <nav className="ml-6 flex items-center gap-1 text-sm font-medium text-muted-foreground">
            <MenuGroup label="文件">
              <MenuItem onClick={onOpenCapture} icon={<FolderOpen className="h-4 w-4" />}>
                打开
              </MenuItem>
              <MenuItem onClick={onExportPacketsJson} icon={<Save className="h-4 w-4" />}>
                导出当前列表
              </MenuItem>
              <MenuItem onClick={onOpenCapture} icon={<Upload className="h-4 w-4" />}>
                导入...
              </MenuItem>
              <MenuItem onClick={() => onNavigate("/updates")} icon={<RefreshCw className="h-4 w-4" />}>
                检查更新
              </MenuItem>
              <MenuDivider />
              <MenuItem danger onClick={() => window.close()}>
                退出
              </MenuItem>
            </MenuGroup>

            <MenuGroup label="编辑">
              <MenuItem onClick={onCopySelectedPacket}>复制所选数据包</MenuItem>
              <MenuItem onClick={onFocusFilter}>查找数据包...</MenuItem>
              <MenuItem onClick={onOpenSettings}>首选项</MenuItem>
            </MenuGroup>

            <MenuGroup label="视图">
              <MenuItem onClick={() => onNavigate("/")}>返回主工作区</MenuItem>
              <MenuItem onClick={() => onNavigate("/analysis-cockpit")}>分析驾驶舱</MenuItem>
              <MenuItem onClick={() => onNavigate("/misc")}>MISC 工具箱</MenuItem>
              <MenuItem onClick={onFocusFilter}>聚焦过滤输入</MenuItem>
            </MenuGroup>

            <MenuGroup label="解密">
              <MenuItem onClick={onOpenTLSDialog} icon={<KeyRound className="h-4 w-4" />}>
                TLS 解密配置
              </MenuItem>
            </MenuGroup>

            <MenuGroup label="分析">
              <MenuItem onClick={() => onNavigate("/analysis-cockpit")}>分析驾驶舱</MenuItem>
              <MenuItem onClick={() => onNavigate("/c2-analysis")}>C2 样本分析</MenuItem>
              <MenuItem onClick={() => onNavigate("/apt-analysis")}>APT 组织画像</MenuItem>
              <MenuItem onClick={onApplyHttpFilter}>应用过滤器 http</MenuItem>
              <MenuItem onClick={() => onNavigate("/industrial-analysis")}>工控分析</MenuItem>
              <MenuItem onClick={() => onNavigate("/vehicle-analysis")}>车机分析</MenuItem>
              <MenuItem onClick={() => onNavigate("/media-analysis")}>媒体流还原</MenuItem>
              <MenuItem onClick={() => onNavigate("/usb-analysis")}>USB 分析</MenuItem>
              <MenuItem onClick={() => onNavigate("/misc")}>MISC 工具箱</MenuItem>
              <MenuItem onClick={onFollowSelectedStream}>追踪流</MenuItem>
              <MenuItem onClick={() => onNavigate("/hunting")}>专家信息</MenuItem>
            </MenuGroup>

            <MenuGroup label="统计">
              <MenuItem onClick={() => onNavigate("/traffic-graph")}>流量图</MenuItem>
              <MenuItem onClick={() => onNavigate("/industrial-analysis")}>工控分析</MenuItem>
              <MenuItem onClick={() => onNavigate("/vehicle-analysis")}>车机分析</MenuItem>
              <MenuItem onClick={() => onNavigate("/media-analysis")}>媒体流还原</MenuItem>
              <MenuItem onClick={() => onNavigate("/usb-analysis")}>USB 分析</MenuItem>
              <MenuItem onClick={onExportEndpointStats}>端点统计导出</MenuItem>
              <MenuItem onClick={onExportProtocolStats}>协议统计导出</MenuItem>
            </MenuGroup>
          </nav>
        </div>

        <div className="flex items-center gap-2 text-xs font-medium">
          <HeaderSettingsButton />
          <span className="flex items-center gap-1 rounded-full border border-rose-200 bg-rose-50 px-2.5 py-1.5 text-rose-600 shadow-sm">
            <ShieldAlert className="h-3.5 w-3.5" /> OWASP
          </span>
          <span className="flex items-center gap-1 rounded-full border border-emerald-200 bg-emerald-50 px-2.5 py-1.5 text-emerald-600 shadow-sm">
            <Activity className="h-3.5 w-3.5" /> CTF
          </span>
          <button
            type="button"
            onClick={onOpenTLSDialog}
            className="flex items-center gap-1 rounded-full border border-amber-200 bg-amber-50 px-2.5 py-1.5 text-amber-600 shadow-sm transition hover:bg-amber-100 hover:text-amber-700"
            title="打开 TLS 解密配置"
          >
            <KeyRound className="h-3.5 w-3.5" /> 解密
          </button>
        </div>
      </div>
    </header>
  );
}

function HeaderSettingsButton() {
  const { toggleSidebar } = useSidebar();
  return (
    <button
      type="button"
      onClick={toggleSidebar}
      className="mr-1 inline-flex h-8 w-8 items-center justify-center rounded-md border border-slate-200 bg-white text-slate-600 transition hover:bg-slate-50 hover:text-slate-900"
      title="打开设置侧栏"
    >
      <Settings2 className="h-4 w-4" />
    </button>
  );
}

export function MainSidebarNav({ activeTheme, pathname }: Pick<MainLayoutChromeProps, "activeTheme" | "pathname">) {
  return (
    <aside className="z-40 flex w-16 shrink-0 flex-col items-center gap-4 border-r border-slate-200 bg-white/88 py-4 shadow-[8px_0_24px_-24px_rgba(15,23,42,0.28)] backdrop-blur">
      {NAV_ITEMS.map((item) => {
        const Icon = item.icon;
        const isActive = pathname === item.path;
        return (
          <Link
            key={item.path}
            to={item.path}
            title={item.label}
            className={cn(
              "group relative rounded-2xl p-3 transition-all",
              isActive ? activeTheme.active : "text-muted-foreground hover:bg-slate-100 hover:text-slate-900",
            )}
          >
            <Icon className="h-5 w-5" />
            {isActive && (
              <div className={cn("absolute left-0 top-1/2 h-6 w-1 -translate-y-1/2 rounded-r-full", activeTheme.bar)} />
            )}
            <div className="pointer-events-none invisible absolute left-full top-1/2 z-50 ml-3 -translate-y-1/2 whitespace-nowrap rounded-xl border border-slate-200 bg-white/95 px-2.5 py-1.5 text-xs font-semibold text-slate-700 opacity-0 shadow-[0_18px_42px_rgba(15,23,42,0.14)] backdrop-blur transition-all group-hover:visible group-hover:opacity-100">
              {item.label}
            </div>
          </Link>
        );
      })}
    </aside>
  );
}

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

export function MainFooter({
  backendConnected,
  backendStatus,
  decryptionConfigured,
  fileMeta,
  filteredPacketCount,
  packets,
  totalPackets,
}: Pick<
  MainLayoutChromeProps,
  | "backendConnected"
  | "backendStatus"
  | "decryptionConfigured"
  | "fileMeta"
  | "filteredPacketCount"
  | "packets"
  | "totalPackets"
>) {
  return (
    <footer className="z-40 flex h-8 shrink-0 items-center justify-between border-t border-slate-200 bg-white/90 px-4 text-[11px] font-medium tracking-wider text-slate-500 backdrop-blur">
      <div className="flex items-center gap-4">
        <span className="flex items-center gap-1">
          <Box className="h-3.5 w-3.5" /> 当前: {fileMeta.name} ({formatBytes(fileMeta.sizeBytes)})
        </span>
        <span className="flex items-center gap-1 text-blue-600">
          显示: {filteredPacketCount.toLocaleString()} / 缓存: {packets.length.toLocaleString()} / 后端总计:{" "}
          {totalPackets.toLocaleString()}
        </span>
      </div>
      <div className="flex items-center gap-4">
        <span className="flex items-center gap-1 text-amber-600">
          <KeyRound className="h-3.5 w-3.5" /> TLS 解密: {decryptionConfigured ? "SSLKEYLOGFILE 已加载" : "未配置"}
        </span>
        <span
          className={cn("flex items-center gap-1", backendConnected ? "text-emerald-600" : "text-muted-foreground")}
        >
          <Activity className="h-3.5 w-3.5" /> 引擎: {backendStatus}
        </span>
      </div>
    </footer>
  );
}

function MenuGroup({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="group relative">
      <button className="cursor-default rounded-lg px-3 py-1.5 transition-colors hover:bg-cyan-50 hover:text-cyan-700">
        {label}
      </button>
      <div className="invisible absolute left-0 top-full z-50 mt-1 max-h-[calc(100vh-5rem)] min-w-[190px] overflow-auto rounded-xl border border-slate-200 bg-white/95 py-1.5 opacity-0 shadow-[0_24px_64px_rgba(15,23,42,0.16)] backdrop-blur transition-all group-hover:visible group-hover:opacity-100">
        {children}
      </div>
    </div>
  );
}

function MenuItem({
  children,
  onClick,
  icon,
  danger = false,
}: {
  children: ReactNode;
  onClick: () => void;
  icon?: ReactNode;
  danger?: boolean;
}) {
  return (
    <div
      className={cn(
        "flex cursor-pointer items-center gap-2 px-3 py-2 text-xs font-medium text-slate-700 transition-colors",
        danger ? "hover:bg-rose-50 hover:text-rose-700" : "hover:bg-cyan-50 hover:text-cyan-700",
      )}
      onClick={onClick}
    >
      {icon}
      <span>{children}</span>
    </div>
  );
}

function MenuDivider() {
  return <div className="my-1 h-px bg-border" />;
}
