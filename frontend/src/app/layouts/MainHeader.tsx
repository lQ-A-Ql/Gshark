import type { ReactNode } from "react";
import { Activity, FolderOpen, KeyRound, RefreshCw, Save, Settings2, ShieldAlert, Upload } from "lucide-react";
import logoImg from "../../assets/logo.png";
import { useSidebar } from "../components/ui/sidebar";
import { cn } from "../components/ui/utils";
import type { MainLayoutChromeProps } from "./mainLayoutChromeTypes";

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
    <header className="relative z-50 flex shrink-0 flex-col border-b border-white/18 bg-white/42 shadow-[0_0_34px_rgba(255,255,255,0.12)] backdrop-blur-xl">
      <div className="flex h-12 items-center justify-between px-4">
        <div className="flex items-center gap-4">
          <img src={logoImg} alt="Logo" className="gshark-brand-mark h-10 w-auto object-contain" />

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
          <span className="gshark-control flex items-center gap-1 px-2.5 py-1.5 text-rose-600">
            <ShieldAlert className="h-3.5 w-3.5" /> OWASP
          </span>
          <span className="gshark-control flex items-center gap-1 px-2.5 py-1.5 text-emerald-600">
            <Activity className="h-3.5 w-3.5" /> CTF
          </span>
          <button
            type="button"
            onClick={onOpenTLSDialog}
            className="gshark-control flex items-center gap-1 px-2.5 py-1.5 text-amber-600 transition hover:text-amber-700"
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
      className="gshark-control-ghost mr-1 inline-flex h-8 w-8 items-center justify-center text-slate-600 transition hover:text-slate-900"
      title="打开设置侧栏"
    >
      <Settings2 className="h-4 w-4" />
    </button>
  );
}

function MenuGroup({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="group relative">
      <button className="gshark-control-ghost cursor-default px-3 py-1.5 transition-colors hover:text-cyan-700">
        {label}
      </button>
      <div className="gshark-form-surface invisible absolute left-0 top-full z-50 mt-1 max-h-[calc(100vh-5rem)] min-w-[190px] overflow-auto py-1.5 opacity-0 shadow-[0_24px_64px_rgba(15,23,42,0.08),0_0_44px_rgba(255,255,255,0.22)] backdrop-blur-xl transition-all group-hover:visible group-hover:opacity-100">
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
        danger ? "hover:bg-rose-50/24 hover:text-rose-700" : "hover:bg-cyan-50/24 hover:text-cyan-700",
      )}
      onClick={onClick}
    >
      {icon}
      <span>{children}</span>
    </div>
  );
}

function MenuDivider() {
  return <div className="my-1 h-px bg-white/18" />;
}
