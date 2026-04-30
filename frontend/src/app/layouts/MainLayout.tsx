import { Outlet, Link, useLocation, useNavigate } from "react-router";
import {
  Activity,
  BarChart3,
  Box,
  Bug,
  Car,
  Clapperboard,
  Crosshair,
  Factory,
  FileDown,
  FolderOpen,
  KeyRound,
  LayoutDashboard,
  Wrench,
  Radar,
  RefreshCw,
  Save,
  Settings2,
  ShieldAlert,
  Upload,
  Usb,
} from "lucide-react";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import logoImg from "../../assets/logo.png";
import { useEffect, useLayoutEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { formatBytes, useSentinel } from "../state/SentinelContext";
import {
  Sidebar,
  SidebarContent,
  SidebarHeader,
  SidebarProvider,
  SidebarRail,
  useSidebar,
} from "../components/ui/sidebar";
import { RuntimeSettingsSidebar } from "../components/RuntimeSettingsSidebar";
import { TLSDecryptionDialog } from "../components/TLSDecryptionDialog";

function cn(...inputs: (string | undefined | null | false)[]) {
  return twMerge(clsx(inputs));
}

const NAV_ITEMS = [
  { path: "/", icon: LayoutDashboard, label: "主工作区", theme: "blue" },
  { path: "/analysis-cockpit", icon: Radar, label: "分析驾驶舱", theme: "indigo" },
  { path: "/c2-analysis", icon: Bug, label: "C2 样本分析", theme: "rose" },
  { path: "/apt-analysis", icon: Crosshair, label: "APT 组织画像", theme: "indigo" },
  { path: "/traffic-graph", icon: BarChart3, label: "流量图", theme: "amber" },
  { path: "/industrial-analysis", icon: Factory, label: "工控分析", theme: "blue" },
  { path: "/vehicle-analysis", icon: Car, label: "车机分析", theme: "emerald" },
  { path: "/media-analysis", icon: Clapperboard, label: "媒体流还原", theme: "rose" },
  { path: "/usb-analysis", icon: Usb, label: "USB 分析", theme: "cyan" },
  { path: "/hunting", icon: ShieldAlert, label: "威胁狩猎中心", theme: "rose" },
  { path: "/objects", icon: FileDown, label: "附件提取", theme: "amber" },
  { path: "/misc", icon: Wrench, label: "MISC 工具箱", theme: "cyan" },
  { path: "/updates", icon: RefreshCw, label: "检查更新", theme: "blue" },
];

const PAGE_THEMES = {
  blue: {
    base: "239 246 255",
    top: "248 250 252",
    bottom: "241 245 249",
    accent: "59 130 246",
    accent2: "14 165 233",
    active: "bg-blue-50 text-blue-600 shadow-[0_12px_30px_-20px_rgba(37,99,235,0.55)]",
    bar: "bg-blue-600",
  },
  indigo: {
    base: "238 242 255",
    top: "248 250 252",
    bottom: "245 243 255",
    accent: "99 102 241",
    accent2: "59 130 246",
    active: "bg-indigo-50 text-indigo-600 shadow-[0_12px_30px_-20px_rgba(79,70,229,0.55)]",
    bar: "bg-indigo-600",
  },
  amber: {
    base: "255 251 235",
    top: "255 253 244",
    bottom: "248 250 252",
    accent: "245 158 11",
    accent2: "251 191 36",
    active: "bg-amber-50 text-amber-600 shadow-[0_12px_30px_-20px_rgba(217,119,6,0.55)]",
    bar: "bg-amber-500",
  },
  emerald: {
    base: "236 253 245",
    top: "248 250 252",
    bottom: "240 253 244",
    accent: "16 185 129",
    accent2: "20 184 166",
    active: "bg-emerald-50 text-emerald-600 shadow-[0_12px_30px_-20px_rgba(5,150,105,0.55)]",
    bar: "bg-emerald-500",
  },
  rose: {
    base: "255 241 242",
    top: "255 251 252",
    bottom: "248 250 252",
    accent: "244 63 94",
    accent2: "251 113 133",
    active: "bg-rose-50 text-rose-600 shadow-[0_12px_30px_-20px_rgba(225,29,72,0.55)]",
    bar: "bg-rose-500",
  },
  cyan: {
    base: "236 254 255",
    top: "248 250 252",
    bottom: "240 249 255",
    accent: "6 182 212",
    accent2: "14 165 233",
    active: "bg-cyan-50 text-cyan-600 shadow-[0_12px_30px_-20px_rgba(8,145,178,0.55)]",
    bar: "bg-cyan-500",
  },
} as const;

type PageThemeName = keyof typeof PAGE_THEMES;
type BackgroundFadeState = {
  key: string;
  style: CSSProperties;
};

type BrowserDragEventLike = {
  preventDefault: () => void;
  stopPropagation: () => void;
  target?: EventTarget | null;
};

function isExplicitDropZone(target: EventTarget | null | undefined) {
  return target instanceof Element && Boolean(target.closest("[data-gshark-drop-zone='true']"));
}

export function preventBrowserPageDrag(event: BrowserDragEventLike) {
  if (isExplicitDropZone(event.target)) {
    return;
  }
  event.preventDefault();
  event.stopPropagation();
}

export function installBrowserPageDragGuard() {
  window.addEventListener("dragstart", preventBrowserPageDrag, { capture: true });
  window.addEventListener("dragover", preventBrowserPageDrag, { capture: true });
  window.addEventListener("drop", preventBrowserPageDrag, { capture: true });
  document.addEventListener("dragstart", preventBrowserPageDrag, { capture: true });
  document.addEventListener("dragover", preventBrowserPageDrag, { capture: true });
  document.addEventListener("drop", preventBrowserPageDrag, { capture: true });
  return () => {
    window.removeEventListener("dragstart", preventBrowserPageDrag, { capture: true });
    window.removeEventListener("dragover", preventBrowserPageDrag, { capture: true });
    window.removeEventListener("drop", preventBrowserPageDrag, { capture: true });
    document.removeEventListener("dragstart", preventBrowserPageDrag, { capture: true });
    document.removeEventListener("dragover", preventBrowserPageDrag, { capture: true });
    document.removeEventListener("drop", preventBrowserPageDrag, { capture: true });
  };
}

function themeForPath(pathname: string): (typeof PAGE_THEMES)[PageThemeName] {
  const navTheme = NAV_ITEMS.find((item) => item.path !== "/" && pathname.startsWith(item.path))?.theme
    ?? (pathname === "/" ? "blue" : pathname.includes("udp") ? "cyan" : pathname.includes("http") ? "cyan" : "blue");
  return PAGE_THEMES[navTheme as PageThemeName] ?? PAGE_THEMES.blue;
}

export function MainLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [tlsDialogOpen, setTlsDialogOpen] = useState(false);
  const [backgroundFade, setBackgroundFade] = useState<BackgroundFadeState | null>(null);
  const backgroundRouteRef = useRef(location.pathname);
  const backgroundThemeStyleRef = useRef<CSSProperties | null>(null);
  const {
    fileMeta,
    filteredPackets,
    packets,
    totalPackets,
    decryptionConfig,
    backendConnected,
    backendStatus,
    openCapture,
    selectedPacket,
    setDisplayFilter,
    applyFilter,
  } = useSentinel();

  const downloadText = (filename: string, content: string, mime = "text/plain;charset=utf-8") => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  };

  const exportPacketsJson = () => {
    downloadText(
      `packets-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.json`,
      JSON.stringify(filteredPackets, null, 2),
      "application/json;charset=utf-8",
    );
  };

  const copySelectedPacket = async () => {
    if (!selectedPacket) return;
    const text = [
      `#${selectedPacket.id} ${selectedPacket.time}`,
      `${selectedPacket.src}:${selectedPacket.srcPort} -> ${selectedPacket.dst}:${selectedPacket.dstPort}`,
      `${selectedPacket.proto} len=${selectedPacket.length}`,
      selectedPacket.info,
    ].join("\n");
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // ignore clipboard failures
    }
  };

  const followSelectedStream = () => {
    if (!selectedPacket || selectedPacket.streamId == null) return;
    if (selectedPacket.proto === "HTTP") {
      navigate("/http-stream");
      return;
    }
    if (selectedPacket.proto === "UDP") {
      navigate("/udp-stream");
      return;
    }
    navigate("/tcp-stream");
  };

  const exportProtocolStats = () => {
    const stats = packets.reduce<Record<string, number>>((acc, p) => {
      acc[p.proto] = (acc[p.proto] ?? 0) + 1;
      return acc;
    }, {});
    downloadText("protocol-stats.json", JSON.stringify(stats, null, 2), "application/json;charset=utf-8");
  };

  const exportEndpointStats = () => {
    const stats = packets.reduce<Record<string, number>>((acc, p) => {
      const key = `${p.src}:${p.srcPort} -> ${p.dst}:${p.dstPort}`;
      acc[key] = (acc[key] ?? 0) + 1;
      return acc;
    }, {});
    const rows = Object.entries(stats)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 200)
      .map(([key, value]) => `${key},${value}`)
      .join("\n");
    downloadText("endpoint-stats.csv", `endpoint,count\n${rows}`);
  };

  useEffect(() => {
    localStorage.setItem("gshark-theme", "light");
  }, []);

  useEffect(() => {
    return installBrowserPageDragGuard();
  }, []);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.ctrlKey && event.key.toLowerCase() === "f") {
        event.preventDefault();
        window.dispatchEvent(new CustomEvent("gshark:focus-filter"));
      }
      if (event.ctrlKey && event.key.toLowerCase() === "o") {
        event.preventDefault();
        void openCapture();
      }
      if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "t") {
        event.preventDefault();
        void navigate("/tcp-stream");
      }
    };

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [navigate, openCapture]);

  const HeaderSettingsButton = () => {
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
  };

  const activeTheme = themeForPath(location.pathname);
  const pageThemeStyle = {
    "--gshark-bg-base": activeTheme.base,
    "--gshark-bg-top": activeTheme.top,
    "--gshark-bg-bottom": activeTheme.bottom,
    "--gshark-bg-accent": activeTheme.accent,
    "--gshark-bg-accent-2": activeTheme.accent2,
  } as CSSProperties;

  useLayoutEffect(() => {
    const previousStyle = backgroundThemeStyleRef.current;
    if (backgroundRouteRef.current !== location.pathname && previousStyle) {
      setBackgroundFade({
        key: location.pathname,
        style: { ...previousStyle },
      });
    }

    backgroundRouteRef.current = location.pathname;
    backgroundThemeStyleRef.current = pageThemeStyle;
  }, [
    location.pathname,
    activeTheme.accent,
    activeTheme.accent2,
    activeTheme.base,
    activeTheme.bottom,
    activeTheme.top,
  ]);

  return (
    <SidebarProvider
      open={settingsOpen}
      onOpenChange={setSettingsOpen}
      style={
        {
          "--sidebar-width": "31rem",
        } as CSSProperties
      }
    >
      <div
        className="gshark-page-bg flex h-screen w-screen flex-col overflow-hidden font-sans text-foreground selection:bg-blue-200 selection:text-blue-900"
        style={pageThemeStyle}
        onDragStartCapture={preventBrowserPageDrag}
        onDragOverCapture={preventBrowserPageDrag}
        onDropCapture={preventBrowserPageDrag}
      >
        <header className="relative z-50 flex shrink-0 flex-col border-b border-slate-200 bg-white/92 shadow-[0_12px_32px_-24px_rgba(15,23,42,0.35)] backdrop-blur">
          <div className="flex h-12 items-center justify-between px-4">
            <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <img src={logoImg} alt="Logo" className="h-10 w-auto object-contain drop-shadow-sm transition-[transform_0.2s] hover:scale-105" /></div>

              <nav className="ml-6 flex items-center gap-1 text-sm font-medium text-muted-foreground">
                <MenuGroup label="文件">
                  <MenuItem onClick={() => void openCapture()} icon={<FolderOpen className="h-4 w-4" />}>打开</MenuItem>
                  <MenuItem onClick={exportPacketsJson} icon={<Save className="h-4 w-4" />}>导出当前列表</MenuItem>
                  <MenuItem onClick={() => void openCapture()} icon={<Upload className="h-4 w-4" />}>导入...</MenuItem>
                  <MenuItem onClick={() => navigate("/updates")} icon={<RefreshCw className="h-4 w-4" />}>检查更新</MenuItem>
                  <MenuDivider />
                  <MenuItem danger onClick={() => window.close()}>退出</MenuItem>
                </MenuGroup>

                <MenuGroup label="编辑">
                  <MenuItem onClick={() => void copySelectedPacket()}>复制所选数据包</MenuItem>
                  <MenuItem onClick={() => window.dispatchEvent(new CustomEvent("gshark:focus-filter"))}>查找数据包...</MenuItem>
                  <MenuItem onClick={() => setSettingsOpen(true)}>首选项</MenuItem>
                </MenuGroup>

                <MenuGroup label="视图">
                  <MenuItem onClick={() => navigate("/")}>返回主工作区</MenuItem>
                  <MenuItem onClick={() => navigate("/analysis-cockpit")}>分析驾驶舱</MenuItem>
                  <MenuItem onClick={() => navigate("/misc")}>MISC 工具箱</MenuItem>
                  <MenuItem onClick={() => window.dispatchEvent(new CustomEvent("gshark:focus-filter"))}>聚焦过滤输入</MenuItem>
                </MenuGroup>

                <MenuGroup label="解密">
                  <MenuItem onClick={() => setTlsDialogOpen(true)} icon={<KeyRound className="h-4 w-4" />}>TLS 解密配置</MenuItem>
                </MenuGroup>

                <MenuGroup label="分析">
                  <MenuItem onClick={() => navigate("/analysis-cockpit")}>分析驾驶舱</MenuItem>
                  <MenuItem onClick={() => navigate("/c2-analysis")}>C2 样本分析</MenuItem>
                  <MenuItem onClick={() => navigate("/apt-analysis")}>APT 组织画像</MenuItem>
                  <MenuItem
                    onClick={() => {
                      setDisplayFilter("http");
                      applyFilter("http");
                    }}
                  >
                    应用过滤器 http
                  </MenuItem>
                  <MenuItem onClick={() => navigate("/industrial-analysis")}>工控分析</MenuItem>
                  <MenuItem onClick={() => navigate("/vehicle-analysis")}>车机分析</MenuItem>
                  <MenuItem onClick={() => navigate("/media-analysis")}>媒体流还原</MenuItem>
                  <MenuItem onClick={() => navigate("/usb-analysis")}>USB 分析</MenuItem>
                  <MenuItem onClick={() => navigate("/misc")}>MISC 工具箱</MenuItem>
                  <MenuItem onClick={followSelectedStream}>追踪流</MenuItem>
                  <MenuItem onClick={() => navigate("/hunting")}>专家信息</MenuItem>
                </MenuGroup>

                <MenuGroup label="统计">
                  <MenuItem onClick={() => navigate("/traffic-graph")}>流量图</MenuItem>
                  <MenuItem onClick={() => navigate("/industrial-analysis")}>工控分析</MenuItem>
                  <MenuItem onClick={() => navigate("/vehicle-analysis")}>车机分析</MenuItem>
                  <MenuItem onClick={() => navigate("/media-analysis")}>媒体流还原</MenuItem>
                  <MenuItem onClick={() => navigate("/usb-analysis")}>USB 分析</MenuItem>
                  <MenuItem onClick={exportEndpointStats}>端点统计导出</MenuItem>
                  <MenuItem onClick={exportProtocolStats}>协议统计导出</MenuItem>
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
                onClick={() => setTlsDialogOpen(true)}
                className="flex items-center gap-1 rounded-full border border-amber-200 bg-amber-50 px-2.5 py-1.5 text-amber-600 shadow-sm transition hover:bg-amber-100 hover:text-amber-700"
                title="打开 TLS 解密配置"
              >
                <KeyRound className="h-3.5 w-3.5" /> 解密
              </button>
            </div>
          </div>
        </header>

        <div className="flex flex-1 overflow-hidden">
          <aside className="z-40 flex w-16 shrink-0 flex-col items-center gap-4 border-r border-slate-200 bg-white/88 py-4 shadow-[8px_0_24px_-24px_rgba(15,23,42,0.28)] backdrop-blur">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  title={item.label}
                  className={cn(
                    "group relative rounded-2xl p-3 transition-all",
                    isActive
                      ? activeTheme.active
                      : "text-muted-foreground hover:bg-slate-100 hover:text-slate-900",
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

          <main className="gshark-page-bg gshark-theme-main relative flex min-w-0 flex-1 flex-col overflow-hidden">
            {backgroundFade ? (
              <div
                key={backgroundFade.key}
                aria-hidden="true"
                className="gshark-page-bg gshark-theme-fade"
                style={backgroundFade.style}
                onAnimationEnd={() => setBackgroundFade(null)}
              />
            ) : null}
            <div key={location.pathname} className="gshark-route-transition flex min-h-0 flex-1 flex-col overflow-hidden">
              <Outlet />
            </div>
          </main>
        </div>

        {settingsOpen ? (
          <button
            type="button"
            aria-label="关闭设置侧栏"
            className="fixed inset-0 z-40 bg-slate-100/65 backdrop-blur-[1px]"
            onClick={() => setSettingsOpen(false)}
          />
        ) : null}

        <Sidebar
          side="right"
          variant="floating"
          collapsible="offcanvas"
          className="z-[60] pt-14 pb-10 pr-3"
        >
          <SidebarHeader className="p-0" />
          <SidebarContent className="p-0">
            <RuntimeSettingsSidebar />
          </SidebarContent>
          <SidebarRail />
        </Sidebar>

        <footer className="z-40 flex h-8 shrink-0 items-center justify-between border-t border-slate-200 bg-white/90 px-4 text-[11px] font-medium tracking-wider text-slate-500 backdrop-blur">
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1"><Box className="h-3.5 w-3.5" /> 当前: {fileMeta.name} ({formatBytes(fileMeta.sizeBytes)})</span>
            <span className="flex items-center gap-1 text-blue-600">
              显示: {filteredPackets.length.toLocaleString()} / 缓存: {packets.length.toLocaleString()} / 后端总计: {totalPackets.toLocaleString()}
            </span>
          </div>
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1 text-amber-600"><KeyRound className="h-3.5 w-3.5" /> TLS 解密: {decryptionConfig.sslKeyLogPath ? "SSLKEYLOGFILE 已加载" : "未配置"}</span>
            <span className={cn("flex items-center gap-1", backendConnected ? "text-emerald-600" : "text-muted-foreground")}>
              <Activity className="h-3.5 w-3.5" /> 引擎: {backendStatus}
            </span>
          </div>
        </footer>
        <TLSDecryptionDialog open={tlsDialogOpen} onOpenChange={setTlsDialogOpen} />
      </div>
    </SidebarProvider>
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


