import { Outlet, Link, useLocation, useNavigate } from "react-router";
import {
  Activity,
  BarChart3,
  Box,
  Car,
  Clapperboard,
  Factory,
  FileDown,
  FolderOpen,
  Hexagon,
  KeyRound,
  LayoutDashboard,
  Puzzle,
  Save,
  ScrollText,
  ShieldAlert,
  Upload,
  Usb,
} from "lucide-react";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { useEffect, type ReactNode } from "react";
import { formatBytes, useSentinel } from "../state/SentinelContext";

function cn(...inputs: (string | undefined | null | false)[]) {
  return twMerge(clsx(inputs));
}

const NAV_ITEMS = [
  { path: "/", icon: LayoutDashboard, label: "主工作区" },
  { path: "/traffic-graph", icon: BarChart3, label: "流量图" },
  { path: "/industrial-analysis", icon: Factory, label: "工控分析" },
  { path: "/vehicle-analysis", icon: Car, label: "车机分析" },
  { path: "/media-analysis", icon: Clapperboard, label: "视频流还原" },
  { path: "/usb-analysis", icon: Usb, label: "USB 分析" },
  { path: "/hunting", icon: ShieldAlert, label: "威胁狩猎中心" },
  { path: "/objects", icon: FileDown, label: "附件提取" },
  { path: "/decryption", icon: KeyRound, label: "TLS 解密" },
  { path: "/plugins", icon: Puzzle, label: "插件管理" },
  { path: "/audit-logs", icon: ScrollText, label: "审计日志" },
];

export function MainLayout() {
  const location = useLocation();
  const navigate = useNavigate();
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
    document.documentElement.classList.remove("dark");
    localStorage.setItem("gshark-theme", "light");
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

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-background font-sans text-foreground selection:bg-blue-200 selection:text-blue-900">
      <header className="relative z-50 flex shrink-0 flex-col border-b border-border bg-card shadow-sm">
        <div className="flex h-12 items-center justify-between px-4">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 font-semibold tracking-wide text-blue-600">
              <Hexagon className="h-6 w-6" />
              <span className="text-lg">GShark-Sentinel</span>
            </div>

            <nav className="ml-6 flex items-center gap-1 text-sm font-medium text-muted-foreground">
              <MenuGroup label="文件">
                <MenuItem onClick={() => void openCapture()} icon={<FolderOpen className="h-4 w-4" />}>打开</MenuItem>
                <MenuItem onClick={exportPacketsJson} icon={<Save className="h-4 w-4" />}>导出当前列表</MenuItem>
                <MenuItem onClick={() => void openCapture()} icon={<Upload className="h-4 w-4" />}>导入...</MenuItem>
                <MenuDivider />
                <MenuItem danger onClick={() => window.close()}>退出</MenuItem>
              </MenuGroup>

              <MenuGroup label="编辑">
                <MenuItem onClick={() => void copySelectedPacket()}>复制所选数据包</MenuItem>
                <MenuItem onClick={() => window.dispatchEvent(new CustomEvent("gshark:focus-filter"))}>查找数据包...</MenuItem>
                <MenuItem onClick={() => navigate("/plugins")}>首选项</MenuItem>
              </MenuGroup>

              <MenuGroup label="视图">
                <MenuItem onClick={() => navigate("/")}>返回主工作区</MenuItem>
                <MenuItem onClick={() => navigate("/decryption")}>TLS 解密</MenuItem>
                <MenuItem onClick={() => window.dispatchEvent(new CustomEvent("gshark:focus-filter"))}>聚焦过滤输入</MenuItem>
              </MenuGroup>

              <MenuGroup label="分析">
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
                <MenuItem onClick={() => navigate("/media-analysis")}>视频流还原</MenuItem>
                <MenuItem onClick={() => navigate("/usb-analysis")}>USB 分析</MenuItem>
                <MenuItem onClick={() => navigate("/audit-logs")}>审计日志</MenuItem>
                <MenuItem onClick={followSelectedStream}>追踪流</MenuItem>
                <MenuItem onClick={() => navigate("/hunting")}>专家信息</MenuItem>
              </MenuGroup>

              <MenuGroup label="统计">
                <MenuItem onClick={() => navigate("/traffic-graph")}>流量图</MenuItem>
                <MenuItem onClick={() => navigate("/industrial-analysis")}>工控分析</MenuItem>
                <MenuItem onClick={() => navigate("/vehicle-analysis")}>车机分析</MenuItem>
                <MenuItem onClick={() => navigate("/media-analysis")}>视频流还原</MenuItem>
                <MenuItem onClick={() => navigate("/usb-analysis")}>USB 分析</MenuItem>
                <MenuItem onClick={exportEndpointStats}>端点统计导出</MenuItem>
                <MenuItem onClick={exportProtocolStats}>协议统计导出</MenuItem>
              </MenuGroup>
            </nav>
          </div>

          <div className="flex items-center gap-2 text-xs font-medium">
            <span className="flex items-center gap-1 rounded-md border border-rose-200 bg-rose-50 px-2.5 py-1.5 text-rose-600">
              <ShieldAlert className="h-3.5 w-3.5" /> OWASP
            </span>
            <span className="flex items-center gap-1 rounded-md border border-emerald-200 bg-emerald-50 px-2.5 py-1.5 text-emerald-600">
              <Activity className="h-3.5 w-3.5" /> CTF
            </span>
            <span className="flex items-center gap-1 rounded-md border border-amber-200 bg-amber-50 px-2.5 py-1.5 text-amber-600">
              <KeyRound className="h-3.5 w-3.5" /> 解密
            </span>
          </div>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        <aside className="z-40 flex w-16 shrink-0 flex-col items-center gap-4 border-r border-border bg-card py-4 shadow-sm">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;
            return (
              <Link
                key={item.path}
                to={item.path}
                title={item.label}
                className={cn(
                  "group relative rounded-xl p-3 transition-all",
                  isActive
                    ? "bg-blue-50 text-blue-600 shadow-sm"
                    : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
                )}
              >
                <Icon className="h-5 w-5" />
                {isActive && (
                  <div className="absolute left-0 top-1/2 h-6 w-1 -translate-y-1/2 rounded-r-full bg-blue-600" />
                )}

                <div className="invisible absolute left-full z-50 ml-3 whitespace-nowrap rounded bg-foreground px-2 py-1 text-xs text-background opacity-0 shadow-md transition-all group-hover:visible group-hover:opacity-100">
                  {item.label}
                </div>
              </Link>
            );
          })}
        </aside>

        <main className="relative flex min-w-0 flex-1 flex-col overflow-hidden bg-background">
          <Outlet />
        </main>
      </div>

      <footer className="z-40 flex h-7 shrink-0 items-center justify-between border-t border-border bg-card px-4 text-[11px] font-medium tracking-wider text-muted-foreground">
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
    </div>
  );
}

function MenuGroup({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="group relative">
      <button className="cursor-default rounded-md px-3 py-1.5 transition-colors hover:bg-accent hover:text-accent-foreground">
        {label}
      </button>
      <div className="invisible absolute left-0 top-full z-50 min-w-[180px] rounded-md border border-border bg-card py-1 opacity-0 shadow-lg transition-all group-hover:visible group-hover:opacity-100">
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
        "flex cursor-pointer items-center gap-2 px-3 py-1.5",
        danger ? "hover:bg-destructive/10 hover:text-destructive" : "hover:bg-accent hover:text-accent-foreground",
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
