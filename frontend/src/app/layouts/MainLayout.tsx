import { Outlet, Link, useLocation, useNavigate } from "react-router";
import { Activity, LayoutDashboard, ShieldAlert, FileDown, KeyRound, Puzzle, Box, FolderOpen, Save, Upload, Hexagon, BarChart3, Factory, Car, Clapperboard, ScrollText } from "lucide-react";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { useEffect } from "react";
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
    downloadText(`packets-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.json`, JSON.stringify(filteredPackets, null, 2), "application/json;charset=utf-8");
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
      // no-op
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
      .map(([k, v]) => `${k},${v}`)
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
    <div className="flex h-screen w-screen flex-col bg-background text-foreground font-sans overflow-hidden selection:bg-blue-200 selection:text-blue-900">
      {/* Top Title Bar */}
      <header className="flex flex-col border-b border-border bg-card shrink-0 shadow-sm relative z-50">
        <div className="flex h-12 items-center justify-between px-4">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-blue-600 font-semibold tracking-wide">
              <Hexagon className="h-6 w-6" />
              <span className="text-lg">GShark-Sentinel</span>
            </div>
            
            {/* Top Dropdown Menu Bar */}
            <nav className="flex items-center gap-1 text-sm font-medium text-muted-foreground ml-6">
              <div className="relative group">
                <button className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground rounded-md transition-colors cursor-default">文件 (F)</button>
                <div className="absolute top-full left-0 min-w-[160px] bg-card border border-border rounded-md shadow-lg py-1 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-50">
                  <div
                    className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer flex items-center gap-2"
                    onClick={() => void openCapture()}
                  ><FolderOpen className="w-4 h-4"/> 打开</div>
                  <div
                    className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer flex items-center gap-2"
                    onClick={exportPacketsJson}
                  ><Save className="w-4 h-4"/> 导出当前列表</div>
                  <div
                    className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer flex items-center gap-2"
                    onClick={() => void openCapture()}
                  ><Upload className="w-4 h-4"/> 导入...</div>
                  <div className="h-px bg-border my-1"></div>
                  <div className="px-3 py-1.5 hover:bg-destructive/10 hover:text-destructive cursor-pointer" onClick={() => window.close()}>退出</div>
                </div>
              </div>
              <div className="relative group">
                <button className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground rounded-md transition-colors cursor-default">编辑 (E)</button>
                <div className="absolute top-full left-0 min-w-[160px] bg-card border border-border rounded-md shadow-lg py-1 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-50">
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={() => void copySelectedPacket()}>复制所选数据包</div>
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={() => window.dispatchEvent(new CustomEvent("gshark:focus-filter"))}>查找数据包...</div>
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={() => navigate("/plugins")}>首选项</div>
                </div>
              </div>
              <div className="relative group">
                <button className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground rounded-md transition-colors cursor-default">视图 (V)</button>
                <div className="absolute top-full left-0 min-w-[180px] bg-card border border-border rounded-md shadow-lg py-1 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-50">
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={() => navigate("/")}>返回主工作区</div>
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={() => navigate("/decryption")}>名称解析 / TLS</div>
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={() => window.dispatchEvent(new CustomEvent("gshark:focus-filter"))}>聚焦过滤输入</div>
                </div>
              </div>
              <div className="relative group">
                <button className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground rounded-md transition-colors cursor-default">分析 (A)</button>
                <div className="absolute top-full left-0 min-w-[160px] bg-card border border-border rounded-md shadow-lg py-1 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-50">
                  <div
                    className="px-3 py-1.5 hover:bg-blue-50 hover:text-blue-700 cursor-pointer"
                    onClick={() => {
                      setDisplayFilter("http");
                      applyFilter("http");
                    }}
                  >
                    应用过滤器: http
                  </div>
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={() => navigate("/industrial-analysis")}>工控分析</div>
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={() => navigate("/vehicle-analysis")}>车机分析</div>
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={() => navigate("/media-analysis")}>视频流还原</div>
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={() => navigate("/audit-logs")}>审计日志</div>
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={followSelectedStream}>追踪流</div>
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={() => navigate("/hunting")}>专家信息</div>
                </div>
              </div>
              <div className="relative group">
                <button className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground rounded-md transition-colors cursor-default">统计 (S)</button>
                <div className="absolute top-full left-0 min-w-[160px] bg-card border border-border rounded-md shadow-lg py-1 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-50">
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={() => navigate("/traffic-graph")}>流量图</div>
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={() => navigate("/industrial-analysis")}>工控分析</div>
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={() => navigate("/vehicle-analysis")}>车机分析</div>
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={() => navigate("/media-analysis")}>视频流还原</div>
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={exportEndpointStats}>端点统计导出</div>
                  <div className="px-3 py-1.5 hover:bg-accent hover:text-accent-foreground cursor-pointer" onClick={exportProtocolStats}>协议统计导出</div>
                </div>
              </div>
            </nav>
        </div>
        <div className="flex items-center gap-2 text-xs font-medium">
            <span className="flex items-center gap-1 rounded-md bg-rose-50 px-2.5 py-1.5 text-rose-600 border border-rose-200">
              <ShieldAlert className="h-3.5 w-3.5" /> OWASP
            </span>
            <span className="flex items-center gap-1 rounded-md bg-emerald-50 px-2.5 py-1.5 text-emerald-600 border border-emerald-200">
              <Activity className="h-3.5 w-3.5" /> CTF
            </span>
            <span className="flex items-center gap-1 rounded-md bg-amber-50 px-2.5 py-1.5 text-amber-600 border border-amber-200">
              <KeyRound className="h-3.5 w-3.5" /> 解密
            </span>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left Sidebar Navigation */}
        <aside className="w-16 flex-col border-r border-border bg-card flex items-center py-4 gap-4 shrink-0 shadow-sm z-40">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;
            return (
              <Link
                key={item.path}
                to={item.path}
                title={item.label}
                className={cn(
                  "p-3 rounded-xl transition-all relative group",
                  isActive 
                    ? "bg-blue-50 text-blue-600 shadow-sm" 
                    : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                )}
              >
                <Icon className="h-5 w-5" />
                {isActive && (
                  <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-blue-600 rounded-r-full" />
                )}
                
                {/* Tooltip */}
                <div className="absolute left-full ml-3 px-2 py-1 bg-foreground text-background text-xs rounded opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all whitespace-nowrap z-50 shadow-md">
                  {item.label}
                </div>
              </Link>
            );
          })}
        </aside>

        {/* Dynamic View Content */}
        <main className="flex-1 min-w-0 bg-background flex flex-col relative overflow-hidden">
          <Outlet />
        </main>
      </div>

      {/* Global Status Bar */}
      <footer className="h-7 flex items-center justify-between border-t border-border bg-card px-4 text-[11px] text-muted-foreground font-medium tracking-wider shrink-0 z-40">
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
