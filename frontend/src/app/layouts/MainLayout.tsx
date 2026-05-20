import { Outlet, useLocation, useNavigate } from "react-router";
import { useEffect, useLayoutEffect, useRef, useState, type CSSProperties } from "react";
import { useSentinel } from "../state/SentinelContext";
import { SidebarProvider } from "../components/ui/sidebar";
import { TLSDecryptionDialog } from "../components/TLSDecryptionDialog";
import { copyTextToClipboard, downloadText } from "../utils/browserFile";
import { installBrowserPageDragGuard, preventBrowserPageDrag } from "./dragGuard";
import { themeForPath } from "./mainLayoutConfig";
import { MainFooter, MainHeader, MainSettingsChrome, MainSidebarNav } from "./MainLayoutChrome";

type BackgroundFadeState = { key: string; style: CSSProperties };

const ROUTE_MOTION_ORDER =
  "/,/analysis-cockpit,/traffic-graph,/hunting,/c2-analysis,/apt-analysis,/industrial-analysis,/vehicle-analysis,/usb-analysis,/media-analysis,/objects,/misc,/evidence,/http-stream,/tcp-stream,/udp-stream,/updates".split(
    ",",
  );

export type RouteMotionDirection = "forward" | "back" | "neutral";

export function getRouteMotionDirection(previousPath: string, nextPath: string): RouteMotionDirection {
  const previousIndex = ROUTE_MOTION_ORDER.indexOf(previousPath);
  const nextIndex = ROUTE_MOTION_ORDER.indexOf(nextPath);
  if (previousPath === nextPath || previousIndex < 0 || nextIndex < 0) {
    return "neutral";
  }
  return nextIndex > previousIndex ? "forward" : "back";
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
    await copyTextToClipboard(text);
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

  const focusFilter = () => {
    window.dispatchEvent(new CustomEvent("gshark:focus-filter"));
  };

  const applyHttpFilter = () => {
    setDisplayFilter("http");
    applyFilter("http");
  };

  const activeTheme = themeForPath(location.pathname);
  const routeMotion = getRouteMotionDirection(backgroundRouteRef.current, location.pathname);
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
        className="gshark-page-bg gshark-glass-shell flex h-screen w-screen flex-col overflow-hidden font-sans text-foreground selection:bg-blue-200 selection:text-blue-900"
        style={pageThemeStyle}
        onDragStartCapture={preventBrowserPageDrag}
        onDragOverCapture={preventBrowserPageDrag}
        onDropCapture={preventBrowserPageDrag}
      >
        <MainHeader
          onApplyHttpFilter={applyHttpFilter}
          onCopySelectedPacket={() => void copySelectedPacket()}
          onExportEndpointStats={exportEndpointStats}
          onExportPacketsJson={exportPacketsJson}
          onExportProtocolStats={exportProtocolStats}
          onFocusFilter={focusFilter}
          onFollowSelectedStream={followSelectedStream}
          onNavigate={navigate}
          onOpenCapture={() => void openCapture()}
          onOpenSettings={() => setSettingsOpen(true)}
          onOpenTLSDialog={() => setTlsDialogOpen(true)}
        />

        <div className="flex flex-1 overflow-hidden">
          <MainSidebarNav activeTheme={activeTheme} pathname={location.pathname} />

          <main className="gshark-page-bg gshark-theme-main relative flex min-w-0 flex-1 flex-col overflow-hidden">
            {backgroundFade ? (
              <div
                key={`fade-${backgroundFade.key}`}
                aria-hidden="true"
                className="gshark-page-bg gshark-theme-fade"
                style={backgroundFade.style}
                onAnimationEnd={() => setBackgroundFade(null)}
              />
            ) : null}
            <div
              key={`route-${location.pathname}`}
              data-route-motion={routeMotion}
              className="gshark-route-transition flex min-h-0 flex-1 flex-col overflow-hidden"
            >
              <Outlet />
            </div>
          </main>
        </div>

        <MainSettingsChrome settingsOpen={settingsOpen} onCloseSettings={() => setSettingsOpen(false)} />
        <MainFooter
          backendConnected={backendConnected}
          backendStatus={backendStatus}
          decryptionConfigured={Boolean(decryptionConfig.sslKeyLogPath)}
          fileMeta={fileMeta}
          filteredPacketCount={filteredPackets.length}
          packets={packets}
          totalPackets={totalPackets}
        />
        <TLSDecryptionDialog open={tlsDialogOpen} onOpenChange={setTlsDialogOpen} />
      </div>
    </SidebarProvider>
  );
}

export { installBrowserPageDragGuard, preventBrowserPageDrag };
