import { afterEach, describe, expect, it, vi } from "vitest";
import { backendClients } from "../integrations/backendClients";
import { buildHeavyWarmupCacheKey, scheduleRouteHeavyWarmup } from "./heavyWarmupPreload";
import { resetPreloadSchedulerForTest, setPreloadFeatureFlagOverrideForTest } from "./preloadScheduler";
import { setPreloadTelemetrySinkForTest } from "./preloadTelemetry";

vi.mock("../integrations/backendClients", () => ({
  backendClients: {
    analysis: {
      getC2SampleAnalysis: vi.fn(),
      getIndustrialAnalysis: vi.fn(),
      getVehicleAnalysis: vi.fn(),
      getUSBAnalysis: vi.fn(),
    },
    vehicleDBC: {
      listVehicleDBCProfiles: vi.fn(),
    },
  },
}));

describe("heavy warmup preload", () => {
  afterEach(() => {
    resetPreloadSchedulerForTest();
    setPreloadTelemetrySinkForTest(undefined);
    vi.mocked(backendClients.analysis.getC2SampleAnalysis).mockReset();
    vi.mocked(backendClients.vehicleDBC.listVehicleDBCProfiles).mockReset();
    delete (window as any).go;
  });

  it("skips when not in desktop runtime", async () => {
    const events: string[] = [];
    setPreloadTelemetrySinkForTest((event) => events.push(`${event.event}:${event.reason ?? ""}`));

    await scheduleRouteHeavyWarmup("/c2-analysis", "hover", warmupInput());

    expect(events).toContain("preload.skipped:not-desktop");
    expect(backendClients.analysis.getC2SampleAnalysis).not.toHaveBeenCalled();
  });

  it("schedules C2 warmup with background source when desktop and flag enabled", async () => {
    (window as any).go = { main: { DesktopApp: {} } };
    setPreloadFeatureFlagOverrideForTest(() => true);
    vi.mocked(backendClients.analysis.getC2SampleAnalysis).mockResolvedValue({} as any);

    await scheduleRouteHeavyWarmup("/c2-analysis", "hover", warmupInput());

    expect(backendClients.analysis.getC2SampleAnalysis).toHaveBeenCalledWith(expect.any(AbortSignal), { source: "warmup" });
  });

  it("keeps forbidden heavy targets dark", async () => {
    (window as any).go = { main: { DesktopApp: {} } };
    setPreloadFeatureFlagOverrideForTest(() => true);
    const events: string[] = [];
    setPreloadTelemetrySinkForTest((event) => events.push(`${event.event}:${event.reason ?? ""}`));

    await scheduleRouteHeavyWarmup("/media-analysis", "hover", warmupInput());

    expect(events).toContain("preload.skipped:forbidden-target");
  });

  it("includes sorted DBC paths and USB HID options in heavy cache keys", () => {
    expect(
      buildHeavyWarmupCacheKey("/vehicle-analysis", {
        ...warmupInput(),
        dbcProfilePaths: ["z.dbc", "a.dbc", "a.dbc"],
      }),
    ).toBe("1::capture.pcapng::10::vehicle::a.dbc|z.dbc");
    expect(buildHeavyWarmupCacheKey("/usb-analysis", { ...warmupInput(), hidSource: "capdata", hidEventLimit: 500 })).toBe(
      "1::capture.pcapng::10::usb::capdata::500",
    );
  });

  it("loads DBC profile paths before vehicle warmup", async () => {
    (window as any).go = { main: { DesktopApp: {} } };
    setPreloadFeatureFlagOverrideForTest(() => true);
    vi.mocked(backendClients.vehicleDBC.listVehicleDBCProfiles).mockResolvedValue([
      { path: "z.dbc", name: "Z", messageCount: 1, signalCount: 2 },
      { path: "a.dbc", name: "A", messageCount: 2, signalCount: 3 },
    ]);
    vi.mocked(backendClients.analysis.getVehicleAnalysis).mockResolvedValue({} as any);

    await scheduleRouteHeavyWarmup("/vehicle-analysis", "hover", warmupInput());

    expect(backendClients.vehicleDBC.listVehicleDBCProfiles).toHaveBeenCalledTimes(1);
    expect(backendClients.analysis.getVehicleAnalysis).toHaveBeenCalledWith(expect.any(AbortSignal), { source: "warmup" });
  });
});

function warmupInput() {
  return {
    backendConnected: true,
    captureReady: true,
    filePath: "capture.pcapng",
    totalPackets: 10,
    captureRevision: 1,
    currentRouteIdle: true,
  };
}
