import { describe, expect, it } from "vitest";
import { buildC2SampleAnalysisCacheKey } from "../features/c2/useC2Analysis";
import { buildIndustrialAnalysisCacheKey } from "../features/industrial/useIndustrialAnalysis";
import { buildTrafficStatsCacheKey } from "../features/traffic/useTrafficGraph";
import {
  buildUSBAnalysisCacheKey,
  clearUSBAnalysisCacheForTest,
  readUSBAnalysisCache,
  writeUSBAnalysisCache,
} from "../features/usb/useUsbAnalysis";
import { buildVehicleAnalysisCacheKey } from "../features/vehicle/useVehicleAnalysis";
import type { USBAnalysis } from "../core/types";

describe("analysis cache keys", () => {
  it("includes capture revision for industrial analysis", () => {
    expect(buildIndustrialAnalysisCacheKey(3, "C:/captures/demo.pcapng", 128)).toBe("3::C:/captures/demo.pcapng::128");
  });

  it("includes capture revision for traffic stats", () => {
    expect(buildTrafficStatsCacheKey(7, "C:/captures/demo.pcapng", 256)).toBe("7::C:/captures/demo.pcapng::256");
  });

  it("includes capture revision for usb analysis", () => {
    expect(buildUSBAnalysisCacheKey(9, "C:/captures/usb.pcapng", 64)).toBe(
      "9::C:/captures/usb.pcapng::64::auto::20000",
    );
    expect(buildUSBAnalysisCacheKey(9, "C:/captures/usb.pcapng", 64, "usbhid")).toBe(
      "9::C:/captures/usb.pcapng::64::usbhid::20000",
    );
    expect(buildUSBAnalysisCacheKey(9, "C:/captures/usb.pcapng", 64, "usbhid", 40000)).toBe(
      "9::C:/captures/usb.pcapng::64::usbhid::40000",
    );
  });

  it("includes capture revision for c2 analysis", () => {
    expect(buildC2SampleAnalysisCacheKey(11, "C:/captures/c2.pcapng", 96)).toBe("11::C:/captures/c2.pcapng::96");
  });

  it("includes sorted dbc profiles for vehicle analysis", () => {
    expect(
      buildVehicleAnalysisCacheKey(5, "C:/captures/vehicle.pcapng", 512, [
        { path: "z.dbc", name: "Z", messageCount: 1, signalCount: 1 },
        { path: "a.dbc", name: "A", messageCount: 1, signalCount: 1 },
      ]),
    ).toBe("5::C:/captures/vehicle.pcapng::512::a.dbc|z.dbc");
  });

  it("returns empty string when capture path is blank", () => {
    expect(buildIndustrialAnalysisCacheKey(1, "", 1)).toBe("");
    expect(buildTrafficStatsCacheKey(1, "   ", 1)).toBe("");
    expect(buildUSBAnalysisCacheKey(1, "", 1)).toBe("");
    expect(buildC2SampleAnalysisCacheKey(1, "   ", 1)).toBe("");
    expect(buildVehicleAnalysisCacheKey(1, "", 1, [])).toBe("");
  });

  it("keeps usb source and limit keys isolated while evicting least recently used entries", () => {
    clearUSBAnalysisCacheForTest();
    const keys = [
      buildUSBAnalysisCacheKey(1, "C:/captures/usb.pcapng", 10, "auto", 20000),
      buildUSBAnalysisCacheKey(1, "C:/captures/usb.pcapng", 10, "usbhid", 20000),
      buildUSBAnalysisCacheKey(1, "C:/captures/usb.pcapng", 10, "usbhid", 40000),
      buildUSBAnalysisCacheKey(2, "C:/captures/usb.pcapng", 10, "auto", 20000),
      buildUSBAnalysisCacheKey(3, "C:/captures/usb.pcapng", 10, "auto", 20000),
      buildUSBAnalysisCacheKey(4, "C:/captures/usb.pcapng", 10, "auto", 20000),
    ];

    keys.slice(0, 5).forEach((key, index) => writeUSBAnalysisCache(key, { ...EMPTY_USB_PAYLOAD, totalUSBPackets: index }));
    expect(readUSBAnalysisCache(keys[0])?.totalUSBPackets).toBe(0);

    writeUSBAnalysisCache(keys[5], { ...EMPTY_USB_PAYLOAD, totalUSBPackets: 5 });

    expect(readUSBAnalysisCache(keys[0])?.totalUSBPackets).toBe(0);
    expect(readUSBAnalysisCache(keys[1])).toBeUndefined();
    expect(readUSBAnalysisCache(keys[2])?.totalUSBPackets).toBe(2);
    expect(readUSBAnalysisCache(keys[5])?.totalUSBPackets).toBe(5);
    clearUSBAnalysisCacheForTest();
  });
});

const EMPTY_USB_PAYLOAD: USBAnalysis = {
  totalUSBPackets: 0,
  keyboardPackets: 0,
  mousePackets: 0,
  otherUSBPackets: 0,
  hidPackets: 0,
  massStoragePackets: 0,
  protocols: [],
  transferTypes: [],
  directions: [],
  devices: [],
  endpoints: [],
  setupRequests: [],
  records: [],
  keyboardEvents: [],
  mouseEvents: [],
  otherRecords: [],
  hidSourceMode: "auto" as const,
  hidSourceCandidates: [],
  hidSelectedSource: undefined,
  hidSourceNotes: [],
  hidEventLimit: 0,
  hidEventsTruncated: false,
  hidMouseEventsTotal: 0,
  hidKeyboardEventsTotal: 0,
  hid: { keyboardEvents: [], mouseEvents: [], devices: [], notes: [] },
  massStorage: {
    totalPackets: 0,
    readPackets: 0,
    writePackets: 0,
    controlPackets: 0,
    devices: [],
    luns: [],
    commands: [],
    readOperations: [],
    writeOperations: [],
    notes: [],
  },
  other: {
    totalPackets: 0,
    controlPackets: 0,
    devices: [],
    endpoints: [],
    setupRequests: [],
    controlRecords: [],
    records: [],
    notes: [],
  },
  notes: [],
  report: {
    summary: [],
    evidence: [],
    details: [],
    recommendations: [],
  },
};
