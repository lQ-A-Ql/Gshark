import { describe, expect, it } from "vitest";
import { buildIndustrialAnalysisCacheKey } from "./IndustrialAnalysis";
import { buildTrafficStatsCacheKey } from "./TrafficGraph";
import { buildUSBAnalysisCacheKey } from "./UsbAnalysis";
import { buildVehicleAnalysisCacheKey } from "./VehicleAnalysis";

describe("analysis cache keys", () => {
  it("includes capture revision for industrial analysis", () => {
    expect(buildIndustrialAnalysisCacheKey(3, "C:/captures/demo.pcapng", 128)).toBe("3::C:/captures/demo.pcapng::128");
  });

  it("includes capture revision for traffic stats", () => {
    expect(buildTrafficStatsCacheKey(7, "C:/captures/demo.pcapng", 256)).toBe("7::C:/captures/demo.pcapng::256");
  });

  it("includes capture revision for usb analysis", () => {
    expect(buildUSBAnalysisCacheKey(9, "C:/captures/usb.pcapng", 64)).toBe("9::C:/captures/usb.pcapng::64");
  });

  it("includes sorted dbc profiles for vehicle analysis", () => {
    expect(buildVehicleAnalysisCacheKey(5, "C:/captures/vehicle.pcapng", 512, [
      { path: "z.dbc", name: "Z", messageCount: 1, signalCount: 1 },
      { path: "a.dbc", name: "A", messageCount: 1, signalCount: 1 },
    ])).toBe("5::C:/captures/vehicle.pcapng::512::a.dbc|z.dbc");
  });

  it("returns empty string when capture path is blank", () => {
    expect(buildIndustrialAnalysisCacheKey(1, "", 1)).toBe("");
    expect(buildTrafficStatsCacheKey(1, "   ", 1)).toBe("");
    expect(buildUSBAnalysisCacheKey(1, "", 1)).toBe("");
    expect(buildVehicleAnalysisCacheKey(1, "", 1, [])).toBe("");
  });
});
