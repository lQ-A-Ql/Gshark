import { describe, expect, it } from "vitest";

import { filterForDomainBucket, filterForIpBucket, filterForPortBucket, filterForProtocolBucket } from "./trafficGraphFilters";

describe("trafficGraphFilters", () => {
  it("maps protocol buckets to display filters", () => {
    expect(filterForProtocolBucket("TLSv1.3")).toBe("tls");
    expect(filterForProtocolBucket("MODBUS")).toContain("modbus");
    expect(filterForProtocolBucket("UDS")).toContain("uds");
    expect(filterForProtocolBucket("custom")).toBe("custom");
  });

  it("builds IP, domain, and port filters", () => {
    expect(filterForIpBucket("10.0.0.2", "src")).toBe("ip.src == 10.0.0.2");
    expect(filterForIpBucket("2001:db8::1", "dst")).toBe("ipv6.dst == 2001:db8::1");
    expect(filterForDomainBucket("example.com")).toContain('http.host contains "example.com"');
    expect(filterForPortBucket("443")).toBe("tcp.port == 443 or udp.port == 443");
  });
});
