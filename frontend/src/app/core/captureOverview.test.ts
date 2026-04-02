import { describe, expect, it } from "vitest";
import { buildCaptureOverview } from "./captureOverview";
import type {
  GlobalTrafficStats,
  IndustrialAnalysis,
  MediaAnalysis,
  Packet,
  ThreatHit,
  USBAnalysis,
  VehicleAnalysis,
} from "./types";

const EMPTY_STATS: GlobalTrafficStats = {
  totalPackets: 0,
  protocolKinds: 0,
  timeline: [],
  protocolDist: [],
  topTalkers: [],
  topHostnames: [],
  topDomains: [],
  topSrcIPs: [],
  topDstIPs: [],
  topComputerNames: [],
  topDestPorts: [],
  topSrcPorts: [],
};

const EMPTY_INDUSTRIAL: IndustrialAnalysis = {
  totalIndustrialPackets: 0,
  protocols: [],
  conversations: [],
  modbus: {
    totalFrames: 0,
    requests: 0,
    responses: 0,
    exceptions: 0,
    functionCodes: [],
    unitIds: [],
    referenceHits: [],
    exceptionCodes: [],
    transactions: [],
  },
  details: [],
  notes: [],
};

const EMPTY_VEHICLE: VehicleAnalysis = {
  totalVehiclePackets: 0,
  protocols: [],
  conversations: [],
  can: {
    totalFrames: 0,
    extendedFrames: 0,
    rtrFrames: 0,
    errorFrames: 0,
    busIds: [],
    messageIds: [],
    payloadProtocols: [],
    payloadRecords: [],
    dbcProfiles: [],
    decodedMessageDist: [],
    decodedSignals: [],
    decodedMessages: [],
    signalTimelines: [],
    frames: [],
  },
  j1939: {
    totalMessages: 0,
    pgns: [],
    sourceAddrs: [],
    targetAddrs: [],
    messages: [],
  },
  doip: {
    totalMessages: 0,
    messageTypes: [],
    vins: [],
    endpoints: [],
    messages: [],
  },
  uds: {
    totalMessages: 0,
    serviceIDs: [],
    negativeCodes: [],
    dtcs: [],
    vins: [],
    messages: [],
    transactions: [],
  },
  recommendations: [],
};

const EMPTY_MEDIA: MediaAnalysis = {
  totalMediaPackets: 0,
  protocols: [],
  applications: [],
  sessions: [],
  notes: [],
};

const EMPTY_USB: USBAnalysis = {
  totalUSBPackets: 0,
  keyboardPackets: 0,
  mousePackets: 0,
  otherUSBPackets: 0,
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
  notes: [],
};

describe("buildCaptureOverview", () => {
  it("prioritizes suspicious traffic and web workflow when hits and http streams exist", () => {
    const packets: Packet[] = [
      {
        id: 42,
        time: "10:00:00.000",
        src: "10.0.0.2",
        srcPort: 54321,
        dst: "93.184.216.34",
        dstPort: 80,
        proto: "HTTP",
        displayProtocol: "HTTP",
        length: 123,
        info: "POST /shell HTTP/1.1",
        payload: "cmd=ZmxhZ3t0ZXN0fQ==",
        streamId: 7,
      },
    ];
    const hits: ThreatHit[] = [
      {
        id: 1,
        packetId: 42,
        category: "OWASP",
        rule: "Possible Webshell",
        level: "high",
        preview: "POST /shell",
        match: "cmd=ZmxhZ3t0ZXN0fQ==",
      },
    ];

    const overview = buildCaptureOverview({
      stats: {
        ...EMPTY_STATS,
        totalPackets: 128,
        protocolKinds: 3,
        protocolDist: [
          { label: "HTTP", count: 70 },
          { label: "TLS", count: 28 },
          { label: "DNS", count: 12 },
        ],
      },
      packets,
      threatHits: hits,
      extractedObjects: [],
      streamIds: { http: [7, 8], tcp: [1, 2, 3], udp: [9] },
      industrial: EMPTY_INDUSTRIAL,
      vehicle: EMPTY_VEHICLE,
      media: EMPTY_MEDIA,
      usb: EMPTY_USB,
    });

    expect(overview.headline).toContain("高危命中");
    expect(overview.recommendations[0]?.key).toBe("web");
    expect(overview.quickFilters.map((item) => item.filter)).toContain("http or tls");
    expect(overview.suspiciousHits[0]?.packetId).toBe(42);
  });

  it("surfaces industrial and vehicle routes when specialized protocols dominate", () => {
    const overview = buildCaptureOverview({
      stats: {
        ...EMPTY_STATS,
        totalPackets: 600,
        protocolKinds: 4,
        protocolDist: [
          { label: "MODBUS", count: 240 },
          { label: "CAN", count: 200 },
          { label: "TCP", count: 80 },
        ],
      },
      packets: [],
      threatHits: [],
      extractedObjects: [],
      streamIds: { http: [], tcp: [1, 2], udp: [3] },
      industrial: {
        ...EMPTY_INDUSTRIAL,
        totalIndustrialPackets: 240,
      },
      vehicle: {
        ...EMPTY_VEHICLE,
        totalVehiclePackets: 200,
      },
      media: EMPTY_MEDIA,
      usb: EMPTY_USB,
    });

    expect(overview.recommendations.map((item) => item.key)).toContain("industrial");
    expect(overview.recommendations.map((item) => item.key)).toContain("vehicle");
    expect(overview.quickFilters.map((item) => item.filter)).toContain("modbus or s7comm or dnp3 or cip or bacnet or iec104 or opcua or pn_rt");
    expect(overview.quickFilters.map((item) => item.filter)).toContain("can or j1939 or doip or uds");
  });
});
