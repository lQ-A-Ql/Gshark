import { describe, expect, it } from "vitest";
import type { VehicleAnalysis as VehicleAnalysisData } from "../core/types";
import { buildCanIdDataGroups } from "./VehicleAnalysis";

function createAnalysis(frames: VehicleAnalysisData["can"]["frames"]): VehicleAnalysisData {
  return {
    totalVehiclePackets: 0,
    protocols: [],
    conversations: [],
    can: {
      totalFrames: frames.length,
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
      frames,
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
}

describe("buildCanIdDataGroups", () => {
  it("builds CAN ID groups from raw CAN frames and removes duplicate DATA for the same ID", () => {
    const analysis = createAnalysis([
      {
        packetId: 101,
        time: "0.100000",
        identifier: "0x123",
        busId: "0x0",
        length: 8,
        rawData: "01 02 03 04",
        isExtended: false,
        isRTR: false,
        isError: false,
        summary: "frame-a",
      },
      {
        packetId: 102,
        time: "0.200000",
        identifier: "0x123",
        busId: "0x0",
        length: 8,
        rawData: "01 02 03 04",
        isExtended: false,
        isRTR: false,
        isError: false,
        summary: "frame-b",
      },
      {
        packetId: 103,
        time: "0.300000",
        identifier: "0x123",
        busId: "0x0",
        length: 8,
        rawData: "AA BB CC DD",
        isExtended: false,
        isRTR: false,
        isError: false,
        summary: "frame-c",
      },
      {
        packetId: 104,
        time: "0.400000",
        identifier: "0x456",
        busId: "0x1",
        length: 4,
        rawData: "11 22",
        isExtended: false,
        isRTR: false,
        isError: false,
        summary: "frame-d",
      },
    ]);

    const groups = buildCanIdDataGroups(analysis);

    expect(groups).toHaveLength(2);
    expect(groups[0]).toMatchObject({
      identifier: "0x123",
      busId: "0x0",
      total: 2,
      observedCount: 3,
    });
    expect(groups[0].items.map((item) => item.value)).toEqual(["01 02 03 04", "AA BB CC DD"]);
    expect(groups[1]).toMatchObject({
      identifier: "0x456",
      busId: "0x1",
      total: 1,
      observedCount: 1,
    });
  });

  it("ignores frames without raw CAN data", () => {
    const analysis = createAnalysis([
      {
        packetId: 201,
        time: "1.000000",
        identifier: "0x700",
        busId: "0x0",
        length: 0,
        isExtended: false,
        isRTR: true,
        isError: false,
        summary: "rtr",
      },
    ]);

    expect(buildCanIdDataGroups(analysis)).toEqual([]);
  });
});
