import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { DBCProfile, VehicleAnalysis as VehicleAnalysisData } from "../core/types";

const mocks = vi.hoisted(() => ({
  getVehicleAnalysis: vi.fn(),
  listVehicleDBCProfiles: vi.fn(),
  addVehicleDBC: vi.fn(),
  removeVehicleDBC: vi.fn(),
  openDBCFile: vi.fn(),
  navigate: vi.fn(),
  sentinelState: {
    backendConnected: true,
    isPreloadingCapture: false,
    fileMeta: {
      path: "C:/captures/vehicle.pcapng",
      name: "vehicle.pcapng",
      sizeBytes: 4096,
    },
    totalPackets: 256,
    captureRevision: 1,
    locatePacketById: vi.fn(),
    preparePacketStream: vi.fn(),
  },
}));

vi.mock("../state/contexts/BackendContext", () => ({
  useBackend: () => ({
    backendConnected: mocks.sentinelState.backendConnected,
  }),
}));

vi.mock("../state/contexts/CaptureContext", () => ({
  useCapture: () => ({
    isPreloadingCapture: mocks.sentinelState.isPreloadingCapture,
    fileMeta: mocks.sentinelState.fileMeta,
    captureRevision: mocks.sentinelState.captureRevision,
  }),
}));

vi.mock("../state/contexts/PacketContext", () => ({
  usePacket: () => ({
    totalPackets: mocks.sentinelState.totalPackets,
    locatePacketById: mocks.sentinelState.locatePacketById,
  }),
}));

vi.mock("../state/contexts/StreamContext", () => ({
  useStream: () => ({
    preparePacketStream: mocks.sentinelState.preparePacketStream,
  }),
}));

vi.mock("../integrations/backendClients", () => ({
  backendClients: {
    analysis: {
      getVehicleAnalysis: mocks.getVehicleAnalysis,
    },
    vehicleDBC: {
      listVehicleDBCProfiles: mocks.listVehicleDBCProfiles,
      addVehicleDBC: mocks.addVehicleDBC,
      removeVehicleDBC: mocks.removeVehicleDBC,
      openDBCFile: mocks.openDBCFile,
    },
  },
}));

vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return {
    ...actual,
    useNavigate: () => mocks.navigate,
  };
});

import VehicleAnalysis from "./VehicleAnalysis";

function createVehicleAnalysis(overrides: Partial<VehicleAnalysisData> = {}): VehicleAnalysisData {
  return {
    totalVehiclePackets: 9,
    protocols: [{ label: "CAN", count: 7 }, { label: "UDS", count: 2 }],
    conversations: [{ label: "bus0", protocol: "CAN", count: 7 }],
    can: {
      totalFrames: 2,
      extendedFrames: 0,
      rtrFrames: 0,
      errorFrames: 0,
      busIds: [{ label: "0x0", count: 2 }],
      messageIds: [{ label: "0x123", count: 2 }],
      payloadProtocols: [{ label: "UDS", count: 2 }],
      payloadRecords: [
        {
          packetId: 11,
          time: "1.000000",
          busId: "0x0",
          identifier: "0x123",
          protocol: "UDS",
          frameType: "single",
          sourceAddress: "0x7e0",
          targetAddress: "0x7e8",
          service: "0x22",
          detail: "ReadDataByIdentifier",
          length: 8,
          rawData: "03 22 F1 90",
          summary: "UDS payload record",
        },
      ],
      dbcProfiles: [],
      decodedMessageDist: [{ label: "EngineData", count: 1 }],
      decodedSignals: [{ label: "Speed", count: 1 }],
      decodedMessages: [
        {
          packetId: 12,
          time: "1.100000",
          busId: "0x0",
          identifier: "0x123",
          database: "car.dbc",
          messageName: "EngineData",
          sender: "ECU",
          signals: [{ name: "Speed", value: "42", unit: "km/h" }],
          summary: "DBC decoded engine data",
        },
      ],
      signalTimelines: [
        {
          name: "Speed",
          samples: [{ packetId: 12, time: "1.100000", value: 42, unit: "km/h", messageName: "EngineData" }],
        },
      ],
      frames: [
        {
          packetId: 10,
          time: "0.900000",
          identifier: "0x123",
          busId: "0x0",
          length: 8,
          rawData: "03 22 F1 90",
          isExtended: false,
          isRTR: false,
          isError: false,
          summary: "raw CAN frame",
        },
      ],
    },
    j1939: {
      totalMessages: 1,
      pgns: [{ label: "65262", count: 1 }],
      sourceAddrs: [{ label: "0x01", count: 1 }],
      targetAddrs: [{ label: "broadcast", count: 1 }],
      messages: [],
    },
    doip: {
      totalMessages: 1,
      messageTypes: [{ label: "diagnostic", count: 1 }],
      vins: [{ label: "VIN123", count: 1 }],
      endpoints: [{ label: "0x0e00 -> 0x0e80", count: 1 }],
      messages: [
        {
          packetId: 21,
          time: "2.000000",
          source: "10.0.0.10",
          destination: "10.0.0.20",
          type: "diagnostic",
          vin: "VIN123",
          diagnosticState: "routing-active",
          summary: "DoIP diagnostic message",
        },
      ],
    },
    uds: {
      totalMessages: 2,
      serviceIDs: [{ label: "0x22 ReadDataByIdentifier", count: 1 }],
      negativeCodes: [{ label: "0x31", count: 1 }],
      dtcs: [],
      vins: [],
      messages: [
        {
          packetId: 31,
          time: "3.000000",
          serviceId: "0x22",
          serviceName: "ReadDataByIdentifier",
          isReply: false,
          sourceAddress: "0x7e0",
          targetAddress: "0x7e8",
          dataIdentifier: "F190",
          summary: "UDS detail message",
        },
      ],
      transactions: [
        {
          requestPacketId: 31,
          responsePacketId: 32,
          requestTime: "3.000000",
          responseTime: "3.010000",
          sourceAddress: "0x7e0",
          targetAddress: "0x7e8",
          serviceId: "0x22",
          serviceName: "ReadDataByIdentifier",
          dataIdentifier: "F190",
          status: "positive",
          latencyMs: 10,
          requestSummary: "read VIN request",
          responseSummary: "read VIN response",
        },
        {
          requestPacketId: 33,
          responsePacketId: 34,
          requestTime: "3.100000",
          responseTime: "3.120000",
          sourceAddress: "0x7e0",
          targetAddress: "0x7e8",
          serviceId: "0x31",
          serviceName: "RoutineControl",
          status: "negative",
          negativeCode: "0x31",
          latencyMs: 20,
          requestSummary: "routine control request",
          responseSummary: "routine rejected",
        },
      ],
    },
    recommendations: ["关注 UDS 负响应与安全访问链路。"],
    report: {
      summary: [{ title: "车机协议摘要", summary: "识别到 CAN 与 UDS 通信。", severity: "info" }],
      evidence: [{ title: "UDS 事务证据", summary: "存在诊断事务。", severity: "medium" }],
      details: [{ title: "CAN 明细证据", summary: "存在可解码 CAN 帧。", severity: "low" }],
      recommendations: ["复核 DBC 映射与诊断会话。"],
    },
    ...overrides,
  };
}

function openDetailsSection() {
  fireEvent.click(screen.getByRole("button", { name: /^明细/ }));
}

function openSetupSection() {
  fireEvent.click(screen.getByRole("button", { name: /^Setup/ }));
}

function openUdsSection() {
  fireEvent.click(screen.getByRole("button", { name: /^UDS/ }));
}

function openReportSection() {
  fireEvent.click(screen.getByRole("button", { name: /^报告/ }));
}

describe("VehicleAnalysis", () => {
  let renderSeed = 0;

  beforeEach(() => {
    renderSeed += 1;
    mocks.sentinelState.backendConnected = true;
    mocks.sentinelState.isPreloadingCapture = false;
    mocks.sentinelState.totalPackets = 256 + renderSeed;
    mocks.sentinelState.captureRevision = renderSeed;
    mocks.sentinelState.fileMeta = {
      path: `C:/captures/vehicle-${renderSeed}.pcapng`,
      name: `vehicle-${renderSeed}.pcapng`,
      sizeBytes: 4096,
    };
    mocks.getVehicleAnalysis.mockReset();
    mocks.listVehicleDBCProfiles.mockReset();
    mocks.addVehicleDBC.mockReset();
    mocks.removeVehicleDBC.mockReset();
    mocks.openDBCFile.mockReset();
    mocks.navigate.mockReset();
    mocks.sentinelState.locatePacketById.mockReset();
    mocks.sentinelState.preparePacketStream.mockReset();
    mocks.getVehicleAnalysis.mockResolvedValue(createVehicleAnalysis());
    mocks.listVehicleDBCProfiles.mockResolvedValue([] satisfies DBCProfile[]);
    mocks.addVehicleDBC.mockResolvedValue([] satisfies DBCProfile[]);
    mocks.removeVehicleDBC.mockResolvedValue([] satisfies DBCProfile[]);
    mocks.openDBCFile.mockResolvedValue({ filePath: "C:/dbc/imported.dbc" });
  });

  it("defaults to setup and preserves DBC input while switching sections", async () => {
    render(<VehicleAnalysis />);

    expect(screen.getByText("DBC 映射")).toBeInTheDocument();
    expect(screen.getByTestId("analysis-workbench-scroll")).toHaveClass("overflow-auto");

    const dbcInput = screen.getByPlaceholderText("或直接输入 DBC 文件路径");
    fireEvent.change(dbcInput, { target: { value: "C:/dbc/car.dbc" } });

    openDetailsSection();
    await waitFor(() => {
      expect(screen.getByText("CAN 明细预览 (1 / 2)")).toBeInTheDocument();
    });
    expect(screen.getByText("raw CAN frame")).toBeInTheDocument();

    openSetupSection();
    expect(screen.getByPlaceholderText("或直接输入 DBC 文件路径")).toHaveValue("C:/dbc/car.dbc");
  });

  it("keeps UDS filter state and exposes the report section", async () => {
    render(<VehicleAnalysis />);

    openUdsSection();
    await waitFor(() => {
      expect(screen.getByText("UDS 配对事务预览 (2)")).toBeInTheDocument();
    });
    expect(screen.getByText("read VIN response")).toBeInTheDocument();
    expect(screen.getByText("routine rejected")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "负响应 · 1" }));
    await waitFor(() => {
      expect(screen.getByText("UDS 配对事务预览 (1)")).toBeInTheDocument();
    });
    expect(screen.queryByText("read VIN response")).not.toBeInTheDocument();
    expect(screen.getByText("routine rejected")).toBeInTheDocument();

    openReportSection();
    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "车机调查报告" })).toBeInTheDocument();
    });
    expect(screen.getByText("车机协议摘要")).toBeInTheDocument();

    openUdsSection();
    expect(screen.getByText("UDS 配对事务预览 (1)")).toBeInTheDocument();
    expect(screen.getByText("routine rejected")).toBeInTheDocument();
  });
});
