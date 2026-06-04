import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { IndustrialAnalysis as IndustrialAnalysisData } from "../core/types";

const mocks = vi.hoisted(() => ({
  getIndustrialAnalysis: vi.fn(),
  sentinelState: {
    backendConnected: true,
    isPreloadingCapture: false,
    fileMeta: {
      path: "C:/captures/modbus.pcapng",
      name: "modbus.pcapng",
      sizeBytes: 4096,
    },
    totalPackets: 128,
    captureRevision: 1,
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
  }),
}));

vi.mock("../state/contexts/StreamContext", () => ({
  useStream: () => ({
    preparePacketStream: vi.fn(),
  }),
}));

vi.mock("../integrations/backendClients", () => ({
  backendClients: {
    analysis: {
      getIndustrialAnalysis: mocks.getIndustrialAnalysis,
    },
  },
}));

vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return {
    ...actual,
    useNavigate: () => vi.fn(),
  };
});

import IndustrialAnalysis from "./IndustrialAnalysis";

function createAnalysis(overrides: Partial<IndustrialAnalysisData> = {}): IndustrialAnalysisData {
  return {
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
    suspiciousWrites: [],
    controlCommands: [],
    ruleHits: [],
    details: [],
    notes: [],
    ...overrides,
  };
}

describe("IndustrialAnalysis", () => {
  let renderSeed = 0;

  beforeEach(() => {
    renderSeed += 1;
    mocks.sentinelState.fileMeta = {
      ...mocks.sentinelState.fileMeta,
      path: `C:/captures/modbus-${renderSeed}.pcapng`,
      name: `modbus-${renderSeed}.pcapng`,
    };
    mocks.sentinelState.captureRevision = renderSeed;
    mocks.getIndustrialAnalysis.mockReset();
    mocks.getIndustrialAnalysis.mockResolvedValue(createAnalysis());
  });

  it("renders decoded UTF-8 input text for Modbus transactions", async () => {
    mocks.getIndustrialAnalysis.mockResolvedValue(createAnalysis({
      totalIndustrialPackets: 1,
      protocols: [{ label: "Modbus/TCP", count: 1 }],
      modbus: {
        totalFrames: 1,
        requests: 1,
        responses: 0,
        exceptions: 0,
        functionCodes: [{ label: "16 写多寄存器", count: 1 }],
        unitIds: [{ label: "Unit 1", count: 1 }],
        referenceHits: [{ label: "Ref 40001", count: 1 }],
        exceptionCodes: [],
        decodedInputs: [{
          startPacketId: 42,
          endPacketId: 45,
          source: "10.0.0.10",
          destination: "10.0.0.20",
          unitId: 1,
          functionCode: 16,
          functionName: "写多寄存器",
          reference: "Ref 40001",
          encoding: "ascii-hex->utf-8",
          text: "flag{modbus-input}",
          rawText: "666c61677b6d6f646275732d696e7075747d",
          summary: "packet #42-45 连续写入 ASCII 输入",
        }],
        transactions: [{
          packetId: 42,
          time: "1.000000",
          source: "10.0.0.10",
          destination: "10.0.0.20",
          transactionId: 7,
          unitId: 1,
          functionCode: 16,
          functionName: "写多寄存器",
          kind: "request",
          reference: "Ref 40001",
          quantity: "6",
          exceptionCode: 0,
          responseTime: "",
          registerValues: "26725, 27756, 28416",
          inputText: "hello modbus",
          summary: "Write Multiple Registers",
        }],
      },
    }));

    render(<IndustrialAnalysis />);

    await waitFor(() => {
      expect(screen.getByText("Modbus 事务明细 (1)")).toBeInTheDocument();
    });
    expect(screen.getByText("UTF-8输入:")).toBeInTheDocument();
    expect(screen.getByText("hello modbus")).toBeInTheDocument();
    expect(screen.getByText("Modbus UTF-8 输入重组 (1)")).toBeInTheDocument();
    expect(screen.getByText("flag{modbus-input}")).toBeInTheDocument();
    expect(screen.getByText(/666c61677b6d6f646275732d696e7075747d/)).toBeInTheDocument();
  });

  it("shows metric cards with analysis data", async () => {
    mocks.getIndustrialAnalysis.mockResolvedValue(createAnalysis({
      totalIndustrialPackets: 256,
      protocols: [{ label: "Modbus/TCP", count: 200 }, { label: "S7comm", count: 56 }],
      modbus: {
        totalFrames: 200,
        requests: 150,
        responses: 45,
        exceptions: 5,
        functionCodes: [{ label: "读线圈", count: 100 }, { label: "写多寄存器", count: 50 }],
        unitIds: [{ label: "Unit 1", count: 120 }, { label: "Unit 2", count: 80 }],
        referenceHits: [],
        exceptionCodes: [],
        transactions: [],
      },
    }));

    render(<IndustrialAnalysis />);

    await waitFor(() => {
      expect(screen.getByText("工控相关包")).toBeInTheDocument();
    });
    expect(screen.getByText("256")).toBeInTheDocument();
    expect(screen.getByText("识别协议")).toBeInTheDocument();
    expect(screen.getAllByText("2").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("Modbus 帧")).toBeInTheDocument();
    expect(screen.getAllByText("200").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("异常响应")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
    expect(screen.getByText("Modbus 请求")).toBeInTheDocument();
    expect(screen.getByText("150")).toBeInTheDocument();
    expect(screen.getByText("Modbus 响应")).toBeInTheDocument();
    expect(screen.getByText("45")).toBeInTheDocument();
    expect(screen.getByText("功能码种类")).toBeInTheDocument();
    expect(screen.getByText("目标 Unit 数")).toBeInTheDocument();
  });

  it("shows Modbus transaction table with data", async () => {
    mocks.getIndustrialAnalysis.mockResolvedValue(createAnalysis({
      totalIndustrialPackets: 10,
      protocols: [{ label: "Modbus/TCP", count: 10 }],
      modbus: {
        totalFrames: 10,
        requests: 5,
        responses: 5,
        exceptions: 0,
        functionCodes: [{ label: "读线圈", count: 5 }],
        unitIds: [{ label: "Unit 1", count: 10 }],
        referenceHits: [{ label: "Ref 00001", count: 5 }],
        exceptionCodes: [],
        transactions: [{
          packetId: 100,
          time: "2.500000",
          source: "192.168.1.10",
          destination: "192.168.1.20",
          transactionId: 1,
          unitId: 1,
          functionCode: 1,
          functionName: "读线圈",
          kind: "request",
          reference: "Ref 00001",
          quantity: "8",
          exceptionCode: 0,
          responseTime: "",
          summary: "Read Coils",
        }],
      },
    }));

    render(<IndustrialAnalysis />);

    await waitFor(() => {
      expect(screen.getByText("Modbus 事务明细 (1)")).toBeInTheDocument();
    });
    expect(screen.getByText("包号")).toBeInTheDocument();
    expect(screen.getByText("时间")).toBeInTheDocument();
    expect(screen.getByText("源")).toBeInTheDocument();
    expect(screen.getByText("目标")).toBeInTheDocument();
    expect(screen.getByText("功能码")).toBeInTheDocument();
    expect(screen.getByText("Unit")).toBeInTheDocument();
    expect(screen.getByText("引用")).toBeInTheDocument();
    expect(screen.getByText("192.168.1.10")).toBeInTheDocument();
    expect(screen.getByText("192.168.1.20")).toBeInTheDocument();
    expect(screen.getAllByText("读线圈").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("Ref 00001").length).toBeGreaterThanOrEqual(1);
  });

  it("filters Modbus transactions by unit ID", async () => {
    mocks.getIndustrialAnalysis.mockResolvedValue(createAnalysis({
      totalIndustrialPackets: 3,
      protocols: [{ label: "Modbus/TCP", count: 3 }],
      modbus: {
        totalFrames: 3,
        requests: 3,
        responses: 0,
        exceptions: 0,
        functionCodes: [{ label: "写多寄存器", count: 3 }],
        unitIds: [{ label: "Unit 1", count: 2 }, { label: "Unit 2", count: 1 }],
        referenceHits: [],
        exceptionCodes: [],
        transactions: [
          {
            packetId: 10, time: "1.000000", source: "10.0.0.1", destination: "10.0.0.2",
            transactionId: 1, unitId: 1, functionCode: 16, functionName: "写多寄存器",
            kind: "request", reference: "", quantity: "", exceptionCode: 0, responseTime: "", summary: "Write 1",
          },
          {
            packetId: 20, time: "2.000000", source: "10.0.0.1", destination: "10.0.0.3",
            transactionId: 2, unitId: 2, functionCode: 16, functionName: "写多寄存器",
            kind: "request", reference: "", quantity: "", exceptionCode: 0, responseTime: "", summary: "Write 2",
          },
          {
            packetId: 30, time: "3.000000", source: "10.0.0.1", destination: "10.0.0.2",
            transactionId: 3, unitId: 1, functionCode: 16, functionName: "写多寄存器",
            kind: "request", reference: "", quantity: "", exceptionCode: 0, responseTime: "", summary: "Write 3",
          },
        ],
      },
    }));

    render(<IndustrialAnalysis />);

    await waitFor(() => {
      expect(screen.getByText("Modbus 事务明细 (3)")).toBeInTheDocument();
    });
    expect(screen.getByText("10.0.0.3")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "2" }));

    await waitFor(() => {
      expect(screen.getByText("Modbus 事务明细 (1)")).toBeInTheDocument();
    });
    expect(screen.getByText("10.0.0.3")).toBeInTheDocument();
    expect(screen.getByText("Write 2")).toBeInTheDocument();
  });

  it("filters Modbus transactions by function code", async () => {
    mocks.getIndustrialAnalysis.mockResolvedValue(createAnalysis({
      totalIndustrialPackets: 3,
      protocols: [{ label: "Modbus/TCP", count: 3 }],
      modbus: {
        totalFrames: 3,
        requests: 3,
        responses: 0,
        exceptions: 0,
        functionCodes: [{ label: "写多寄存器", count: 2 }, { label: "读线圈", count: 1 }],
        unitIds: [{ label: "Unit 1", count: 3 }],
        referenceHits: [],
        exceptionCodes: [],
        transactions: [
          {
            packetId: 10, time: "1.000000", source: "10.0.0.1", destination: "10.0.0.2",
            transactionId: 1, unitId: 1, functionCode: 16, functionName: "写多寄存器",
            kind: "request", reference: "", quantity: "", exceptionCode: 0, responseTime: "", summary: "Write A",
          },
          {
            packetId: 20, time: "2.000000", source: "10.0.0.1", destination: "10.0.0.2",
            transactionId: 2, unitId: 1, functionCode: 1, functionName: "读线圈",
            kind: "request", reference: "", quantity: "", exceptionCode: 0, responseTime: "", summary: "Read Coils",
          },
          {
            packetId: 30, time: "3.000000", source: "10.0.0.1", destination: "10.0.0.2",
            transactionId: 3, unitId: 1, functionCode: 16, functionName: "写多寄存器",
            kind: "request", reference: "", quantity: "", exceptionCode: 0, responseTime: "", summary: "Write B",
          },
        ],
      },
    }));

    render(<IndustrialAnalysis />);

    await waitFor(() => {
      expect(screen.getByText("Modbus 事务明细 (3)")).toBeInTheDocument();
    });
    expect(screen.getAllByText("写多寄存器").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("读线圈").length).toBeGreaterThanOrEqual(1);

    fireEvent.click(screen.getByRole("button", { name: "16" }));

    await waitFor(() => {
      expect(screen.getByText("Modbus 事务明细 (2)")).toBeInTheDocument();
    });
    expect(screen.getByText("Write A")).toBeInTheDocument();
    expect(screen.getByText("Write B")).toBeInTheDocument();
    expect(screen.queryByText("Read Coils")).not.toBeInTheDocument();
  });
});
