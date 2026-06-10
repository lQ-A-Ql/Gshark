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

function openModbusSection() {
  fireEvent.click(screen.getByRole("button", { name: /Modbus/ }));
}

function openDnp3Section() {
  fireEvent.click(screen.getByRole("button", { name: /DNP3/ }));
}

function openCommandsSection() {
  fireEvent.click(screen.getByRole("button", { name: /控制命令/ }));
}

function openDetailsSection() {
  fireEvent.click(screen.getByRole("button", { name: /^明细 协议明细记录$/ }));
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
    openModbusSection();

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

    openModbusSection();
    await waitFor(() => {
      expect(screen.getByText("Modbus 请求")).toBeInTheDocument();
    });
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
    openModbusSection();

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
    openModbusSection();

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
    openModbusSection();

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

  it("renders a DNP3-specific section from generic industrial details, commands, and rules", async () => {
    mocks.getIndustrialAnalysis.mockResolvedValue(createAnalysis({
      totalIndustrialPackets: 12,
      protocols: [{ label: "DNP3", count: 12 }],
      controlCommands: [
        {
          packetId: 301,
          time: "4.100000",
          protocol: "DNP3",
          source: "172.16.0.10",
          destination: "172.16.0.20",
          operation: "operate",
          target: "index=12",
          value: "trip",
          result: "success",
          summary: "DNP3 operate command",
        },
      ],
      ruleHits: [
        {
          rule: "dnp3-operate-burst",
          level: "high",
          packetId: 302,
          time: "4.200000",
          source: "172.16.0.10",
          destination: "172.16.0.20",
          functionName: "operate",
          target: "outstation-7",
          evidence: "fc=5 count=3",
          summary: "Repeated DNP3 operate requests",
        },
      ],
      details: [
        {
          name: "DNP3 outstation",
          totalFrames: 9,
          operations: [{ label: "select", count: 2 }],
          targets: [{ label: "index=12", count: 2 }],
          results: [{ label: "ack", count: 1 }],
          records: [
            {
              packetId: 300,
              time: "4.000000",
              source: "172.16.0.10",
              destination: "172.16.0.20",
              operation: "select",
              target: "index=12",
              result: "ack",
              value: "trip",
              summary: "DNP3 select before operate",
            },
          ],
        },
      ],
    }));

    render(<IndustrialAnalysis />);
    openDnp3Section();

    await waitFor(() => {
      expect(screen.getByText("DNP3 专项 (3)")).toBeInTheDocument();
    });

    expect(screen.getByText("明细记录")).toBeInTheDocument();
    expect(screen.getByText("控制指令")).toBeInTheDocument();
    expect(screen.getByText("规则命中")).toBeInTheDocument();
    expect(screen.getAllByText("操作类型").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("DNP3 select before operate").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("DNP3 operate command").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("Repeated DNP3 operate requests").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("index=12").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("fc=5 count=3").length).toBeGreaterThanOrEqual(1);

    openDetailsSection();
    await waitFor(() => {
      expect(screen.getByText("DNP3 outstation 明细 (1)")).toBeInTheDocument();
    });
    expect(screen.getByText("DNP3 outstation 明细 (1)")).toBeInTheDocument();
  });

  it("does not render a DNP3-specific section when no DNP3 data exists", async () => {
    mocks.getIndustrialAnalysis.mockResolvedValue(createAnalysis({
      totalIndustrialPackets: 5,
      protocols: [{ label: "Modbus/TCP", count: 5 }],
      controlCommands: [
        {
          packetId: 401,
          time: "5.100000",
          protocol: "IEC104",
          source: "10.1.0.10",
          destination: "10.1.0.20",
          operation: "single command",
          target: "ioa=7",
          value: "on",
          result: "ack",
          summary: "IEC104 single command",
        },
      ],
      ruleHits: [{ rule: "modbus-write", level: "high", packetId: 402, summary: "Modbus burst write" }],
      details: [
        {
          name: "IEC104",
          totalFrames: 2,
          operations: [{ label: "single command", count: 1 }],
          targets: [{ label: "ioa=7", count: 1 }],
          results: [{ label: "ack", count: 1 }],
          records: [{ packetId: 401, time: "5.100000", source: "10.1.0.10", destination: "10.1.0.20", operation: "single command", target: "ioa=7", result: "ack", summary: "IEC104 record" }],
        },
      ],
    }));

    render(<IndustrialAnalysis />);
    openCommandsSection();

    await waitFor(() => {
      expect(screen.getByText("控制指令 (1)")).toBeInTheDocument();
    });

    expect(screen.queryByText(/DNP3 专项/)).not.toBeInTheDocument();
    openDetailsSection();
    await waitFor(() => {
      expect(screen.getByText("IEC104 明细 (1)")).toBeInTheDocument();
    });
    expect(screen.getByText("IEC104 record")).toBeInTheDocument();

    openCommandsSection();
    await waitFor(() => {
      expect(screen.getByText("控制指令 (1)")).toBeInTheDocument();
    });
    expect(screen.getByText("IEC104 single command")).toBeInTheDocument();
  });
});
