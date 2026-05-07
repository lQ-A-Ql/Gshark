import { render, screen, waitFor } from "@testing-library/react";
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

vi.mock("../state/SentinelContext", () => ({
  useSentinel: () => mocks.sentinelState,
}));

vi.mock("../integrations/wailsBridge", () => ({
  bridge: {
    getIndustrialAnalysis: mocks.getIndustrialAnalysis,
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
});
