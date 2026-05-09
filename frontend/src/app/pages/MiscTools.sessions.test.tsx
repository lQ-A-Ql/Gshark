import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { expandModule, resetMiscToolsMocks } from "./MiscTools.testFixtures";

const mocks = vi.hoisted(() => ({
  listMiscModules: vi.fn(),
  importMiscModulePackage: vi.fn(),
  deleteMiscModule: vi.fn(),
  runMiscModule: vi.fn(),
  getHTTPLoginAnalysis: vi.fn(),
  getMySQLAnalysis: vi.fn(),
  getSMTPAnalysis: vi.fn(),
  getShiroRememberMeAnalysis: vi.fn(),
  decodeStreamPayload: vi.fn(),
  inspectStreamPayload: vi.fn(),
  listStreamPayloadSources: vi.fn(),
  listNTLMSessionMaterials: vi.fn(),
  listSMB3SessionCandidates: vi.fn(),
  generateSMB3RandomSessionKey: vi.fn(),
  runWinRMDecrypt: vi.fn(),
  getWinRMDecryptResultText: vi.fn(),
  exportWinRMDecryptResult: vi.fn(),
  navigate: vi.fn(),
  sentinelState: {
    fileMeta: {
      name: "capture.pcapng",
      sizeBytes: 2048,
      path: "C:/captures/capture.pcapng",
    },
    locatePacketById: vi.fn(),
    preparePacketStream: vi.fn(),
    setActiveStream: vi.fn(),
  },
}));

vi.mock("../state/SentinelContext", () => ({
  useSentinel: () => mocks.sentinelState,
}));

vi.mock("../integrations/wailsBridge", () => ({
  bridge: {
    listMiscModules: mocks.listMiscModules,
    importMiscModulePackage: mocks.importMiscModulePackage,
    deleteMiscModule: mocks.deleteMiscModule,
    runMiscModule: mocks.runMiscModule,
    getHTTPLoginAnalysis: mocks.getHTTPLoginAnalysis,
    getMySQLAnalysis: mocks.getMySQLAnalysis,
    getSMTPAnalysis: mocks.getSMTPAnalysis,
    getShiroRememberMeAnalysis: mocks.getShiroRememberMeAnalysis,
    decodeStreamPayload: mocks.decodeStreamPayload,
    inspectStreamPayload: mocks.inspectStreamPayload,
    listStreamPayloadSources: mocks.listStreamPayloadSources,
    listNTLMSessionMaterials: mocks.listNTLMSessionMaterials,
    listSMB3SessionCandidates: mocks.listSMB3SessionCandidates,
    generateSMB3RandomSessionKey: mocks.generateSMB3RandomSessionKey,
    runWinRMDecrypt: mocks.runWinRMDecrypt,
    getWinRMDecryptResultText: mocks.getWinRMDecryptResultText,
    exportWinRMDecryptResult: mocks.exportWinRMDecryptResult,
  },
}));

vi.mock("react-router", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router")>();
  return {
    ...actual,
    useNavigate: () => mocks.navigate,
  };
});

import MiscTools from "./MiscTools";

describe("MiscTools session candidate modules", () => {
  beforeEach(() => {
    resetMiscToolsMocks(mocks);
  });

  it(
    "loads candidates and renders detailed selector options",
    async () => {
      render(<MiscTools />);

      await waitFor(() => {
        expect(mocks.listMiscModules).toHaveBeenCalledTimes(1);
        expect(mocks.getHTTPLoginAnalysis).toHaveBeenCalledTimes(1);
      });
      expect(mocks.getMySQLAnalysis).not.toHaveBeenCalled();
      expect(mocks.getSMTPAnalysis).not.toHaveBeenCalled();
      expect(mocks.getShiroRememberMeAnalysis).not.toHaveBeenCalled();
      expect(mocks.listNTLMSessionMaterials).not.toHaveBeenCalled();
      expect(mocks.listSMB3SessionCandidates).not.toHaveBeenCalled();

      await expandModule("ntlm-session-materials");
      await waitFor(() => {
        expect(mocks.listNTLMSessionMaterials).toHaveBeenCalledTimes(1);
      });

      await expandModule("mysql-session-analysis");
      await waitFor(() => {
        expect(mocks.getMySQLAnalysis).toHaveBeenCalledTimes(1);
      });

      await expandModule("smtp-session-analysis");
      await waitFor(() => {
        expect(mocks.getSMTPAnalysis).toHaveBeenCalledTimes(1);
      });

      await expandModule("shiro-rememberme-analysis");
      await waitFor(() => {
        expect(mocks.getShiroRememberMeAnalysis).toHaveBeenCalledTimes(1);
      });

      await expandModule("smb3-session-key");
      await waitFor(() => {
        expect(mocks.listSMB3SessionCandidates).toHaveBeenCalledTimes(1);
      });

      expect(await screen.findByText("已发现 2 条候选，其中 1 条材料完整")).toBeInTheDocument();
      expect(screen.getByTestId("smb-session-candidate-101")).toBeInTheDocument();
      expect(screen.getByTestId("smb-session-candidate-102")).toBeInTheDocument();
      expect(screen.getAllByText("LAB\\Administrator").length).toBeGreaterThan(0);
      expect(screen.getAllByText("Guest").length).toBeGreaterThan(0);
      expect(screen.getAllByText("MySQL 会话重建").length).toBeGreaterThan(0);
      expect(screen.getByText("DELETE FROM audit_logs")).toBeInTheDocument();
      expect(screen.getAllByText("SMTP 会话重建").length).toBeGreaterThan(0);
      expect(screen.getByText("Quarterly Report")).toBeInTheDocument();
      expect(screen.getAllByText("Shiro rememberMe 分析").length).toBeGreaterThan(0);
      expect(screen.getByText("org.apache.shiro.subject.SimplePrincipalCollection")).toBeInTheDocument();
    },
    10000,
  );

  it("links Shiro rememberMe candidates back to packet and stream evidence", async () => {
    render(<MiscTools />);

    await expandModule("shiro-rememberme-analysis");
    expect(await screen.findByText("org.apache.shiro.subject.SimplePrincipalCollection")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "定位到包" }));
    await waitFor(() => {
      expect(mocks.sentinelState.locatePacketById).toHaveBeenCalledWith(401);
    });
    expect(mocks.navigate).toHaveBeenCalledWith("/");

    fireEvent.click(screen.getByRole("button", { name: "打开关联流" }));
    await waitFor(() => {
      expect(mocks.sentinelState.preparePacketStream).toHaveBeenCalledWith(401, "HTTP");
    });
    expect(mocks.navigate).toHaveBeenCalledWith("/http-stream", { state: { streamId: 44 } });
  });

  it("autofills non-hash fields after selecting a candidate and keeps hash editable", async () => {
    render(<MiscTools />);

    await waitFor(() => {
      expect(mocks.listMiscModules).toHaveBeenCalled();
    });
    expect(mocks.listSMB3SessionCandidates).not.toHaveBeenCalled();

    await expandModule("smb3-session-key");
    await waitFor(() => {
      expect(mocks.listSMB3SessionCandidates).toHaveBeenCalledTimes(1);
    });

    const hashInput = screen.getByLabelText("NTLM Hash (十六进制)") as HTMLInputElement;
    fireEvent.change(hashInput, { target: { value: "31d6cfe0d16ae931b73c59d7e0c089c0" } });

    fireEvent.click(screen.getByTestId("smb-session-candidate-101"));

    expect((screen.getByLabelText("Username (用户名)") as HTMLInputElement).value).toBe("Administrator");
    expect((screen.getByLabelText("Domain (域名/可留空)") as HTMLInputElement).value).toBe("LAB");
    expect((screen.getByLabelText("NTProofStr") as HTMLInputElement).value).toBe("00112233445566778899aabbccddeeff");
    expect((screen.getByLabelText("Encrypted Session Key") as HTMLInputElement).value).toBe("ffeeddccbbaa99887766554433221100");
    expect(hashInput.value).toBe("31d6cfe0d16ae931b73c59d7e0c089c0");

    fireEvent.change(screen.getByLabelText("Username (用户名)"), { target: { value: "Admin2" } });
    expect((screen.getByLabelText("Username (用户名)") as HTMLInputElement).value).toBe("Admin2");
  });

  it("does not load candidates when no capture is active", () => {
    mocks.sentinelState.fileMeta.path = "";

    render(<MiscTools />);

    return waitFor(() => {
      expect(mocks.listMiscModules).toHaveBeenCalled();
      expect(mocks.getHTTPLoginAnalysis).not.toHaveBeenCalled();
      expect(mocks.getMySQLAnalysis).not.toHaveBeenCalled();
      expect(mocks.getSMTPAnalysis).not.toHaveBeenCalled();
      expect(mocks.getShiroRememberMeAnalysis).not.toHaveBeenCalled();
      expect(mocks.listSMB3SessionCandidates).not.toHaveBeenCalled();
    }).then(async () => {
      await expandModule("smb3-session-key");
      const selector = screen.getByTestId("smb-session-candidate-select");
      expect(selector).toHaveAttribute("aria-disabled", "true");
      expect(selector).toHaveTextContent("未加载抓包，请先在主工作区导入文件");
    });
  });

  it("shows a concise error when candidate loading fails", async () => {
    mocks.listSMB3SessionCandidates.mockRejectedValueOnce(new Error("扫描 SMB3 Session 候选失败"));

    render(<MiscTools />);

    await expandModule("smb3-session-key");
    expect(await screen.findByText("扫描 SMB3 Session 候选失败")).toBeInTheDocument();
  });
});
