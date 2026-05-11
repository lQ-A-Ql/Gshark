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

async function renderAndExpand(moduleID: string, waitForContent: () => unknown) {
  render(<MiscTools />);
  await expandModule(moduleID, waitForContent);
}

describe("MiscTools session candidate modules", () => {
  beforeEach(() => {
    resetMiscToolsMocks(mocks);
  });

  it("defers session candidate loading until modules are expanded", async () => {
    render(<MiscTools />);

    await waitFor(() => {
      expect(mocks.listMiscModules).toHaveBeenCalledTimes(1);
      expect(screen.getByTestId("misc-module-toggle-http-login-analysis")).toBeInTheDocument();
    });
    expect(mocks.getMySQLAnalysis).not.toHaveBeenCalled();
    expect(mocks.getSMTPAnalysis).not.toHaveBeenCalled();
    expect(mocks.getShiroRememberMeAnalysis).not.toHaveBeenCalled();
    expect(mocks.listNTLMSessionMaterials).not.toHaveBeenCalled();
    expect(mocks.listSMB3SessionCandidates).not.toHaveBeenCalled();
  });

  it("loads NTLM session materials after expansion", async () => {
    await renderAndExpand("ntlm-session-materials", () =>
      expect(screen.getByText(/当前筛选命中 2 条材料/)).toBeInTheDocument(),
    );
    expect(mocks.listNTLMSessionMaterials).toHaveBeenCalledTimes(1);
    expect(screen.getAllByText("LAB\\Administrator").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Guest").length).toBeGreaterThan(0);
  });

  it("loads MySQL session details after expansion", async () => {
    await renderAndExpand("mysql-session-analysis", () =>
      expect(screen.getByText("DELETE FROM audit_logs")).toBeInTheDocument(),
    );
    expect(mocks.getMySQLAnalysis).toHaveBeenCalledTimes(1);
    expect(screen.getAllByText("MySQL 会话重建").length).toBeGreaterThan(0);
  }, 15000);

  it("loads SMTP session details after expansion", async () => {
    await renderAndExpand("smtp-session-analysis", () =>
      expect(screen.getByText("Quarterly Report")).toBeInTheDocument(),
    );
    expect(mocks.getSMTPAnalysis).toHaveBeenCalledTimes(1);
    expect(screen.getAllByText("SMTP 会话重建").length).toBeGreaterThan(0);
  }, 15000);

  it("loads Shiro rememberMe details after expansion", async () => {
    await renderAndExpand("shiro-rememberme-analysis", () =>
      expect(screen.getByText("org.apache.shiro.subject.SimplePrincipalCollection")).toBeInTheDocument(),
    );
    expect(mocks.getShiroRememberMeAnalysis).toHaveBeenCalledTimes(1);
    expect(screen.getAllByText("Shiro rememberMe 分析").length).toBeGreaterThan(0);
  });

  it("links Shiro rememberMe candidates back to packet and stream evidence", async () => {
    await renderAndExpand("shiro-rememberme-analysis", () =>
      expect(screen.getByText("org.apache.shiro.subject.SimplePrincipalCollection")).toBeInTheDocument(),
    );

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
});
