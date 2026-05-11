import { fireEvent, screen, waitFor } from "@testing-library/react";

import {
  createHTTPLoginAnalysisFixture,
  createMiscModulesFixture,
  createMySQLAnalysisFixture,
  createNTLMSessionMaterialsFixture,
  createPayloadDecodeFixture,
  createPayloadInspectionFixture,
  createRunMiscModuleResult,
  createShiroRememberMeAnalysisFixture,
  createSMB3SessionCandidatesFixture,
  createSMTPAnalysisFixture,
} from "./MiscTools.mockData";

export function resetMiscToolsMocks(mocks: any) {
  window.localStorage.clear();
  mocks.sentinelState.fileMeta.path = "C:/captures/capture.pcapng";
  mocks.sentinelState.fileMeta.name = "capture.pcapng";
  mocks.sentinelState.locatePacketById.mockReset();
  mocks.sentinelState.preparePacketStream.mockReset();
  mocks.sentinelState.setActiveStream.mockReset();
  mocks.sentinelState.locatePacketById.mockResolvedValue(null);
  mocks.sentinelState.preparePacketStream.mockResolvedValue({ packet: null, protocol: "HTTP", streamId: 44 });
  mocks.sentinelState.setActiveStream.mockResolvedValue(undefined);
  mocks.listMiscModules.mockReset();
  mocks.importMiscModulePackage.mockReset();
  mocks.deleteMiscModule.mockReset();
  mocks.runMiscModule.mockReset();
  mocks.getHTTPLoginAnalysis.mockReset();
  mocks.getMySQLAnalysis.mockReset();
  mocks.getSMTPAnalysis.mockReset();
  mocks.getShiroRememberMeAnalysis.mockReset();
  mocks.decodeStreamPayload.mockReset();
  mocks.inspectStreamPayload.mockReset();
  mocks.listStreamPayloadSources.mockReset();
  mocks.listNTLMSessionMaterials.mockReset();
  mocks.listSMB3SessionCandidates.mockReset();
  mocks.generateSMB3RandomSessionKey.mockReset();
  mocks.runWinRMDecrypt.mockReset();
  mocks.getWinRMDecryptResultText.mockReset();
  mocks.exportWinRMDecryptResult.mockReset();
  mocks.navigate.mockReset();
  mocks.deleteMiscModule.mockResolvedValue(undefined);
  mocks.runMiscModule.mockResolvedValue(createRunMiscModuleResult());
  mocks.getHTTPLoginAnalysis.mockResolvedValue(createHTTPLoginAnalysisFixture());
  mocks.getSMTPAnalysis.mockResolvedValue(createSMTPAnalysisFixture());
  mocks.getMySQLAnalysis.mockResolvedValue(createMySQLAnalysisFixture());
  mocks.getShiroRememberMeAnalysis.mockResolvedValue(createShiroRememberMeAnalysisFixture());
  mocks.inspectStreamPayload.mockResolvedValue(createPayloadInspectionFixture());
  mocks.decodeStreamPayload.mockResolvedValue(createPayloadDecodeFixture());
  mocks.listStreamPayloadSources.mockResolvedValue([]);
  mocks.listNTLMSessionMaterials.mockResolvedValue(createNTLMSessionMaterialsFixture());
  mocks.listMiscModules.mockResolvedValue(createMiscModulesFixture());
  mocks.listSMB3SessionCandidates.mockResolvedValue(createSMB3SessionCandidatesFixture());
}

export async function expandModule(moduleID: string, waitForContent?: () => unknown) {
  const toggle = await screen.findByTestId(`misc-module-toggle-${moduleID}`);
  if (toggle.getAttribute("aria-expanded") !== "true") {
    fireEvent.click(toggle);
  }
  await waitFor(() => {
    const currentToggle = screen.getByTestId(`misc-module-toggle-${moduleID}`);
    if (currentToggle.getAttribute("aria-expanded") !== "true") {
      throw new Error(`MISC module ${moduleID} did not expand`);
    }
  }, { timeout: 10000 });
  if (waitForContent) {
    await waitFor(waitForContent, { timeout: 25000 });
  }
}
