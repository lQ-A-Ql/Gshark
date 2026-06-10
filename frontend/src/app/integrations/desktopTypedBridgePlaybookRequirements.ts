import type { DesktopTransportBinding } from "./bridgeTypes";

export const playbookTypedBindingRequirements: Record<string, keyof DesktopTransportBinding> = {
  listPlaybooks: "ListPlaybooks",
  getPlaybook: "GetPlaybook",
  createPlaybook: "CreatePlaybook",
  updatePlaybook: "UpdatePlaybook",
  deletePlaybook: "DeletePlaybook",
  runPlaybook: "RunPlaybook",
  getPlaybookLastRun: "GetPlaybookLastRun",
  listSavedSearches: "ListSavedSearches",
  getSavedSearch: "GetSavedSearch",
  createSavedSearch: "CreateSavedSearch",
  updateSavedSearch: "UpdateSavedSearch",
  deleteSavedSearch: "DeleteSavedSearch",
  executeSavedSearch: "ExecuteSavedSearch",
  listHypotheses: "ListHypotheses",
  getHypothesis: "GetHypothesis",
  createHypothesis: "CreateHypothesis",
  updateHypothesis: "UpdateHypothesis",
  deleteHypothesis: "DeleteHypothesis",
  addHypothesisEvidence: "AddHypothesisEvidence",
  updateHypothesisStatus: "UpdateHypothesisStatus",
};
