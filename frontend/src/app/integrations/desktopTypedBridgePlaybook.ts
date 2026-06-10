import type {
  HuntingPlaybook,
  Hypothesis,
  PlaybookRunResult,
  SavedSearch,
  ThreatHit,
} from "../core/types/huntingPlaybook";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { LONG_TYPED_IPC_TIMEOUT_MS, typedCall } from "./desktopTypedBridgeCore";

export function createPlaybookTypedOverrides(desktopApp: DesktopTransportBinding): Partial<BackendBridge> {
  return {
    async listPlaybooks() {
      return (await typedCall(() => desktopApp.ListPlaybooks!(), "DesktopApp.ListPlaybooks")) as HuntingPlaybook[];
    },
    async getPlaybook(id) {
      return (await typedCall(() => desktopApp.GetPlaybook!(id), "DesktopApp.GetPlaybook")) as HuntingPlaybook;
    },
    async createPlaybook(playbook) {
      return (await typedCall(
        () => desktopApp.CreatePlaybook!(playbook),
        "DesktopApp.CreatePlaybook",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      )) as HuntingPlaybook;
    },
    async updatePlaybook(id, playbook) {
      return (await typedCall(
        () => desktopApp.UpdatePlaybook!(id, playbook),
        "DesktopApp.UpdatePlaybook",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      )) as HuntingPlaybook;
    },
    async deletePlaybook(id) {
      await typedCall(
        () => desktopApp.DeletePlaybook!(id),
        "DesktopApp.DeletePlaybook",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      );
    },
    async runPlaybook(id) {
      return (await typedCall(
        () => desktopApp.RunPlaybook!(id),
        "DesktopApp.RunPlaybook",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      )) as PlaybookRunResult;
    },
    async getPlaybookLastRun(id) {
      return (await typedCall(
        () => desktopApp.GetPlaybookLastRun!(id),
        "DesktopApp.GetPlaybookLastRun",
      )) as PlaybookRunResult;
    },
    async listSavedSearches() {
      return (await typedCall(() => desktopApp.ListSavedSearches!(), "DesktopApp.ListSavedSearches")) as SavedSearch[];
    },
    async getSavedSearch(id) {
      return (await typedCall(() => desktopApp.GetSavedSearch!(id), "DesktopApp.GetSavedSearch")) as SavedSearch;
    },
    async createSavedSearch(search) {
      return (await typedCall(
        () => desktopApp.CreateSavedSearch!(search),
        "DesktopApp.CreateSavedSearch",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      )) as SavedSearch;
    },
    async updateSavedSearch(id, search) {
      return (await typedCall(
        () => desktopApp.UpdateSavedSearch!(id, search),
        "DesktopApp.UpdateSavedSearch",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      )) as SavedSearch;
    },
    async deleteSavedSearch(id) {
      await typedCall(
        () => desktopApp.DeleteSavedSearch!(id),
        "DesktopApp.DeleteSavedSearch",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      );
    },
    async executeSavedSearch(id) {
      return (await typedCall(
        () => desktopApp.ExecuteSavedSearch!(id),
        "DesktopApp.ExecuteSavedSearch",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      )) as { search: SavedSearch; hits: ThreatHit[]; total: number };
    },
    async listHypotheses(status) {
      return (await typedCall(
        () => desktopApp.ListHypotheses!(status ?? ""),
        "DesktopApp.ListHypotheses",
      )) as Hypothesis[];
    },
    async getHypothesis(id) {
      return (await typedCall(() => desktopApp.GetHypothesis!(id), "DesktopApp.GetHypothesis")) as Hypothesis;
    },
    async createHypothesis(hypothesis) {
      return (await typedCall(
        () => desktopApp.CreateHypothesis!(hypothesis),
        "DesktopApp.CreateHypothesis",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      )) as Hypothesis;
    },
    async updateHypothesis(id, hypothesis) {
      return (await typedCall(
        () => desktopApp.UpdateHypothesis!(id, hypothesis),
        "DesktopApp.UpdateHypothesis",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      )) as Hypothesis;
    },
    async deleteHypothesis(id) {
      await typedCall(
        () => desktopApp.DeleteHypothesis!(id),
        "DesktopApp.DeleteHypothesis",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      );
    },
    async addHypothesisEvidence(hypothesisId, evidence) {
      return (await typedCall(
        () => desktopApp.AddHypothesisEvidence!(hypothesisId, evidence),
        "DesktopApp.AddHypothesisEvidence",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      )) as Hypothesis;
    },
    async updateHypothesisStatus(id, status, conclusion) {
      return (await typedCall(
        () => desktopApp.UpdateHypothesisStatus!(id, status, conclusion ?? ""),
        "DesktopApp.UpdateHypothesisStatus",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      )) as Hypothesis;
    },
  };
}
