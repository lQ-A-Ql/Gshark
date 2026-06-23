import type {
  HuntingPlaybook,
  Hypothesis,
  HypothesisEvidence,
  HypothesisStatus,
  PlaybookRunResult,
  SavedSearch,
  ThreatHit,
} from "../../core/types/huntingPlaybook";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

export interface PlaybookClient {
  // Playbook CRUD
  listPlaybooks(signal?: AbortSignal): Promise<HuntingPlaybook[]>;
  getPlaybook(id: string, signal?: AbortSignal): Promise<HuntingPlaybook>;
  createPlaybook(playbook: Partial<HuntingPlaybook>, signal?: AbortSignal): Promise<HuntingPlaybook>;
  updatePlaybook(id: string, playbook: Partial<HuntingPlaybook>, signal?: AbortSignal): Promise<HuntingPlaybook>;
  deletePlaybook(id: string, signal?: AbortSignal): Promise<void>;
  runPlaybook(id: string, signal?: AbortSignal): Promise<PlaybookRunResult>;
  getPlaybookLastRun(id: string, signal?: AbortSignal): Promise<PlaybookRunResult>;

  // Saved search CRUD
  listSavedSearches(signal?: AbortSignal): Promise<SavedSearch[]>;
  getSavedSearch(id: string, signal?: AbortSignal): Promise<SavedSearch>;
  createSavedSearch(search: Partial<SavedSearch>, signal?: AbortSignal): Promise<SavedSearch>;
  updateSavedSearch(id: string, search: Partial<SavedSearch>, signal?: AbortSignal): Promise<SavedSearch>;
  deleteSavedSearch(id: string, signal?: AbortSignal): Promise<void>;
  executeSavedSearch(
    id: string,
    signal?: AbortSignal,
  ): Promise<{ search: SavedSearch; hits: ThreatHit[]; total: number }>;

  // Hypothesis CRUD
  listHypotheses(status?: HypothesisStatus, signal?: AbortSignal): Promise<Hypothesis[]>;
  getHypothesis(id: string, signal?: AbortSignal): Promise<Hypothesis>;
  createHypothesis(hypothesis: Partial<Hypothesis>, signal?: AbortSignal): Promise<Hypothesis>;
  updateHypothesis(id: string, hypothesis: Partial<Hypothesis>, signal?: AbortSignal): Promise<Hypothesis>;
  deleteHypothesis(id: string, signal?: AbortSignal): Promise<void>;
  addHypothesisEvidence(
    hypothesisId: string,
    evidence: Partial<HypothesisEvidence>,
    signal?: AbortSignal,
  ): Promise<Hypothesis>;
  updateHypothesisStatus(
    id: string,
    status: HypothesisStatus,
    conclusion?: string,
    signal?: AbortSignal,
  ): Promise<Hypothesis>;
}

export function createPlaybookClient(request: JsonRequest): PlaybookClient {
  return {
    // Playbook CRUD
    async listPlaybooks(signal) {
      return request<HuntingPlaybook[]>("/api/playbooks", { signal });
    },

    async getPlaybook(id, signal) {
      return request<HuntingPlaybook>(`/api/playbooks/${encodeURIComponent(id)}`, { signal });
    },

    async createPlaybook(playbook, signal) {
      return request<HuntingPlaybook>("/api/playbooks", {
        method: "POST",
        body: JSON.stringify(playbook),
        signal,
      });
    },

    async updatePlaybook(id, playbook, signal) {
      return request<HuntingPlaybook>(`/api/playbooks/${encodeURIComponent(id)}`, {
        method: "PUT",
        body: JSON.stringify(playbook),
        signal,
      });
    },

    async deletePlaybook(id, signal) {
      await request<void>(`/api/playbooks/${encodeURIComponent(id)}`, {
        method: "DELETE",
        signal,
      });
    },

    async runPlaybook(id, signal) {
      return request<PlaybookRunResult>(`/api/playbooks/${encodeURIComponent(id)}/run`, {
        method: "POST",
        signal,
      });
    },

    async getPlaybookLastRun(id, signal) {
      return request<PlaybookRunResult>(`/api/playbooks/${encodeURIComponent(id)}/last-run`, { signal });
    },

    // Saved search CRUD
    async listSavedSearches(signal) {
      return request<SavedSearch[]>("/api/hunting/saved-searches", { signal });
    },

    async getSavedSearch(id, signal) {
      return request<SavedSearch>(`/api/hunting/saved-searches/${encodeURIComponent(id)}`, { signal });
    },

    async createSavedSearch(search, signal) {
      return request<SavedSearch>("/api/hunting/saved-searches", {
        method: "POST",
        body: JSON.stringify(search),
        signal,
      });
    },

    async updateSavedSearch(id, search, signal) {
      return request<SavedSearch>(`/api/hunting/saved-searches/${encodeURIComponent(id)}`, {
        method: "PUT",
        body: JSON.stringify(search),
        signal,
      });
    },

    async deleteSavedSearch(id, signal) {
      await request<void>(`/api/hunting/saved-searches/${encodeURIComponent(id)}`, {
        method: "DELETE",
        signal,
      });
    },

    async executeSavedSearch(id, signal) {
      return request<{ search: SavedSearch; hits: ThreatHit[]; total: number }>(
        `/api/hunting/saved-searches/${encodeURIComponent(id)}/execute`,
        { method: "POST", signal },
      );
    },

    // Hypothesis CRUD
    async listHypotheses(status, signal) {
      const query = status ? `?status=${encodeURIComponent(status)}` : "";
      return request<Hypothesis[]>(`/api/hunting/hypotheses${query}`, { signal });
    },

    async getHypothesis(id, signal) {
      return request<Hypothesis>(`/api/hunting/hypotheses/${encodeURIComponent(id)}`, { signal });
    },

    async createHypothesis(hypothesis, signal) {
      return request<Hypothesis>("/api/hunting/hypotheses", {
        method: "POST",
        body: JSON.stringify(hypothesis),
        signal,
      });
    },

    async updateHypothesis(id, hypothesis, signal) {
      return request<Hypothesis>(`/api/hunting/hypotheses/${encodeURIComponent(id)}`, {
        method: "PUT",
        body: JSON.stringify(hypothesis),
        signal,
      });
    },

    async deleteHypothesis(id, signal) {
      await request<void>(`/api/hunting/hypotheses/${encodeURIComponent(id)}`, {
        method: "DELETE",
        signal,
      });
    },

    async addHypothesisEvidence(hypothesisId, evidence, signal) {
      return request<Hypothesis>(`/api/hunting/hypotheses/${encodeURIComponent(hypothesisId)}/evidence`, {
        method: "POST",
        body: JSON.stringify(evidence),
        signal,
      });
    },

    async updateHypothesisStatus(id, status, conclusion, signal) {
      return request<Hypothesis>(`/api/hunting/hypotheses/${encodeURIComponent(id)}/status`, {
        method: "POST",
        body: JSON.stringify({ status, conclusion }),
        signal,
      });
    },
  };
}
