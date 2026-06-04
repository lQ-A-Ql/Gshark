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
  listPlaybooks(): Promise<HuntingPlaybook[]>;
  getPlaybook(id: string): Promise<HuntingPlaybook>;
  createPlaybook(playbook: Partial<HuntingPlaybook>): Promise<HuntingPlaybook>;
  updatePlaybook(id: string, playbook: Partial<HuntingPlaybook>): Promise<HuntingPlaybook>;
  deletePlaybook(id: string): Promise<void>;
  runPlaybook(id: string): Promise<PlaybookRunResult>;
  getPlaybookLastRun(id: string): Promise<PlaybookRunResult>;

  // Saved search CRUD
  listSavedSearches(): Promise<SavedSearch[]>;
  getSavedSearch(id: string): Promise<SavedSearch>;
  createSavedSearch(search: Partial<SavedSearch>): Promise<SavedSearch>;
  updateSavedSearch(id: string, search: Partial<SavedSearch>): Promise<SavedSearch>;
  deleteSavedSearch(id: string): Promise<void>;
  executeSavedSearch(id: string): Promise<{ search: SavedSearch; hits: ThreatHit[]; total: number }>;

  // Hypothesis CRUD
  listHypotheses(status?: HypothesisStatus): Promise<Hypothesis[]>;
  getHypothesis(id: string): Promise<Hypothesis>;
  createHypothesis(hypothesis: Partial<Hypothesis>): Promise<Hypothesis>;
  updateHypothesis(id: string, hypothesis: Partial<Hypothesis>): Promise<Hypothesis>;
  deleteHypothesis(id: string): Promise<void>;
  addHypothesisEvidence(hypothesisId: string, evidence: Partial<HypothesisEvidence>): Promise<Hypothesis>;
  updateHypothesisStatus(id: string, status: HypothesisStatus, conclusion?: string): Promise<Hypothesis>;
}

export function createPlaybookClient(request: JsonRequest): PlaybookClient {
  return {
    // Playbook CRUD
    async listPlaybooks() {
      return request<HuntingPlaybook[]>("/api/playbooks");
    },

    async getPlaybook(id) {
      return request<HuntingPlaybook>(`/api/playbooks/${encodeURIComponent(id)}`);
    },

    async createPlaybook(playbook) {
      return request<HuntingPlaybook>("/api/playbooks", {
        method: "POST",
        body: JSON.stringify(playbook),
      });
    },

    async updatePlaybook(id, playbook) {
      return request<HuntingPlaybook>(`/api/playbooks/${encodeURIComponent(id)}`, {
        method: "PUT",
        body: JSON.stringify(playbook),
      });
    },

    async deletePlaybook(id) {
      await request<void>(`/api/playbooks/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
    },

    async runPlaybook(id) {
      return request<PlaybookRunResult>(`/api/playbooks/${encodeURIComponent(id)}/run`, {
        method: "POST",
      });
    },

    async getPlaybookLastRun(id) {
      return request<PlaybookRunResult>(`/api/playbooks/${encodeURIComponent(id)}/last-run`);
    },

    // Saved search CRUD
    async listSavedSearches() {
      return request<SavedSearch[]>("/api/hunting/saved-searches");
    },

    async getSavedSearch(id) {
      return request<SavedSearch>(`/api/hunting/saved-searches/${encodeURIComponent(id)}`);
    },

    async createSavedSearch(search) {
      return request<SavedSearch>("/api/hunting/saved-searches", {
        method: "POST",
        body: JSON.stringify(search),
      });
    },

    async updateSavedSearch(id, search) {
      return request<SavedSearch>(`/api/hunting/saved-searches/${encodeURIComponent(id)}`, {
        method: "PUT",
        body: JSON.stringify(search),
      });
    },

    async deleteSavedSearch(id) {
      await request<void>(`/api/hunting/saved-searches/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
    },

    async executeSavedSearch(id) {
      return request<{ search: SavedSearch; hits: ThreatHit[]; total: number }>(
        `/api/hunting/saved-searches/${encodeURIComponent(id)}/execute`,
        { method: "POST" },
      );
    },

    // Hypothesis CRUD
    async listHypotheses(status) {
      const query = status ? `?status=${encodeURIComponent(status)}` : "";
      return request<Hypothesis[]>(`/api/hunting/hypotheses${query}`);
    },

    async getHypothesis(id) {
      return request<Hypothesis>(`/api/hunting/hypotheses/${encodeURIComponent(id)}`);
    },

    async createHypothesis(hypothesis) {
      return request<Hypothesis>("/api/hunting/hypotheses", {
        method: "POST",
        body: JSON.stringify(hypothesis),
      });
    },

    async updateHypothesis(id, hypothesis) {
      return request<Hypothesis>(`/api/hunting/hypotheses/${encodeURIComponent(id)}`, {
        method: "PUT",
        body: JSON.stringify(hypothesis),
      });
    },

    async deleteHypothesis(id) {
      await request<void>(`/api/hunting/hypotheses/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
    },

    async addHypothesisEvidence(hypothesisId, evidence) {
      return request<Hypothesis>(
        `/api/hunting/hypotheses/${encodeURIComponent(hypothesisId)}/evidence`,
        {
          method: "POST",
          body: JSON.stringify(evidence),
        },
      );
    },

    async updateHypothesisStatus(id, status, conclusion) {
      return request<Hypothesis>(
        `/api/hunting/hypotheses/${encodeURIComponent(id)}/status`,
        {
          method: "POST",
          body: JSON.stringify({ status, conclusion }),
        },
      );
    },
  };
}
