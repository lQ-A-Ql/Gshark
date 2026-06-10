export interface DesktopPlaybookBinding {
  ListPlaybooks?: () => Promise<unknown>;
  GetPlaybook?: (id: string) => Promise<unknown>;
  CreatePlaybook?: (payload: unknown) => Promise<unknown>;
  UpdatePlaybook?: (id: string, payload: unknown) => Promise<unknown>;
  DeletePlaybook?: (id: string) => Promise<unknown>;
  RunPlaybook?: (id: string) => Promise<unknown>;
  GetPlaybookLastRun?: (id: string) => Promise<unknown>;
  ListSavedSearches?: () => Promise<unknown>;
  GetSavedSearch?: (id: string) => Promise<unknown>;
  CreateSavedSearch?: (payload: unknown) => Promise<unknown>;
  UpdateSavedSearch?: (id: string, payload: unknown) => Promise<unknown>;
  DeleteSavedSearch?: (id: string) => Promise<unknown>;
  ExecuteSavedSearch?: (id: string) => Promise<unknown>;
  ListHypotheses?: (status: string) => Promise<unknown>;
  GetHypothesis?: (id: string) => Promise<unknown>;
  CreateHypothesis?: (payload: unknown) => Promise<unknown>;
  UpdateHypothesis?: (id: string, payload: unknown) => Promise<unknown>;
  DeleteHypothesis?: (id: string) => Promise<unknown>;
  AddHypothesisEvidence?: (id: string, payload: unknown) => Promise<unknown>;
  UpdateHypothesisStatus?: (id: string, status: string, conclusion: string) => Promise<unknown>;
}
