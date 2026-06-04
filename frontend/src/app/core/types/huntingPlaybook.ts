// ---------------------------------------------------------------------------
// Hunting Playbook types
// ---------------------------------------------------------------------------

export type PlaybookStepType =
  | "threat_hunt"
  | "filter_query"
  | "yara_scan"
  | "c2_analysis"
  | "apt_analysis"
  | "custom";

export type PlaybookStatus = "draft" | "ready" | "running" | "complete" | "failed";

export interface PlaybookStepCondition {
  field: string;
  operator: "gt" | "gte" | "lt" | "lte" | "eq" | "neq";
  value: string;
}

export interface PlaybookStep {
  id: string;
  name: string;
  description?: string;
  type: PlaybookStepType;
  config?: Record<string, unknown>;
  conditions?: PlaybookStepCondition[];
  enabled: boolean;
}

export interface HuntingPlaybook {
  id: string;
  name: string;
  description?: string;
  author?: string;
  tags?: string[];
  steps: PlaybookStep[];
  status: PlaybookStatus;
  createdAt: string;
  updatedAt: string;
}

export interface PlaybookStepResult {
  stepId: string;
  stepName: string;
  status: "pass" | "fail" | "skip" | "error";
  hitsCount: number;
  hits?: ThreatHit[];
  error?: string;
  durationMs: number;
  conditionOk: boolean;
}

export interface PlaybookRunResult {
  playbookId: string;
  playbookName: string;
  status: PlaybookStatus;
  stepResults: PlaybookStepResult[];
  totalHits: number;
  durationMs: number;
  startedAt: string;
  completedAt: string;
}

// ---------------------------------------------------------------------------
// Saved Search types
// ---------------------------------------------------------------------------

export interface SavedSearch {
  id: string;
  name: string;
  description?: string;
  query: string;
  filters?: string[];
  tags?: string[];
  hitCount?: number;
  createdAt: string;
  updatedAt: string;
}

// ---------------------------------------------------------------------------
// Hypothesis types
// ---------------------------------------------------------------------------

export type HypothesisStatus =
  | "open"
  | "investigating"
  | "confirmed"
  | "refuted"
  | "inconclusive";

export interface HypothesisEvidence {
  id: string;
  description: string;
  source: string;
  refId?: string;
  strength: "supports" | "contradicts" | "neutral";
  createdAt: string;
}

export interface Hypothesis {
  id: string;
  title: string;
  description?: string;
  status: HypothesisStatus;
  playbookId?: string;
  evidence?: HypothesisEvidence[];
  conclusion?: string;
  tags?: string[];
  createdAt: string;
  updatedAt: string;
}

// Re-export ThreatHit for convenience.
export interface ThreatHit {
  id: number;
  packetId: number;
  category: string;
  rule: string;
  level: string;
  preview: string;
  match: string;
}
