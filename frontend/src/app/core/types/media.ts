import type { TrafficBucket } from "./traffic";

export interface MediaArtifact {
  token: string;
  name: string;
  codec?: string;
  format?: string;
  sizeBytes: number;
}

export interface MediaSession {
  id: string;
  mediaType: string;
  family: string;
  application: string;
  source: string;
  sourcePort: number;
  destination: string;
  destinationPort: number;
  transport: string;
  ssrc?: string;
  payloadType?: string;
  codec?: string;
  clockRate?: number;
  startTime?: string;
  endTime?: string;
  packetCount: number;
  gapCount: number;
  controlSummary?: string;
  tags: string[];
  notes: string[];
  artifact?: MediaArtifact;
}

export interface MediaAnalysis {
  totalMediaPackets: number;
  protocols: TrafficBucket[];
  applications: TrafficBucket[];
  sessions: MediaSession[];
  notes: string[];
}

export interface SpeechToTextStatus {
  available: boolean;
  engine: string;
  language: string;
  pythonAvailable: boolean;
  pythonCommand?: string;
  ffmpegAvailable: boolean;
  voskAvailable: boolean;
  modelAvailable: boolean;
  modelPath?: string;
  message: string;
}

export interface MediaTranscriptionSegment {
  startSeconds: number;
  endSeconds: number;
  text: string;
}

export interface MediaTranscription {
  token: string;
  sessionId: string;
  title: string;
  text: string;
  language: string;
  engine: string;
  status: string;
  error?: string;
  cached: boolean;
  durationSeconds: number;
  segments: MediaTranscriptionSegment[];
}

export interface SpeechBatchTaskItem {
  token: string;
  sessionId: string;
  mediaLabel: string;
  title: string;
  status: "queued" | "running" | "completed" | "failed" | "skipped";
  error?: string;
  cached: boolean;
  text?: string;
}

export interface SpeechBatchTaskStatus {
  taskId: string;
  total: number;
  queued: number;
  running: number;
  completed: number;
  failed: number;
  skipped: number;
  currentToken?: string;
  currentLabel?: string;
  done: boolean;
  cancelled: boolean;
  items: SpeechBatchTaskItem[];
}
