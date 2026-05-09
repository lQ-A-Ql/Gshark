import { describe, expect, it } from "vitest";
import type { MediaSession, MediaTranscription, SpeechBatchTaskStatus } from "../../core/types";
import {
  canPlayArtifact,
  estimateTranscriptionProgress,
  progressToneClass,
  type TranscriptionProgressTone,
  transcriptionRecordOf,
  transcriptionStatusOf,
} from "./MediaSessionTableUtils";

const idleBatchStatus: SpeechBatchTaskStatus = {
  taskId: "",
  total: 0,
  queued: 0,
  running: 0,
  completed: 0,
  failed: 0,
  skipped: 0,
  done: false,
  cancelled: false,
  items: [],
};

function artifact(format: string) {
  return { token: format, name: format, format, sizeBytes: 1 };
}

function createSession(overrides: Partial<MediaSession> = {}): MediaSession {
  return {
    id: "session-1",
    mediaType: "audio",
    family: "rtp",
    application: "RTP",
    source: "10.0.0.1",
    sourcePort: 4000,
    destination: "10.0.0.2",
    destinationPort: 5000,
    transport: "udp",
    packetCount: 12,
    gapCount: 0,
    tags: [],
    notes: [],
    artifact: {
      token: "token-1",
      name: "media.raw",
      format: "opus",
      sizeBytes: 128,
    },
    ...overrides,
  };
}

function batchStatusWithItem(overrides: SpeechBatchTaskStatus["items"][number]): SpeechBatchTaskStatus {
  return { ...idleBatchStatus, items: [overrides] };
}

function createTranscription(overrides: Partial<MediaTranscription> = {}): MediaTranscription {
  return {
    token: "token-1",
    sessionId: "session-1",
    title: "audio",
    text: "hello",
    language: "zh",
    engine: "vosk",
    status: "completed",
    cached: true,
    durationSeconds: 1,
    segments: [],
    ...overrides,
  };
}

function batchItem(status: SpeechBatchTaskStatus["items"][number]["status"], overrides = {}) {
  return {
    token: "token-1",
    sessionId: "session-1",
    mediaLabel: "audio",
    title: "audio",
    status,
    cached: false,
    ...overrides,
  };
}

describe("MediaSessionTableUtils", () => {
  it("detects playable video and audio artifacts", () => {
    for (const format of ["h264", "264", "h265", "265", "hevc"]) {
      expect(canPlayArtifact(createSession({ mediaType: "video", artifact: artifact(format) }))).toBe(true);
    }

    for (const format of ["ulaw", "alaw", "g722", "l16", "aac", "opus", "mpa", "mp3"]) {
      expect(canPlayArtifact(createSession({ mediaType: "audio", artifact: artifact(format) }))).toBe(true);
    }
  });

  it("rejects missing and unsupported playback artifacts", () => {
    expect(canPlayArtifact(createSession({ artifact: undefined }))).toBe(false);
    expect(canPlayArtifact(createSession({ mediaType: "video", artifact: artifact("avi") }))).toBe(false);
    expect(canPlayArtifact(createSession({ mediaType: "audio", artifact: artifact("flac") }))).toBe(false);
  });

  it("uses batch transcription status before cached transcriptions", () => {
    const status = transcriptionStatusOf(createSession(), batchStatusWithItem(batchItem("running")), {
      "token-1": createTranscription(),
    });

    expect(status).toMatchObject({ status: "running", label: "转写中" });
  });

  it("returns cached and batch transcription records", () => {
    expect(
      transcriptionRecordOf(createSession(), idleBatchStatus, {
        "token-1": createTranscription({ text: "cached text" }),
      }),
    ).toMatchObject({
      text: "cached text",
      status: "completed",
      cached: true,
    });

    expect(
      transcriptionRecordOf(createSession(), batchStatusWithItem(batchItem("failed", { error: "missing model" })), {}),
    ).toMatchObject({ error: "missing model", status: "failed", cached: false });
  });

  it("maps progress windows and tone classes", () => {
    expect([0, 1200, 5000, 12000].map((ms) => estimateTranscriptionProgress(ms))).toEqual([
      { percent: 14, label: "正在准备音频", tone: "rose" },
      { percent: 38, label: "正在转码为识别输入", tone: "amber" },
      { percent: 76, label: "正在进行离线转写", tone: "blue" },
      { percent: 92, label: "正在整理转写结果", tone: "emerald" },
    ]);
    const tones: TranscriptionProgressTone[] = ["rose", "amber", "blue", "emerald"];
    expect(tones.map((tone) => progressToneClass(tone))).toEqual([
      "bg-rose-500",
      "bg-amber-500",
      "bg-blue-500",
      "bg-emerald-500",
    ]);
  });
});
