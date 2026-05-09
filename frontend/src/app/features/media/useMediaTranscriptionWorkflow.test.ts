import { describe, expect, it } from "vitest";
import type { MediaTranscription, SpeechBatchTaskStatus, SpeechToTextStatus } from "../../core/types";
import { isMediaDependencyError, mergeBatchTranscriptions } from "./useMediaTranscriptionWorkflow";

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

const speechStatus: SpeechToTextStatus = {
  available: true,
  engine: "whisper",
  language: "zh-CN",
  pythonAvailable: true,
  ffmpegAvailable: true,
  voskAvailable: false,
  modelAvailable: true,
  message: "",
};

function transcription(overrides: Partial<MediaTranscription> = {}): MediaTranscription {
  return {
    token: "token-1",
    sessionId: "session-1",
    title: "audio",
    text: "old text",
    language: "en",
    engine: "vosk",
    status: "completed",
    cached: true,
    durationSeconds: 42,
    segments: [{ startSeconds: 1, endSeconds: 2, text: "old text" }],
    ...overrides,
  };
}

describe("useMediaTranscriptionWorkflow helpers", () => {
  it("merges batch transcription text while preserving existing timing details", () => {
    const result = mergeBatchTranscriptions(
      { "token-1": transcription() },
      {
        ...idleBatchStatus,
        items: [
          {
            token: "token-1",
            sessionId: "session-1",
            mediaLabel: "audio",
            title: "batch audio",
            status: "completed",
            cached: false,
            text: "fresh text",
          },
        ],
      },
      speechStatus,
    );

    expect(result["token-1"]).toMatchObject({
      title: "batch audio",
      text: "fresh text",
      language: "zh-CN",
      engine: "whisper",
      status: "completed",
      cached: false,
      durationSeconds: 42,
      segments: [{ startSeconds: 1, endSeconds: 2, text: "old text" }],
    });
  });

  it("ignores empty batch transcription text", () => {
    const prev = { "token-1": transcription({ text: "keep me" }) };
    const result = mergeBatchTranscriptions(
      prev,
      {
        ...idleBatchStatus,
        items: [
          {
            token: "token-1",
            sessionId: "session-1",
            mediaLabel: "audio",
            title: "empty",
            status: "completed",
            cached: false,
            text: "   ",
          },
        ],
      },
      null,
    );

    expect(result).toEqual(prev);
  });

  it("classifies media dependency errors for dependency dialogs", () => {
    expect(isMediaDependencyError("ffmpeg not found")).toBe(true);
    expect(isMediaDependencyError("Python runtime missing")).toBe(true);
    expect(isMediaDependencyError("Vosk 模型缺失")).toBe(true);
    expect(isMediaDependencyError("network request failed")).toBe(false);
  });
});
