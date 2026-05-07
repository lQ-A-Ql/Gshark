import { describe, expect, it } from "vitest";
import { asSpeechBatchTaskStatus, asToolRuntimeSnapshot } from "./runtimeMapper";

describe("runtimeMapper", () => {
  it("maps speech batch task status", () => {
    const result = asSpeechBatchTaskStatus({
      task_id: "task-1",
      total: 2,
      queued: 1,
      items: [{ token: "a", session_id: "s1", media_label: "m1", title: "T1", status: "done", cached: true }],
    });

    expect(result).toMatchObject({
      taskId: "task-1",
      total: 2,
      queued: 1,
      items: [{ token: "a", sessionId: "s1", status: "done", cached: true }],
    });
  });

  it("maps runtime snapshot", () => {
    const result = asToolRuntimeSnapshot({
      config: { tshark_path: "tshark.exe", yara_timeout_ms: 123 },
      tshark: { available: true, path: "t", custom_path: "c" },
      speech: { available: true, engine: "vosk", python_available: true },
      yara: { available: false, enabled: true, timeout_ms: 456 },
    });

    expect(result).toMatchObject({
      config: { tsharkPath: "tshark.exe", yaraTimeoutMs: 123 },
      tshark: { available: true, path: "t", customPath: "c" },
      speech: { available: true, engine: "vosk", pythonAvailable: true },
      yara: { enabled: true, timeoutMs: 456 },
    });
  });
});
