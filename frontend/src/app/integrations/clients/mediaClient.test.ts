import { describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  downloadBlob: vi.fn(),
}));

vi.mock("../../utils/browserFile", () => ({
  downloadBlob: mocks.downloadBlob,
}));

import { createMediaClient } from "./mediaClient";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;
type BlobRequest = (path: string, init?: RequestInit) => Promise<Blob>;

describe("mediaClient", () => {
  it("maps media analysis payloads and passes refresh signal", async () => {
    const signal = new AbortController().signal;
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      expect(path).toBe("/api/analysis/media?refresh=1");
      expect(init?.signal).toBe(signal);
      return {
        total_media_packets: 2,
        protocols: [{ label: "RTP", count: 2 }],
        applications: [],
        sessions: [{ id: "rtp-1", media_type: "audio", packet_count: 2 }],
        notes: ["ok"],
      };
    }) as unknown as JsonRequest;
    const requestBlob = vi.fn() as unknown as BlobRequest;

    const result = await createMediaClient(request, requestBlob).getMediaAnalysis(true, signal);

    expect(result).toMatchObject({
      totalMediaPackets: 2,
      protocols: [{ label: "RTP", count: 2 }],
      sessions: [{ id: "rtp-1", mediaType: "audio", packetCount: 2 }],
      notes: ["ok"],
    });
  });

  it("posts transcription requests and maps batch lifecycle status", async () => {
    const request = vi.fn(async (path: string, init?: RequestInit) => {
      if (path === "/api/analysis/media/transcribe") {
        expect(init?.method).toBe("POST");
        expect(JSON.parse(String(init?.body))).toEqual({ token: "tok", force: true });
        return { token: "tok", session_id: "s1", text: "hello", status: "completed" };
      }
      if (path === "/api/analysis/media/transcribe/batch") {
        if (init?.method === "POST") {
          expect(JSON.parse(String(init.body))).toEqual({ force: false });
          return { task_id: "task-1", queued: 1, done: false };
        }
        return { task_id: "task-1", completed: 1, done: true };
      }
      if (path === "/api/analysis/media/transcribe/batch/cancel") {
        expect(init?.method).toBe("POST");
        return { task_id: "task-1", cancelled: true, done: true };
      }
      throw new Error(`unexpected path ${path}`);
    }) as unknown as JsonRequest;
    const requestBlob = vi.fn() as unknown as BlobRequest;
    const client = createMediaClient(request, requestBlob);

    await expect(client.transcribeMediaArtifact("tok", true)).resolves.toMatchObject({
      token: "tok",
      sessionId: "s1",
      text: "hello",
      status: "completed",
    });
    await expect(client.startMediaBatchTranscription(false)).resolves.toMatchObject({
      taskId: "task-1",
      queued: 1,
      done: false,
    });
    await expect(client.getMediaBatchTranscriptionStatus()).resolves.toMatchObject({
      taskId: "task-1",
      completed: 1,
      done: true,
    });
    await expect(client.cancelMediaBatchTranscription()).resolves.toMatchObject({
      taskId: "task-1",
      cancelled: true,
      done: true,
    });
  });

  it("downloads media blobs with stable filenames and URLs", async () => {
    const request = vi.fn() as unknown as JsonRequest;
    const blob = new Blob(["media"]);
    const requestBlob = vi.fn(async (path: string) => {
      if (path.includes("/media/export?")) {
        expect(path).toBe("/api/analysis/media/export?token=tok%2F1");
      }
      return blob;
    }) as unknown as BlobRequest;
    const client = createMediaClient(request, requestBlob);

    await client.downloadMediaArtifact("tok/1", "call.wav");
    await client.exportMediaBatchTranscription("json");
    await expect(client.getMediaPlaybackBlob("tok/1")).resolves.toBe(blob);

    expect(requestBlob).toHaveBeenCalledWith("/api/analysis/media/export?token=tok%2F1");
    expect(requestBlob).toHaveBeenCalledWith("/api/analysis/media/transcribe/batch/export?format=json");
    expect(requestBlob).toHaveBeenCalledWith("/api/analysis/media/play?token=tok%2F1");
    expect(mocks.downloadBlob).toHaveBeenCalledWith("call.wav", blob);
    expect(mocks.downloadBlob).toHaveBeenCalledWith("media-transcription.json", blob);
  });
});
