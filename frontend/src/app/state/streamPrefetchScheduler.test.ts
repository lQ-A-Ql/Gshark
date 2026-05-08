import { describe, expect, it, vi } from "vitest";
import type { BinaryStream } from "../core/types";
import { scheduleStreamPrefetch } from "./streamPrefetchScheduler";

function createBinaryStream(id: number): BinaryStream {
  return {
    id,
    protocol: "TCP",
    from: "127.0.0.1:40001",
    to: "127.0.0.1:17891",
    chunks: [],
    nextCursor: 0,
    totalChunks: 0,
    hasMore: false,
    loadMeta: { source: "network" },
  };
}

function createTask(options?: { current?: boolean }) {
  return {
    signal: new AbortController().signal,
    isCurrent: () => options?.current ?? true,
    finish: vi.fn(),
  };
}

async function flushMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

describe("streamPrefetchScheduler", () => {
  it("skips scheduling when stream already cached", () => {
    const cache = new Map<number, BinaryStream>([[7, createBinaryStream(7)]]);
    const inFlight = new Set<number>();
    const beginTask = vi.fn(() => createTask());
    const fetchStream = vi.fn(async () => createBinaryStream(7));

    const scheduled = scheduleStreamPrefetch({
      targetId: 7,
      taskKey: "prefetch-tcp-7",
      cache,
      inFlight,
      beginTask,
      fetchStream,
    });

    expect(scheduled).toBe(false);
    expect(beginTask).not.toHaveBeenCalled();
    expect(fetchStream).not.toHaveBeenCalled();
  });

  it("stores prefetch stream and clears in-flight when task is current", async () => {
    const cache = new Map<number, BinaryStream>();
    const inFlight = new Set<number>();
    const task = createTask({ current: true });
    const beginTask = vi.fn(() => task);
    const stream = createBinaryStream(13);
    const fetchStream = vi.fn(async () => stream);

    const scheduled = scheduleStreamPrefetch({
      targetId: 13,
      taskKey: "prefetch-tcp-13",
      cache,
      inFlight,
      beginTask,
      fetchStream,
    });

    expect(scheduled).toBe(true);
    expect(inFlight.has(13)).toBe(true);

    await flushMicrotasks();

    expect(fetchStream).toHaveBeenCalledWith(13, task.signal);
    expect(cache.get(13)).toBe(stream);
    expect(task.finish).toHaveBeenCalledTimes(1);
    expect(inFlight.has(13)).toBe(false);
  });

  it("does not cache stream when task is stale but still cleans up", async () => {
    const cache = new Map<number, BinaryStream>();
    const inFlight = new Set<number>();
    const task = createTask({ current: false });
    const beginTask = vi.fn(() => task);
    const stream = createBinaryStream(21);
    const fetchStream = vi.fn(async () => stream);

    const scheduled = scheduleStreamPrefetch({
      targetId: 21,
      taskKey: "prefetch-udp-21",
      cache,
      inFlight,
      beginTask,
      fetchStream,
    });

    expect(scheduled).toBe(true);

    await flushMicrotasks();

    expect(cache.size).toBe(0);
    expect(task.finish).toHaveBeenCalledTimes(1);
    expect(inFlight.has(21)).toBe(false);
  });
});
