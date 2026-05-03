import { describe, expect, it } from "vitest";
import { createCaptureTaskScope } from "./captureTaskScope";

describe("createCaptureTaskScope", () => {
  it("aborts an older task with the same key", () => {
    const scope = createCaptureTaskScope();
    const first = scope.beginTask("packet-page");
    const second = scope.beginTask("packet-page");

    expect(first.signal.aborted).toBe(true);
    expect(first.isCurrent()).toBe(false);
    expect(second.signal.aborted).toBe(false);
    expect(second.isCurrent()).toBe(true);
  });

  it("invalidates and aborts all in-flight tasks when the capture scope changes", () => {
    const scope = createCaptureTaskScope();
    const packet = scope.beginTask("packet-page");
    const threat = scope.beginTask("threat-analysis");
    const oldScopeId = scope.currentScopeId();

    const nextScopeId = scope.invalidate();

    expect(nextScopeId).toBe(oldScopeId + 1);
    expect(packet.signal.aborted).toBe(true);
    expect(threat.signal.aborted).toBe(true);
    expect(packet.isCurrent()).toBe(false);
    expect(threat.isCurrent()).toBe(false);
  });

  it("allows parallel tasks with different keys until scope invalidation", () => {
    const scope = createCaptureTaskScope();
    const packet = scope.beginTask("packet-page");
    const stream = scope.beginTask("tcp-stream");

    expect(packet.isCurrent()).toBe(true);
    expect(stream.isCurrent()).toBe(true);

    packet.finish();

    expect(packet.isCurrent()).toBe(false);
    expect(stream.isCurrent()).toBe(true);
  });
});
