import type { ToolRuntimeSnapshot } from "../core/types";

export function withToolRuntimeSnapshotMeta(
  snapshot: ToolRuntimeSnapshot,
  transport: NonNullable<ToolRuntimeSnapshot["transport"]>,
  transportError = "",
): ToolRuntimeSnapshot {
  Object.defineProperties(snapshot, {
    transport: { configurable: true, enumerable: false, value: transport },
    transportError: { configurable: true, enumerable: false, value: transportError },
  });
  return snapshot;
}
