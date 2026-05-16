import type { ToolRuntimeSnapshot } from "../core/types";

export function isTSharkSnapshotDegraded(snapshot?: ToolRuntimeSnapshot | null) {
  return Boolean(
    snapshot?.tshark.available &&
      (snapshot.tshark.capabilityCheckDegraded || (snapshot.tshark.missingOptionalFields?.length ?? 0) > 0),
  );
}
