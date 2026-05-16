import type { Dispatch, SetStateAction } from "react";
import type { ToolRuntimeSnapshot } from "../core/types";
import type { TSharkStatus } from "../integrations/clients/toolRuntimeClient";
import { toTSharkStatus } from "./tsharkStatusState";
import { probeToolRuntimeSnapshot } from "./toolRuntimeProbeActions";
import {
  describeToolRuntimeProbeError,
  detectToolRuntimeProbeTransport,
  type ToolRuntimeProbeState,
  type ToolRuntimeProbeTransport,
} from "./toolRuntimeProbeState";

interface BackgroundProbeOptions {
  readonly setToolRuntimeCheckDegraded: Dispatch<SetStateAction<boolean>>;
  readonly setToolRuntimeProbeState: Dispatch<SetStateAction<ToolRuntimeProbeState>>;
  readonly setToolRuntimeProbeTransport: Dispatch<SetStateAction<ToolRuntimeProbeTransport>>;
  readonly setLastToolRuntimeProbeError: Dispatch<SetStateAction<string>>;
  readonly setToolRuntimeSnapshot: Dispatch<SetStateAction<ToolRuntimeSnapshot | null>>;
  readonly setTsharkStatus: Dispatch<SetStateAction<TSharkStatus>>;
}

export function startFullToolRuntimeProbe({
  setToolRuntimeCheckDegraded,
  setToolRuntimeProbeState,
  setToolRuntimeProbeTransport,
  setLastToolRuntimeProbeError,
  setToolRuntimeSnapshot,
  setTsharkStatus,
}: BackgroundProbeOptions) {
  setToolRuntimeProbeState("probing_full");
  void probeToolRuntimeSnapshot("full")
    .then((snapshot) => {
      setToolRuntimeCheckDegraded(false);
      setToolRuntimeProbeState("ready");
      setToolRuntimeProbeTransport(snapshot.transport ?? detectToolRuntimeProbeTransport());
      setLastToolRuntimeProbeError("");
      setToolRuntimeSnapshot(snapshot);
      setTsharkStatus(toTSharkStatus(snapshot.tshark));
    })
    .catch((error) => {
      setToolRuntimeCheckDegraded(true);
      setToolRuntimeProbeState("timeout_background");
      setLastToolRuntimeProbeError(describeToolRuntimeProbeError(error));
    });
}
