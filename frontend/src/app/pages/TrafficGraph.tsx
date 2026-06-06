import { TrafficGraphLayout } from "./TrafficGraphLayout";
import { useTrafficGraphPageState } from "./useTrafficGraphPageState";

export default function TrafficGraph() {
  return <TrafficGraphLayout {...useTrafficGraphPageState()} />;
}
