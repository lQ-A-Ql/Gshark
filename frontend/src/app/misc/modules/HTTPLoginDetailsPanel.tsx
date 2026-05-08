import type { HTTPLoginAnalysis, HTTPLoginEndpoint } from "../../core/types";
import { HTTPLoginAttemptTable } from "./HTTPLoginAttemptTable";
import { HTTPLoginEndpointDetailsPanel } from "./HTTPLoginEndpointDetailsPanel";
import { HTTPLoginBruteforceAlert, HTTPLoginSuccessHint } from "./HTTPLoginStatusAlerts";

type HTTPLoginAttempt = HTTPLoginAnalysis["attempts"][number];

interface HTTPLoginDetailsPanelProps {
  selectedEndpoint: HTTPLoginEndpoint | null;
  attempts: HTTPLoginAttempt[];
  bruteforceCount: number;
  successCount: number;
}

export function HTTPLoginDetailsPanel({
  selectedEndpoint,
  attempts,
  bruteforceCount,
  successCount,
}: HTTPLoginDetailsPanelProps) {
  return (
    <div className="space-y-4">
      <HTTPLoginEndpointDetailsPanel selectedEndpoint={selectedEndpoint} />
      <HTTPLoginAttemptTable attempts={attempts} />
      {bruteforceCount > 0 && <HTTPLoginBruteforceAlert bruteforceCount={bruteforceCount} />}
      {successCount > 0 && <HTTPLoginSuccessHint />}
    </div>
  );
}
