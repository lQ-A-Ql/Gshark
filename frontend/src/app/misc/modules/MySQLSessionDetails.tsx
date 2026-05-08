import type { MySQLSession } from "../../core/types";
import { MySQLQueryTraceTable } from "./MySQLQueryTraceTable";
import { MySQLServerEventPanel } from "./MySQLServerEventPanel";
import { MySQLSessionOverviewPanel } from "./MySQLSessionOverviewPanel";

interface MySQLSessionDetailsProps {
  session: MySQLSession | null;
}

export function MySQLSessionDetails({ session }: MySQLSessionDetailsProps) {
  return (
    <div className="space-y-4">
      <MySQLSessionOverviewPanel session={session} />
      <MySQLQueryTraceTable session={session} />
      <MySQLServerEventPanel session={session} />
    </div>
  );
}
