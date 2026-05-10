import type { ModbusDecodedInput, ModbusSuspiciousWrite, ModbusTransaction } from "../../core/types";
import { ModbusDecodedInputsPanel } from "./ModbusDecodedInputsPanel";
import { ModbusSuspiciousWritesPanel } from "./ModbusSuspiciousWritesPanel";
import { ModbusTransactionsPanel } from "./ModbusTransactionsPanel";

interface IndustrialModbusPanelsProps {
  suspiciousWrites: ModbusSuspiciousWrite[];
  decodedInputs: ModbusDecodedInput[];
  transactions: ModbusTransaction[];
  unitOptions: string[];
  functionOptions: string[];
  unitFilter: string;
  functionFilter: string;
  onUnitFilterChange: (value: string) => void;
  onFunctionFilterChange: (value: string) => void;
}

export function IndustrialModbusPanels({
  suspiciousWrites,
  decodedInputs,
  transactions,
  unitOptions,
  functionOptions,
  unitFilter,
  functionFilter,
  onUnitFilterChange,
  onFunctionFilterChange,
}: IndustrialModbusPanelsProps) {
  return (
    <>
      {suspiciousWrites.length > 0 && <ModbusSuspiciousWritesPanel suspiciousWrites={suspiciousWrites} />}
      {decodedInputs.length > 0 && <ModbusDecodedInputsPanel decodedInputs={decodedInputs} />}
      <ModbusTransactionsPanel
        transactions={transactions}
        unitOptions={unitOptions}
        functionOptions={functionOptions}
        unitFilter={unitFilter}
        functionFilter={functionFilter}
        onUnitFilterChange={onUnitFilterChange}
        onFunctionFilterChange={onFunctionFilterChange}
      />
    </>
  );
}
