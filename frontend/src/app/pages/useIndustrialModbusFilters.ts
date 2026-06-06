import { useMemo, useState } from "react";
import type { IndustrialAnalysis } from "../core/types";

export function useIndustrialModbusFilters(analysis: IndustrialAnalysis) {
  const [modbusUnitFilter, setModbusUnitFilter] = useState("all");
  const [modbusFunctionFilter, setModbusFunctionFilter] = useState("all");
  const modbusUnitOptions = useMemo(() => {
    const units = new Set(analysis.modbus.transactions.map((t) => String(t.unitId)));
    return ["all", ...Array.from(units).sort()];
  }, [analysis.modbus.transactions]);
  const modbusFunctionOptions = useMemo(() => {
    const fns = new Set(analysis.modbus.transactions.map((t) => String(t.functionCode)));
    return ["all", ...Array.from(fns).sort()];
  }, [analysis.modbus.transactions]);
  const filteredModbusTransactions = useMemo(
    () =>
      analysis.modbus.transactions.filter((t) => {
        if (modbusUnitFilter !== "all" && String(t.unitId) !== modbusUnitFilter) return false;
        if (modbusFunctionFilter !== "all" && String(t.functionCode) !== modbusFunctionFilter) return false;
        return true;
      }),
    [analysis.modbus.transactions, modbusFunctionFilter, modbusUnitFilter],
  );
  return {
    filteredModbusTransactions,
    modbusFunctionFilter,
    modbusFunctionOptions,
    modbusUnitFilter,
    modbusUnitOptions,
    setModbusFunctionFilter,
    setModbusUnitFilter,
  };
}
