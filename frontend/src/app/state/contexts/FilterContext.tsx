import { createContext, useContext, type PropsWithChildren } from "react";

export interface FilterContextValue {
  displayFilter: string;
  setDisplayFilter: (value: string) => void;
  applyFilter: (value?: string) => void;
  clearFilter: () => void;
}

const FilterContext = createContext<FilterContextValue | null>(null);

export function FilterProvider({ children, value }: PropsWithChildren<{ value: FilterContextValue }>) {
  return <FilterContext.Provider value={value}>{children}</FilterContext.Provider>;
}

export function useFilter() {
  const ctx = useContext(FilterContext);
  if (!ctx) {
    throw new Error("useFilter must be used inside FilterProvider");
  }
  return ctx;
}
