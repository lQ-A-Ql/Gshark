import { useState, type Dispatch, type SetStateAction } from "react";

export interface UseDisplayFilterStateResult {
  readonly displayFilter: string;
  readonly setDisplayFilter: Dispatch<SetStateAction<string>>;
}

/**
 * Owns the user-supplied display filter string slice.
 *
 * This is a thin wrapper around a single `useState`, but it formalizes
 * ownership so no other hook mutates the display filter behind this slice's
 * back.
 */
export function useDisplayFilterState(): UseDisplayFilterStateResult {
  const [displayFilter, setDisplayFilter] = useState("");

  return {
    displayFilter,
    setDisplayFilter,
  };
}
