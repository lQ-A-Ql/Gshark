import type { StreamDecoderKind } from "../core/types";
import { asKnownDecoder } from "./StreamDecoderWorkbenchUtils";

export function runSuggestedDecoder(value: unknown, onRunDecoder: (decoder: StreamDecoderKind) => void) {
  const decoder = asKnownDecoder(value);
  if (decoder) {
    onRunDecoder(decoder);
  }
}
