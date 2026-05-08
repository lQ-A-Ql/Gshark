export function pickAdjacentStreamTargets(streamIds: number[], currentStreamId: number, limit: number): number[] {
  if (!Number.isFinite(currentStreamId) || currentStreamId < 0 || limit <= 0) {
    return [];
  }

  const currentIndex = streamIds.findIndex((id) => id === currentStreamId);
  if (currentIndex < 0) {
    return [];
  }

  const targets: number[] = [];
  for (const candidate of [streamIds[currentIndex + 1], streamIds[currentIndex - 1]]) {
    if (!Number.isFinite(candidate) || candidate <= 0) {
      continue;
    }
    if (targets.includes(candidate)) {
      continue;
    }
    targets.push(candidate);
    if (targets.length >= limit) {
      break;
    }
  }
  return targets;
}

export function canSchedulePrefetch(options: {
  hasCached: boolean;
  inFlight: boolean;
  inFlightSize: number;
  maxInFlight?: number;
}): boolean {
  const maxInFlight = options.maxInFlight ?? 2;
  if (options.hasCached || options.inFlight) {
    return false;
  }
  return options.inFlightSize < maxInFlight;
}
