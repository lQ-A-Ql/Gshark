import type { StreamProtocol } from "../core/types";

export type StreamSwitchSequences = Record<StreamProtocol, number>;

export function createStreamSwitchSequences(): StreamSwitchSequences {
  return {
    HTTP: 0,
    TCP: 0,
    UDP: 0,
  };
}

export function bumpStreamSwitchSequence(sequences: StreamSwitchSequences, protocol: StreamProtocol): number {
  sequences[protocol] += 1;
  return sequences[protocol];
}

export function bumpAllStreamSwitchSequences(sequences: StreamSwitchSequences): void {
  sequences.HTTP += 1;
  sequences.TCP += 1;
  sequences.UDP += 1;
}

export function resetStreamSwitchSequences(sequences: StreamSwitchSequences): void {
  sequences.HTTP = 0;
  sequences.TCP = 0;
  sequences.UDP = 0;
}

export function isLatestStreamSwitchSequence(
  sequences: StreamSwitchSequences,
  protocol: StreamProtocol,
  requestSequence: number,
  isTaskCurrent: () => boolean,
): boolean {
  if (!isTaskCurrent()) {
    return false;
  }
  return sequences[protocol] === requestSequence;
}
