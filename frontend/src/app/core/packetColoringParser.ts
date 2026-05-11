import type { Packet } from "./types";
import { parseRGB16Triplet, type RGB16 } from "./packetColoringColors";
import { buildPacketColorMatcher } from "./packetColoringMatchers";

export interface ParsedColorRule {
  name: string;
  expr: string;
  bg: RGB16;
  fg: RGB16;
  match: (packet: Packet, text: string) => boolean;
}

function parseRuleLine(line: string): ParsedColorRule | null {
  const trimmed = line.trim();
  if (!trimmed || !trimmed.startsWith("@")) return null;

  const match = /^@([^@]+)@([^@]+)@\[([^\]]+)\]\[([^\]]+)\]$/.exec(trimmed);
  if (!match) return null;

  const name = match[1].trim();
  const expr = match[2].trim();
  return {
    name,
    expr,
    bg: parseRGB16Triplet(match[3]),
    fg: parseRGB16Triplet(match[4]),
    match: buildPacketColorMatcher(name, expr),
  };
}

export function parsePacketColorRules(text: string): ParsedColorRule[] {
  return text
    .split(/\r?\n/)
    .map((line) => parseRuleLine(line))
    .filter((rule): rule is ParsedColorRule => rule != null);
}
