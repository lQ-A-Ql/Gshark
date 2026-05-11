import type { Packet } from "./types";
import { rgb16ToCss, rgb16ToRgba } from "./packetColoringColors";
import { parsePacketColorRules } from "./packetColoringParser";
import { WIRESHARK_COLORING_TEXT } from "./packetColoringRules";

export interface PacketColorStyle {
  ruleName: string;
  backgroundColor: string;
  backgroundGradient: string;
  color: string;
}

const RULES = parsePacketColorRules(WIRESHARK_COLORING_TEXT);

export function getPacketColorStyle(packet: Packet): PacketColorStyle | null {
  const text = `${packet.info ?? ""} ${packet.payload ?? ""}`.toLowerCase();
  const matched = RULES.find((rule) => rule.match(packet, text));
  if (!matched) return null;

  const strong = rgb16ToRgba(matched.bg, 0.85);
  const mid = rgb16ToRgba(matched.bg, 0.45);
  const clear = rgb16ToRgba(matched.bg, 0.05);
  const fontColor = "rgb(0, 0, 0)";

  return {
    ruleName: matched.name,
    backgroundColor: rgb16ToCss(matched.bg),
    backgroundGradient: `linear-gradient(90deg, ${strong} 0%, ${mid} 42%, ${clear} 100%)`,
    color: fontColor,
  };
}
