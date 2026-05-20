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

  const edge = rgb16ToRgba(matched.bg, 0.46);
  const soft = rgb16ToRgba(matched.bg, 0.2);
  const mist = rgb16ToRgba(matched.bg, 0.09);
  const clear = rgb16ToRgba(matched.bg, 0.035);
  const fontColor = "rgb(0, 0, 0)";

  return {
    ruleName: matched.name,
    backgroundColor: rgb16ToCss(matched.bg),
    backgroundGradient: [
      `linear-gradient(90deg, ${edge} 0 0.35rem, transparent 0.35rem 100%)`,
      `radial-gradient(circle at 12% 50%, ${soft} 0%, ${clear} 44%, transparent 72%)`,
      `linear-gradient(90deg, ${soft} 0%, ${mist} 34%, ${clear} 78%, transparent 100%)`,
      "linear-gradient(180deg, rgba(255, 255, 255, 0.18), rgba(255, 255, 255, 0.04))",
    ].join(", "),
    color: fontColor,
  };
}
