import type { PacketWireDTO } from "./packetWireDtos";

export interface PacketsPageWireDTO extends Record<string, unknown> {
  items?: PacketWireDTO[];
  next_cursor?: number;
  total?: number;
  has_more?: boolean;
  filtering?: boolean;
}

export interface PacketLocateWireDTO extends Record<string, unknown> {
  packet_id?: number;
  cursor?: number;
  total?: number;
  found?: boolean;
}
