export interface StreamIndexWireDTO extends Record<string, unknown> {
  ids?: number[];
}

export interface PacketRawHexWireDTO extends Record<string, unknown> {
  raw_hex?: string;
}

export interface PacketLayersWireDTO extends Record<string, unknown> {
  layers?: Record<string, unknown>;
}
