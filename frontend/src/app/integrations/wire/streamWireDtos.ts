export interface StreamIndexWireDTO extends Record<string, unknown> {
  ids?: unknown;
}

export interface PacketRawHexWireDTO extends Record<string, unknown> {
  raw_hex?: unknown;
}

export interface PacketLayersWireDTO extends Record<string, unknown> {
  layers?: unknown;
}
