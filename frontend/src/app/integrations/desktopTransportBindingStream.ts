export interface DesktopPacketBinding {
  ListPacketsPage?: (cursor: number, limit: number, filter: string) => Promise<unknown>;
  LocatePacketPage?: (packetId: number, limit: number, filter: string) => Promise<unknown>;
  GetPacket?: (packetId: number) => Promise<unknown>;
  GetPacketRawHex?: (packetId: number) => Promise<unknown>;
  GetPacketLayers?: (packetId: number) => Promise<unknown>;
}

export interface DesktopStreamBinding {
  GetHttpStream?: (streamId: number) => Promise<unknown>;
  GetRawStream?: (protocol: string, streamId: number) => Promise<unknown>;
  GetRawStreamPage?: (protocol: string, streamId: number, cursor: number, limit: number) => Promise<unknown>;
  DecodeStreamPayload?: (request: unknown) => Promise<unknown>;
  InspectStreamPayload?: (payload: string) => Promise<unknown>;
  ListStreamPayloadSources?: (limit: number) => Promise<unknown>;
  ListStreamIDs?: (protocol: string) => Promise<unknown>;
  UpdateStreamPayloads?: (protocol: string, streamId: number, patches: unknown[]) => Promise<unknown>;
}
