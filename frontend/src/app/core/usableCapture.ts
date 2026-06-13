export function hasUsableCapturePath(filePath: string, totalPackets: number): boolean {
  return filePath.trim().length > 0 && totalPackets > 0;
}
