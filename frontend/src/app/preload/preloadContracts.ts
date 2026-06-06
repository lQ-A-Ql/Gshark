export type FeaturePreloadContract<Input, Data> = {
  getCacheKey(input: Input): string;
  readCache(key: string): Data | undefined;
  writeCache(key: string, data: Data): void;
  getInflight(key: string): Promise<Data> | undefined;
  prefetch(input: Input, signal: AbortSignal): Promise<Data>;
};
