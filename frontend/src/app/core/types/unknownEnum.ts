export type KnownOrUnknown<T extends string> = T | (string & { readonly __knownOrUnknown?: never });
