import type { StreamPayloadSource } from "../core/types";

export type DecoderSettings = {
  behinder: {
    pass: string;
    key: string;
    iv: string;
    extractParam: boolean;
    deriveKeyFromPass: boolean;
    urlDecodeRounds: number;
    inputEncoding: "auto" | "base64" | "hex";
    cipherMode: "ecb" | "cbc";
  };
  antsword: {
    pass: string;
    extractParam: boolean;
    urlDecodeRounds: number;
    encoder: "" | "rot13";
  };
  godzilla: {
    pass: string;
    key: string;
    extractParam: boolean;
    stripMarkers: boolean;
    urlDecodeRounds: number;
    inputEncoding: "auto" | "base64" | "hex";
    cipher: "aes_ecb" | "aes_cbc" | "xor";
  };
};

export type BatchItem = {
  index: number;
  payload: string;
  label: string;
};

export type BatchDecodeProgress = {
  total: number;
  done: number;
  success: number;
  failed: number;
  currentLabel: string;
};

export type DecoderApplyMode = "preview" | "derived" | "overwrite";

export type DecoderHintSource = Pick<
  StreamPayloadSource,
  "familyHint" | "decoderOptionsHint" | "sourceRole" | "decoderHints" | "paramName"
>;

export const MAX_BATCH_FAILURE_DETAILS = 20;
export const EMPTY_SELECT_VALUE = "__empty__";

export const DEFAULT_SETTINGS: DecoderSettings = {
  behinder: {
    pass: "rebeyond",
    key: "",
    iv: "",
    extractParam: true,
    deriveKeyFromPass: true,
    urlDecodeRounds: 0,
    inputEncoding: "auto",
    cipherMode: "ecb",
  },
  antsword: {
    pass: "pass",
    extractParam: true,
    urlDecodeRounds: 1,
    encoder: "",
  },
  godzilla: {
    pass: "pass",
    key: "",
    extractParam: true,
    stripMarkers: true,
    urlDecodeRounds: 0,
    inputEncoding: "auto",
    cipher: "aes_ecb",
  },
};
