export type ErrorCode =
  | "invalid_fragment"
  | "unsupported_version"
  | "wrong_kind"
  | "invalid_blob_length"
  | "argon2_out_of_bounds"
  | "argon2_unavailable"
  | "passphrase_required"
  | "wrong_passphrase"
  | "corrupt"
  | "empty_payload"
  | "payload_too_large"
  | "manifest";

// Every failure the crypto module can report. `code` is stable; `message` is for logs.
// `claimToken` is set by the client library when the failure came after a single-view
// secret was claimed, so the caller can retry without consuming a fresh reveal.
export class ShhError extends Error {
  readonly code: ErrorCode;
  claimToken?: string;

  constructor(code: ErrorCode, message?: string) {
    super(message ?? code);
    this.name = "ShhError";
    this.code = code;
  }
}
