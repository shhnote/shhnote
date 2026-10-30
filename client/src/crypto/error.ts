export type ErrorCode =
  | "invalid_fragment"
  | "unsupported_version"
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
export class ShhError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message?: string) {
    super(message ?? code);
    this.name = "ShhError";
    this.code = code;
  }
}
