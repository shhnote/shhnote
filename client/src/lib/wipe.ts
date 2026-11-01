import type { Payload } from "../crypto/container.ts";

// Best effort (SPEC §10): overwrite what can be overwritten once a secret has done its job.
// Strings cannot be wiped in JavaScript; byte arrays can.
export function wipeBytes(...buffers: (Uint8Array | null | undefined)[]): void {
  for (const buffer of buffers) buffer?.fill(0);
}

export function wipePayload(payload: Payload | null | undefined): void {
  for (const file of payload?.files ?? []) file.bytes.fill(0);
}
