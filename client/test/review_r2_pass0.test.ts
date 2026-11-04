// Round-2 pass 0 (claims audit), C-27: the client caps the reveal body at `max_blob_bytes`,
// which the server defines as a bucket (padded size); a stored secret whose bucket equals
// the ceiling is served with Content-Length = blobLen(bucket) and the client refuses it.
// Throwaway; delete after the review.
import assert from "node:assert/strict";
import { test } from "node:test";

import { revealSecret } from "../src/client.ts";
import { blobLen } from "../src/crypto/padding.ts";
import { encodeFragment } from "../src/crypto/fragment.ts";
import { ApiError } from "../src/lib/api.ts";

const MAX = 65536;

const config = {
  fragment_version: 1,
  padding: { mode: "padme", min: 65536 },
  inline_max: MAX,
  max_blob_bytes: MAX,
  claim_window_secs: 900,
  min_ttl_secs: 60,
  max_ttl_secs: 1209600,
  default_ttl_secs: 86400,
  ttl_presets: [900],
  text_max_bytes: 65536,
  files_enabled: true,
  regions: [],
  server_version: "0.4.0-rc.1",
  web_mode: "full",
};

test("review_r2_pass0: a blob of blobLen(max_blob_bytes) bytes, which the server stores, is refused by the client", async () => {
  const served = blobLen(MAX);
  assert.ok(served > MAX, "blobLen(bucket) exceeds the bucket");
  const fetchImpl = async (input: string): Promise<Response> => {
    if (input.endsWith("/config")) return new Response(JSON.stringify(config), { status: 200 });
    if (input.endsWith("/secrets/reveal")) {
      return new Response(new Uint8Array(served), {
        status: 200,
        headers: { "content-type": "application/octet-stream", "content-length": String(served) },
      });
    }
    throw new Error(`unexpected ${input}`);
  };
  const fragment = encodeFragment(new Uint8Array(32), "share");
  await assert.rejects(
    revealSecret(`#${fragment}`, { apiBase: "https://x.test/api/v1", fetch: fetchImpl }),
    (e: unknown) => e instanceof ApiError && e.code === "too_large",
  );
});
