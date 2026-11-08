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

// `max_blob_bytes` is a bucket (SPEC §4), so a secret at the ceiling is served with
// Content-Length = blobLen(bucket), longer than the bucket itself.
test("a blob of blobLen(max_blob_bytes) bytes, which the server stores, passes the client's cap", async () => {
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
  // The body is all zeros, so decryption fails; what matters is that the cap let it through.
  await assert.rejects(
    revealSecret(`#${fragment}`, { apiBase: "https://x.test/api/v1", fetch: fetchImpl }),
    (e: unknown) => !(e instanceof ApiError && e.code === "too_large"),
  );
});
