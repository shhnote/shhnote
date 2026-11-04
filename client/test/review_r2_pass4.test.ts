// Security review round 2, pass 4: the client-side pieces the reference pages rely on
// (activation guard, the strings block, the claim store, config caching). Each test states the
// property it checks; a failing test is a finding.
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { checkProtocol } from "../src/client.ts";
import { ShhError } from "../src/crypto/error.ts";
import { isUserActivation } from "../src/lib/activation.ts";
import { Api, getConfig } from "../src/lib/api.ts";
import { ClaimStore } from "../src/ui/claims.ts";
import { ttlChoices } from "../src/ui/create.ts";
import { createT } from "../src/ui/i18n.ts";

function event(type: string, fields: Record<string, unknown>): Event {
  return { type, isTrusted: true, ...fields } as unknown as Event;
}

describe("review r2 pass4: activation guard (SPEC §5.1)", () => {
  it("accepts only a trusted pointer click with detail > 0 or a trusted Enter/Space", () => {
    assert.equal(isUserActivation(event("click", { detail: 1 })), true);
    assert.equal(isUserActivation(event("click", { detail: 0 })), false, "button.click() from a script");
    assert.equal(isUserActivation(event("click", { detail: 1, isTrusted: false })), false, "dispatchEvent");
    assert.equal(isUserActivation(event("submit", {})), false, "requestSubmit() is trusted but not an activation");
    assert.equal(isUserActivation(event("keydown", { key: "Enter" })), true);
    assert.equal(isUserActivation(event("keydown", { key: " " })), true);
    assert.equal(isUserActivation(event("keydown", { key: "a" })), false);
    assert.equal(isUserActivation(event("keyup", { key: "Enter" })), false);
    assert.equal(isUserActivation(event("pointerdown", { detail: 1 })), false);
  });

  it("asks the browser's user-activation state when the API exists", () => {
    const saved = (globalThis as { navigator?: unknown }).navigator;
    try {
      Object.defineProperty(globalThis, "navigator", { value: { userActivation: { isActive: false } }, configurable: true });
      assert.equal(isUserActivation(event("click", { detail: 1 })), false, "no activation in the window");
      Object.defineProperty(globalThis, "navigator", { value: { userActivation: { isActive: true } }, configurable: true });
      assert.equal(isUserActivation(event("click", { detail: 1 })), true);
    } finally {
      Object.defineProperty(globalThis, "navigator", { value: saved, configurable: true });
    }
  });
});

describe("review r2 pass4: strings block", () => {
  const rootWith = (json: string) => ({ querySelector: () => ({ textContent: json }) }) as unknown as ParentNode;

  it("treats the block as data: markup in a string stays a string, unknown keys are ignored", () => {
    const t = createT(rootWith('{"burn-working": "<b>x</b> \\u003c/script>", "__proto__": {"polluted": 1}, "constructor": "x"}'));
    assert.equal(t("burn-working"), "<b>x</b> </script>");
    assert.equal(({} as Record<string, unknown>)["polluted"], undefined, "no prototype pollution through the block");
    assert.equal(t("reveal-download"), "reveal-download");
  });

  it("variable substitution never re-reads the substituted value", () => {
    const t = createT(rootWith('{"result-chip-expires": "Expires in {period} {period}"}'));
    assert.equal(t("result-chip-expires", { period: "{period}" }), "Expires in {period} {period}");
  });
});

describe("review r2 pass4: claim store (SPEC §10)", () => {
  class FakeStorage {
    readonly items = new Map<string, string>();
    get length() {
      return this.items.size;
    }
    key(i: number) {
      return [...this.items.keys()][i] ?? null;
    }
    getItem(k: string) {
      return this.items.get(k) ?? null;
    }
    setItem(k: string, v: string) {
      this.items.set(k, v);
    }
    removeItem(k: string) {
      this.items.delete(k);
    }
  }

  it("ignores hostile or foreign entries and removes only its own expired ones", () => {
    const storage = new FakeStorage();
    storage.setItem("shh-claim:x", '{"claimToken": 5, "expiresAt": "soon"}');
    storage.setItem("shh-claim:y", "not json");
    storage.setItem("shh-claim:z", '{"claimToken": "T", "expiresAt": 10}');
    storage.setItem("other-app", "keep");
    const store = new ClaimStore(storage as unknown as Storage, () => 20);
    assert.equal(store.get("shh-claim:x"), null);
    assert.equal(store.get("shh-claim:z"), null, "expired");
    store.prune();
    assert.deepEqual([...storage.items.keys()], ["other-app"]);
  });

  it("survives a storage that throws", () => {
    const throwing = new Proxy({}, { get: () => () => { throw new Error("blocked"); } }) as unknown as Storage;
    const store = new ClaimStore(throwing, () => 0);
    assert.equal(store.get("shh-claim:x"), null);
    store.set("shh-claim:x", "T", 1);
    store.delete("shh-claim:x");
    store.prune();
  });
});

describe("review r2 pass4: instance config", () => {
  it("getConfig caches per normalised base and per fetch, and a failure is not kept", async () => {
    let calls = 0;
    const failing = async () => {
      calls += 1;
      return new Response("no", { status: 500 });
    };
    await assert.rejects(getConfig("https://h.example/api/v1/", failing));
    await assert.rejects(getConfig("https://h.example/api/v1", failing));
    assert.equal(calls, 2, "a failed fetch is retried, not cached");
    const ok = async () => new Response(JSON.stringify({ fragment_version: 1, max_blob_bytes: 1 }), { status: 200 });
    const a = await getConfig("https://h.example/api/v1/", ok);
    const b = await getConfig("https://h.example/api/v1", ok);
    assert.equal(a, b, "one object for both spellings");
  });

  it("checkProtocol refuses every version but the one this package speaks", () => {
    checkProtocol({ fragment_version: 1 });
    for (const v of [0, 2, 1.5, -1, Number.NaN, "1" as unknown as number]) {
      assert.throws(
        () => checkProtocol({ fragment_version: v }),
        (e: unknown) => e instanceof ShhError && e.code === "unsupported_protocol",
      );
    }
  });

  it("ttlChoices drops presets outside the instance bounds and never offers an empty list silently", () => {
    const { seconds, selected } = ttlChoices({ ttl_presets: [30, 900, 10_000_000], default_ttl_secs: 86_400, min_ttl_secs: 60, max_ttl_secs: 1_209_600 });
    assert.deepEqual(seconds, [900, 86_400]);
    assert.equal(selected, 86_400);
    const none = ttlChoices({ ttl_presets: [], default_ttl_secs: 30, min_ttl_secs: 60, max_ttl_secs: 120 });
    assert.deepEqual(none.seconds, []);
  });

  it("Api never sends credentials and never lets a cache answer", async () => {
    let init: RequestInit | undefined;
    const api = new Api("https://h.example/api/v1", async (_url, i) => {
      init = i;
      return new Response("{}", { status: 200 });
    });
    await api.config();
    assert.equal(init?.credentials, "omit");
    assert.equal(init?.cache, "no-store");
  });
});
