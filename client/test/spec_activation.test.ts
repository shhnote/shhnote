import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { toBase64Url } from "../src/crypto/bytes.ts";
import { lookup } from "../src/crypto/secret.ts";
import { isUserActivation } from "../src/lib/activation.ts";
import { ClaimStore, MAX_CLAIM_WINDOW_SECS } from "../src/ui/claims.ts";

const seed = new Uint8Array(32).fill(7);

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
const asStorage = (s: FakeStorage) => s as unknown as Storage;

// sessionStorage holds the claim token and its expiry and nothing else, never past the
// claim window (SPEC §10).
describe("what the claim store writes", () => {
  it("writes exactly one entry per claimed secret: {claimToken, expiresAt} under the lookup hash", async () => {
    const storage = new FakeStorage();
    let now = 1_000;
    const store = new ClaimStore(asStorage(storage), () => now);
    const lookupValue = await lookup(seed);
    const key = await ClaimStore.keyFor(lookupValue);
    store.set(key, "CLAIM-TOKEN", now + 900_000);
    assert.equal(storage.items.size, 1);
    const [k, v] = [...storage.items.entries()][0]!;
    assert.equal(k, key);
    assert.deepEqual(Object.keys(JSON.parse(v)).sort(), ["claimToken", "expiresAt"]);
    const everything = k + v;
    assert.ok(!everything.includes(toBase64Url(seed)), "seed in storage");
    assert.ok(!everything.includes(toBase64Url(lookupValue)), "lookup in storage");
    // The window as the spec bounds it: nothing lives past claim_window_secs' maximum.
    assert.equal(MAX_CLAIM_WINDOW_SECS, 86_400);
    now += 900_000;
    assert.equal(store.get(key), null);
    assert.equal(storage.items.size, 0, "an expired entry is removed on read");
  });

  it("a tampered or foreign entry is never handed back as a token", () => {
    const storage = new FakeStorage();
    const store = new ClaimStore(asStorage(storage), () => 100);
    for (const bad of [
      JSON.stringify({ claimToken: "T", expiresAt: "9999999999" }),
      JSON.stringify({ claimToken: 42, expiresAt: 9_999 }),
      JSON.stringify({ claimToken: "T" }),
      JSON.stringify(["T", 9_999]),
      JSON.stringify({ claimToken: "T", expiresAt: Number.NaN }),
      "null",
      "",
    ]) {
      storage.setItem("shh-claim:x", bad);
      assert.equal(store.get("shh-claim:x"), null, bad);
      assert.equal(storage.getItem("shh-claim:x"), null, `${bad} survived a read`);
    }
    // Infinity is a number: an entry that never expires would outlive every window.
    storage.setItem("shh-claim:x", JSON.stringify({ claimToken: "T", expiresAt: Number.POSITIVE_INFINITY }));
    assert.equal(store.get("shh-claim:x"), null, "JSON has no Infinity, so this is unparseable");
  });

  it("prune removes every expired claim and touches nothing of another kind", () => {
    const storage = new FakeStorage();
    for (let i = 0; i < 50; i++) {
      storage.setItem(`shh-claim:${i}`, JSON.stringify({ claimToken: `T${i}`, expiresAt: i * 10 }));
    }
    storage.setItem("shhnote-theme", "dark");
    storage.setItem("other-app", "{}");
    new ClaimStore(asStorage(storage), () => 250).prune();
    const left = [...storage.items.keys()];
    assert.equal(left.filter((k) => k.startsWith("shh-claim:")).length, 24, "entries with expiresAt > 250");
    assert.ok(left.includes("shhnote-theme") && left.includes("other-app"));
  });
});

// A scanner that runs the page's scripts must consume nothing (SPEC §5).
describe("only a real activation reveals", () => {
  const nav = globalThis.navigator as { userActivation?: { isActive: boolean } } | undefined;
  const withActivation = (active: boolean | undefined, run: () => void) => {
    const had = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: active === undefined ? { ...(nav ?? {}) } : { ...(nav ?? {}), userActivation: { isActive: active } },
    });
    try {
      run();
    } finally {
      if (had) Object.defineProperty(globalThis, "navigator", had);
      else delete (globalThis as { navigator?: unknown }).navigator;
    }
  };
  const ev = (type: string, extra: Record<string, unknown>) => ({ type, isTrusted: true, ...extra }) as unknown as Event;

  it("what a page script can produce is refused", () => {
    withActivation(true, () => {
      assert.equal(isUserActivation(ev("click", { detail: 0 })), false, "button.click()");
      assert.equal(isUserActivation(ev("click", { detail: 1, isTrusted: false })), false, "dispatchEvent(new MouseEvent)");
      assert.equal(isUserActivation(ev("submit", {})), false, "requestSubmit()");
      assert.equal(isUserActivation(ev("keydown", { key: "Enter", isTrusted: false })), false, "synthetic key");
      assert.equal(isUserActivation(ev("keyup", { key: "Enter" })), false);
      assert.equal(isUserActivation(ev("keydown", { key: "Tab" })), false);
      assert.equal(isUserActivation(ev("pointerdown", { detail: 1 })), false);
      assert.equal(isUserActivation(ev("touchend", { detail: 1 })), false);
      assert.equal(isUserActivation(ev("click", { detail: 1, isTrusted: undefined })), false);
    });
    // A trusted click with the browser saying the user has not activated anything: a
    // scanner that replays recorded input without a gesture.
    withActivation(false, () => {
      assert.equal(isUserActivation(ev("click", { detail: 1 })), false);
      assert.equal(isUserActivation(ev("keydown", { key: "Enter" })), false);
    });
  });

  it("a real press is accepted, with or without the activation API", () => {
    for (const active of [true, undefined]) {
      withActivation(active, () => {
        assert.equal(isUserActivation(ev("click", { detail: 1 })), true);
        assert.equal(isUserActivation(ev("click", { detail: 2 })), true);
        assert.equal(isUserActivation(ev("keydown", { key: "Enter" })), true);
        assert.equal(isUserActivation(ev("keydown", { key: " " })), true);
      });
    }
  });
});
