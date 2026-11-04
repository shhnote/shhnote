import { ShhError } from "./error.ts";
import { type Argon2Params, checkArgon2Bounds } from "./kdf.ts";

interface Exports {
  memory: WebAssembly.Memory;
  shh_alloc(len: number): number;
  shh_free(ptr: number, len: number): void;
  shh_argon2id(
    pwd: number,
    pwdLen: number,
    salt: number,
    saltLen: number,
    m: number,
    t: number,
    p: number,
    out: number,
  ): number;
}

const encoder = new TextEncoder();

// Argon2id, compiled to WebAssembly from the same Rust crate the server uses. Load it once
// and reuse it; each call allocates the memory the parameters ask for and frees it after.
export class Argon2 {
  private readonly wasm: Exports;

  private constructor(wasm: Exports) {
    this.wasm = wasm;
  }

  static async load(source: BufferSource | WebAssembly.Module): Promise<Argon2> {
    const module = source instanceof WebAssembly.Module ? source : await WebAssembly.compile(source);
    const instance = await WebAssembly.instantiate(module, {});
    return new Argon2(instance.exports as unknown as Exports);
  }

  // For the browser: `Argon2.fromResponse(fetch("/static/argon2.wasm"))`.
  static async fromResponse(response: Response | Promise<Response>): Promise<Argon2> {
    const module = await WebAssembly.compileStreaming(response);
    return Argon2.load(module);
  }

  hash(passphrase: string, salt: Uint8Array, params: Argon2Params): Uint8Array<ArrayBuffer> {
    checkArgon2Bounds(params);
    const pwd = encoder.encode(passphrase);
    const pwdPtr = this.wasm.shh_alloc(pwd.length);
    const saltPtr = this.wasm.shh_alloc(salt.length);
    const outPtr = this.wasm.shh_alloc(32);
    try {
      // Memory may grow during the call, which detaches earlier views, so views are taken fresh each time.
      new Uint8Array(this.wasm.memory.buffer).set(pwd, pwdPtr);
      new Uint8Array(this.wasm.memory.buffer).set(salt, saltPtr);
      const status = this.wasm.shh_argon2id(pwdPtr, pwd.length, saltPtr, salt.length, params.m, params.t, params.p, outPtr);
      if (status === 1) throw new ShhError("argon2_out_of_bounds");
      if (status !== 0) throw new ShhError("argon2_unavailable", `argon2 failed with status ${status}`);
      return new Uint8Array(this.wasm.memory.buffer.slice(outPtr, outPtr + 32));
    } finally {
      // The JavaScript copy of the passphrase bytes goes too; the string itself cannot be wiped.
      pwd.fill(0);
      const view = new Uint8Array(this.wasm.memory.buffer);
      view.fill(0, pwdPtr, pwdPtr + pwd.length);
      view.fill(0, outPtr, outPtr + 32);
      this.wasm.shh_free(pwdPtr, pwd.length);
      this.wasm.shh_free(saltPtr, salt.length);
      this.wasm.shh_free(outPtr, 32);
    }
  }
}
