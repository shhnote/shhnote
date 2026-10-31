use std::slice;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroize;

// The same client bounds as `shhnote_core::kdf::Argon2Params` (SPEC §2.9). Duplicated on
// purpose: this crate must stay free of the core crate's non-wasm dependencies.
const MIN_M: u32 = 8 * 1024;
const MAX_M: u32 = 256 * 1024;
const MAX_T: u32 = 8;
const MAX_P: u32 = 4;
const OUT_LEN: usize = 32;

const OK: i32 = 0;
const ERR_BOUNDS: i32 = 1;
const ERR_FAILED: i32 = 2;

// The JavaScript side allocates input and output buffers here, inside wasm memory.
#[unsafe(no_mangle)]
pub extern "C" fn shh_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len.max(1));
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// # Safety
/// `ptr` and `len` must come from a matching `shh_alloc` call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shh_free(ptr: *mut u8, len: usize) {
    drop(unsafe { Vec::from_raw_parts(ptr, 0, len.max(1)) });
}

/// Argon2id with a 32-byte output. Returns 0 on success, 1 for parameters outside the
/// bounds, 2 if hashing failed. `out` must point at 32 writable bytes.
///
/// # Safety
/// All pointers must be valid for the given lengths inside wasm memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shh_argon2id(
    pwd: *const u8,
    pwd_len: usize,
    salt: *const u8,
    salt_len: usize,
    m: u32,
    t: u32,
    p: u32,
    out: *mut u8,
) -> i32 {
    if !(MIN_M..=MAX_M).contains(&m) || !(1..=MAX_T).contains(&t) || !(1..=MAX_P).contains(&p) {
        return ERR_BOUNDS;
    }
    let Ok(params) = Params::new(m, t, p, Some(OUT_LEN)) else {
        return ERR_BOUNDS;
    };
    let pwd = unsafe { slice::from_raw_parts(pwd, pwd_len) };
    let salt = unsafe { slice::from_raw_parts(salt, salt_len) };
    let out = unsafe { slice::from_raw_parts_mut(out, OUT_LEN) };
    // The work memory is ours, so it can be wiped before it goes back to the allocator;
    // otherwise the passphrase-derived state would sit in wasm memory until reused (SPEC §10).
    let mut blocks = vec![Block::new(); params.block_count()];
    let result = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(pwd, salt, out, &mut blocks);
    blocks.zeroize();
    match result {
        Ok(()) => OK,
        Err(_) => ERR_FAILED,
    }
}
