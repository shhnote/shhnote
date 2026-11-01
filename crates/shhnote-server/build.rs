use std::{
    fs,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

// The client bundles and the Argon2 module are embedded into the binary, so they must exist,
// be what they claim to be, and come from the sources in this checkout. They are generated
// by `scripts/build-client.sh`, never committed.
const ASSETS: [&str; 4] = ["app.js", "shh.js", "shh-ui.js", "argon2.wasm"];
// Everything the bundles are built from. Keep in step with the stamp in the build script.
const INPUT_DIRS: [&str; 2] = ["client/src", "crates/shhnote-argon2-wasm/src"];
const INPUT_FILES: [&str; 5] = [
    "client/package-lock.json",
    "client/tsconfig.json",
    "crates/shhnote-argon2-wasm/Cargo.toml",
    "scripts/build-client.sh",
    "scripts/build-wasm.sh",
];

fn main() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.join("../..");
    let dir = manifest.join("static");
    let hint = "run scripts/build-client.sh (it needs Node 24 and the wasm32 Rust target)";

    for name in ASSETS {
        let path = dir.join(name);
        println!("cargo:rerun-if-changed={}", path.display());
        let bytes =
            fs::read(&path).unwrap_or_else(|_| panic!("missing {}: {hint}", path.display()));
        if bytes.is_empty() {
            panic!("{} is empty: {hint}", path.display());
        }
        if name.ends_with(".wasm") && !bytes.starts_with(b"\0asm\x01\0\0\0") {
            panic!("{} is not a WebAssembly module: {hint}", path.display());
        }
    }

    for input in INPUT_DIRS.iter().chain(INPUT_FILES.iter()) {
        println!("cargo:rerun-if-changed={}", root.join(input).display());
    }
    let stamp_path = dir.join(".stamp");
    println!("cargo:rerun-if-changed={}", stamp_path.display());
    let stamp = fs::read_to_string(&stamp_path).unwrap_or_default();
    if stamp.trim() != input_hash(&root) {
        panic!(
            "the embedded client assets were built from other sources than this checkout: {hint}"
        );
    }
}

// SHA-256 over every input, in byte order of its path: `path\n` then the contents, the same
// as the shell pipeline in the build script.
fn input_hash(root: &Path) -> String {
    let mut paths: Vec<String> = INPUT_FILES.iter().map(|f| f.to_string()).collect();
    for dir in INPUT_DIRS {
        walk(root, Path::new(dir), &mut paths);
    }
    paths.sort_unstable();
    paths.dedup();
    let mut hasher = Sha256::new();
    for rel in paths {
        hasher.update(rel.as_bytes());
        hasher.update(b"\n");
        hasher.update(fs::read(root.join(&rel)).unwrap_or_default());
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// Relative paths with `/` separators, whatever the host uses.
fn walk(root: &Path, rel: &Path, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(root.join(rel)) else {
        return;
    };
    for entry in entries.flatten() {
        let child: PathBuf = rel.join(entry.file_name());
        if entry.path().is_dir() {
            walk(root, &child, out);
        } else {
            let text = child
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push(text);
        }
    }
}
