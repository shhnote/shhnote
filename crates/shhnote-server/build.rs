use std::path::Path;

// The client bundles and the Argon2 module are embedded into the binary, so they must exist
// before the server compiles. They are generated, never committed.
fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("static");
    for name in ["app.js", "shh.js", "argon2.wasm"] {
        let path = dir.join(name);
        println!("cargo:rerun-if-changed={}", path.display());
        if !path.exists() {
            panic!(
                "missing {}: run scripts/build-client.sh first (it needs Node 24 and the wasm32 Rust target)",
                path.display()
            );
        }
    }
}
