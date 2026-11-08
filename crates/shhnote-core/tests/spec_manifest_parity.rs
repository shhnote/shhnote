use shhnote_core::{Error, container::Payload};

// A payload holding only a manifest (SPEC §2.5). Both implementations must decide the same
// for the same bytes (SPEC §2.14); client/test/spec_conformance.test.ts has the TypeScript
// side of each case.
fn with_manifest(json: &str) -> Vec<u8> {
    let mut out = (json.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(json.as_bytes());
    out
}

#[test]
fn spec_manifest_file_size_negative_zero_is_refused() {
    let bytes = with_manifest(r#"{"v":1,"text":"t","files":[{"name":"a","type":"","size":-0}]}"#);
    assert!(
        matches!(Payload::decode(&bytes), Err(Error::Manifest(_))),
        "serde_json reads -0 as a float and refuses it for u64"
    );
}

#[test]
fn spec_manifest_deep_nesting_in_an_ignored_key_is_accepted() {
    // serde_json skips ignored values iteratively, so its recursion limit does not apply;
    // the TypeScript decoder accepts the same bytes.
    for depth in [200usize, 500_000] {
        let deep = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        let bytes = with_manifest(&format!(r#"{{"v":1,"text":"t","files":[],"x":{deep}}}"#));
        let payload = Payload::decode(&bytes).unwrap_or_else(|e| panic!("depth {depth}: {e}"));
        assert_eq!(payload.text.as_deref(), Some("t"));
    }
}

#[test]
fn spec_manifest_duplicated_unknown_key_is_ignored() {
    let bytes = with_manifest(r#"{"v":1,"text":"t","files":[],"x":1,"x":2}"#);
    let payload =
        Payload::decode(&bytes).expect("serde_json ignores unknown fields, duplicated or not");
    assert_eq!(payload.text.as_deref(), Some("t"));
}

#[test]
fn spec_manifest_parity_cases_from_the_vectors_are_refused() {
    for json in [
        r#"{"v":1,"text":"t","files":[],"text":"u"}"#,
        r#"{"v":1.0,"text":"t","files":[]}"#,
        r#"{"v":1,"files":[]}"#,
        "\u{feff}{\"v\":1,\"text\":\"t\",\"files\":[]}",
        r#"{"v":1,"text":"\ud800","files":[]}"#,
        r#"{"v":1,"text":"t","files":[null]}"#,
    ] {
        assert!(
            matches!(
                Payload::decode(&with_manifest(json)),
                Err(Error::Manifest(_))
            ),
            "{json}"
        );
    }
}
