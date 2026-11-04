// Round-2 security review, pass 5: the Rust side of the manifest-parity cases in
// client/test/review_r2_pass5.test.ts (finding F-5-5). Each test pins what serde_json does
// today; the TypeScript decoder decides the opposite for the same bytes.
use shhnote_core::{Error, container::Payload};

fn with_manifest(json: &str) -> Vec<u8> {
    let mut out = (json.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(json.as_bytes());
    out
}

#[test]
fn spec_r2_f_5_5_file_size_negative_zero_is_refused_here_and_accepted_in_typescript() {
    let bytes = with_manifest(r#"{"v":1,"text":"t","files":[{"name":"a","type":"","size":-0}]}"#);
    assert!(
        matches!(Payload::decode(&bytes), Err(Error::Manifest(_))),
        "serde_json reads -0 as a float and refuses it for u64"
    );
}

#[test]
fn deep_nesting_in_an_ignored_key_is_accepted_on_both_sides() {
    // serde_json skips ignored values iteratively, so its recursion limit does not apply;
    // the TypeScript decoder accepts the same bytes. Checked, not a finding.
    for depth in [200usize, 500_000] {
        let deep = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        let bytes = with_manifest(&format!(r#"{{"v":1,"text":"t","files":[],"x":{deep}}}"#));
        let payload = Payload::decode(&bytes).unwrap_or_else(|e| panic!("depth {depth}: {e}"));
        assert_eq!(payload.text.as_deref(), Some("t"));
    }
}

#[test]
fn spec_r2_f_5_5_duplicated_unknown_key_is_accepted_here_and_refused_in_typescript() {
    let bytes = with_manifest(r#"{"v":1,"text":"t","files":[],"x":1,"x":2}"#);
    let payload =
        Payload::decode(&bytes).expect("serde_json ignores unknown fields, duplicated or not");
    assert_eq!(payload.text.as_deref(), Some("t"));
}

#[test]
fn the_parity_cases_the_vectors_pin_still_hold() {
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
