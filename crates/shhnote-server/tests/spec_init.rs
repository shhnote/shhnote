// SPEC §8: `shhnote init` makes the two secrets a start needs, before any configuration
// exists; `--env <path>` writes them into a file without touching a value already set.
use std::{fs, process::Command};

fn shhnote() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shhnote"));
    // No configuration at all: `init` must not need one, and must not read a stray .env.
    cmd.env_clear().current_dir(std::env::temp_dir());
    cmd
}

#[test]
fn spec_init_subcommand() {
    let out = shhnote().arg("init").output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert!(lines[0].starts_with("SHH_SECRET_KEY=") && lines[0].len() >= 15 + 32);
    assert!(lines[1].starts_with("SHH_ADMIN_TOKEN=") && lines[1].len() >= 16 + 32);

    let dir = std::env::temp_dir().join(format!("shhnote-spec-init-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let env = dir.join("env");
    fs::write(
        &env,
        "SHH_ENV=production\nSHH_SECRET_KEY=\nSHH_ADMIN_TOKEN=keep-this-exact-value-please\n",
    )
    .unwrap();
    let out = shhnote()
        .args(["init", "--env", env.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = String::from_utf8(out.stdout).unwrap();
    assert!(report.contains("SHH_SECRET_KEY: filled in"), "{report}");
    assert!(
        report.contains("SHH_ADMIN_TOKEN: already set, kept"),
        "{report}"
    );
    let written = fs::read_to_string(&env).unwrap();
    assert!(written.starts_with("SHH_ENV=production\nSHH_SECRET_KEY="));
    assert!(written.contains("\nSHH_ADMIN_TOKEN=keep-this-exact-value-please\n"));
    assert!(
        !report.contains(&written[written.find("SHH_SECRET_KEY=").unwrap() + 15..][..20]),
        "the report must not print values"
    );

    let fresh = dir.join("fresh");
    let out = shhnote()
        .args(["init", "--env", fresh.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("written to a new file"));
    assert_eq!(fs::read_to_string(&fresh).unwrap().lines().count(), 2);

    let bad = shhnote().args(["init", "--nonsense"]).output().unwrap();
    assert!(!bad.status.success());
    let _ = fs::remove_dir_all(&dir);
}
