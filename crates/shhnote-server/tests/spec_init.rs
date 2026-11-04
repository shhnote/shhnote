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

    // Round 2, R-9: a value set in any form the server reads (`export`, spaces around `=`)
    // is kept, never shadowed by an appended line; an empty quoted value is filled; a key
    // set twice is refused with the lines named and the file left alone.
    let forms = dir.join("forms");
    fs::write(
        &forms,
        "export SHH_SECRET_KEY=keep-this-exact-value-please-too\nSHH_ADMIN_TOKEN = \"\"\n",
    )
    .unwrap();
    let out = shhnote()
        .args(["init", "--env", forms.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = String::from_utf8(out.stdout).unwrap();
    assert!(
        report.contains("SHH_SECRET_KEY: already set, kept"),
        "{report}"
    );
    assert!(report.contains("SHH_ADMIN_TOKEN: filled in"), "{report}");
    let written = fs::read_to_string(&forms).unwrap();
    assert_eq!(written.matches("SHH_SECRET_KEY").count(), 1, "{written}");
    assert!(
        written.starts_with(
            "export SHH_SECRET_KEY=keep-this-exact-value-please-too\nSHH_ADMIN_TOKEN="
        )
    );
    assert!(!written.contains("SHH_ADMIN_TOKEN = \"\""), "{written}");

    let twice = dir.join("twice");
    fs::write(&twice, "SHH_SECRET_KEY=\nSHH_SECRET_KEY=second\n").unwrap();
    let out = shhnote()
        .args(["init", "--env", twice.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("lines 1 and 2 both set SHH_SECRET_KEY"),
        "{err}"
    );
    assert_eq!(
        fs::read_to_string(&twice).unwrap(),
        "SHH_SECRET_KEY=\nSHH_SECRET_KEY=second\n"
    );

    // Round 2, R-10: the mode is kept, and one that lets others read the file is called out.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let open = dir.join("open");
        fs::write(&open, "SHH_SECRET_KEY=\n").unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o644)).unwrap();
        let out = shhnote()
            .args(["init", "--env", open.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(out.status.success());
        let report = String::from_utf8(out.stdout).unwrap();
        assert!(
            report.contains("readable by other users (mode 644)") && report.contains("chmod 600"),
            "{report}"
        );
        assert_eq!(
            fs::metadata(&open).unwrap().permissions().mode() & 0o777,
            0o644
        );
        // `fresh` was created by `init` itself, owner-only.
        let out = shhnote()
            .args(["init", "--env", fresh.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains("readable by other users"),
            "a private file was warned about"
        );
    }

    let bad = shhnote().args(["init", "--nonsense"]).output().unwrap();
    assert!(!bad.status.success());
    let _ = fs::remove_dir_all(&dir);
}
