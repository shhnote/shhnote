use std::{
    fs, io,
    path::{Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

// `shhnote init`: the two secrets an instance needs before it can start (SPEC §8). Printed
// as `KEY=value` lines, or written into an env file: created when missing, otherwise only
// the keys it lacks are added and a value that is already set is never touched.

pub const KEYS: [&str; 2] = ["SHH_SECRET_KEY", "SHH_ADMIN_TOKEN"];

// 32 random bytes, base64url: 43 characters, above the 32 the server requires.
pub fn generate() -> io::Result<Vec<(&'static str, String)>> {
    KEYS.iter()
        .map(|key| {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
            Ok((*key, URL_SAFE_NO_PAD.encode(bytes)))
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Created,
    Filled,
    Appended,
    Kept,
}

// Applies the generated values to the file: a missing file is created (readable by its owner
// only), an empty `KEY=` line is filled in place, a missing key is appended, a set key stays.
// Every write goes through a temp file and a rename, so the file is never half-written.
pub fn apply(
    path: &Path,
    values: &[(&'static str, String)],
) -> io::Result<Vec<(&'static str, Outcome)>> {
    let existing = match fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let Some(text) = existing else {
        let body: String = values.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
        write_atomically(path, &body)?;
        return Ok(values.iter().map(|(k, _)| (*k, Outcome::Created)).collect());
    };
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut outcomes = Vec::new();
    for (key, value) in values {
        // Every line that sets the key, in any form the server's reader accepts: a key set
        // twice is left to the operator, since the server would read the last one while a
        // fill here would touch the first.
        let found: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| assignment(line).is_some_and(|a| a.key == *key))
            .map(|(i, _)| i)
            .collect();
        match found[..] {
            [] => {
                lines.push(format!("{key}={value}"));
                outcomes.push((*key, Outcome::Appended));
            }
            [i] => {
                let line = &lines[i];
                let set = assignment(line).expect("found above");
                let empty = set.is_empty().ok_or_else(|| {
                    io::Error::other(format!(
                        "line {} sets {key} in a form shhnote init cannot judge; set it by hand",
                        i + 1
                    ))
                })?;
                if empty {
                    lines[i] = format!("{}{key}={value}", set.prefix);
                    outcomes.push((*key, Outcome::Filled));
                } else {
                    outcomes.push((*key, Outcome::Kept));
                }
            }
            [first, .., last] => {
                return Err(io::Error::other(format!(
                    "lines {} and {} both set {key}; keep one",
                    first + 1,
                    last + 1
                )));
            }
        }
    }
    if outcomes.iter().any(|(_, o)| *o != Outcome::Kept) {
        let mut body = lines.join("\n");
        body.push('\n');
        write_atomically(path, &body)?;
    }
    Ok(outcomes)
}

// One `KEY=value` line as the server's `.env` reader (dotenvy) sees it: an optional `export`,
// spaces around the `=`, a value that may be quoted or followed by a comment.
struct Assignment<'a> {
    // Everything before the key (`export ` and indentation), kept when the line is rewritten.
    prefix: &'a str,
    key: &'a str,
    value: &'a str,
}

impl Assignment<'_> {
    // Whether the server would read an empty value. `None` for a quoted value that does not
    // end on this line, which this tool does not try to understand.
    fn is_empty(&self) -> Option<bool> {
        let value = self.value.trim();
        if value.is_empty() || value.starts_with('#') {
            return Some(true);
        }
        if let Some(quote) = value.chars().next().filter(|c| *c == '"' || *c == '\'') {
            let inner = &value[1..];
            let close = inner.find(quote)?;
            return Some(inner[..close].is_empty());
        }
        Some(false)
    }
}

fn assignment(line: &str) -> Option<Assignment<'_>> {
    let body = line.trim_start();
    if body.starts_with('#') {
        return None;
    }
    let body = body.strip_prefix("export ").map_or(body, str::trim_start);
    let (key, value) = body.split_once('=')?;
    let key = key.trim_end();
    let valid = !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !valid {
        return None;
    }
    let prefix = &line[..line.len() - body.len()];
    Some(Assignment { prefix, key, value })
}

// Writes the whole file next to the old one and renames it into place: a crash, a full disk
// or a kill leaves either the old file or the new one, never a truncated env file with the
// server's secrets half gone. The new file keeps the old one's permissions and, where the
// caller may set them, its owner and group (a new file is owner-only); a symlinked env file
// is updated where it points.
fn write_atomically(path: &Path, body: &str) -> io::Result<()> {
    let target = match fs::canonicalize(path) {
        Ok(target) => target,
        Err(e) if e.kind() == io::ErrorKind::NotFound => path.to_path_buf(),
        Err(e) => return Err(e),
    };
    let existing = match fs::metadata(&target) {
        Ok(meta) => Some(meta),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let dir = match target.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = target
        .file_name()
        .ok_or_else(|| io::Error::other("the env path names no file"))?
        .to_string_lossy();
    let mut random = [0u8; 6];
    getrandom::fill(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
    let temp = dir.join(format!(".{name}.{}.tmp", URL_SAFE_NO_PAD.encode(random)));

    let written = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        io::Write::write_all(&mut file, body.as_bytes())?;
        file.sync_all()?;
        if let Some(meta) = &existing {
            // Owner and group too, where we may set them (root can; anyone else gets their own).
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let _ = std::os::unix::fs::chown(&temp, Some(meta.uid()), Some(meta.gid()));
            }
            fs::set_permissions(&temp, meta.permissions())?;
        }
        fs::rename(&temp, &target)?;
        // Best effort: the rename is durable once the directory entry is on disk, but the
        // file is already in place, so a failure here is no reason to report one.
        #[cfg(unix)]
        let _ = fs::File::open(&dir).and_then(|d| d.sync_all());
        Ok(())
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    written
}

// The subcommand itself: `init` prints, `init --env <path>` writes. Exit code 0 on success.
pub fn run(args: &[String]) -> io::Result<()> {
    let values = generate()?;
    match args {
        [] => {
            for (key, value) in &values {
                println!("{key}={value}");
            }
            Ok(())
        }
        [flag, path] if flag == "--env" => {
            let path = Path::new(path);
            for (key, outcome) in apply(path, &values)? {
                let what = match outcome {
                    Outcome::Created => "written to a new file",
                    Outcome::Filled => "filled in",
                    Outcome::Appended => "appended",
                    Outcome::Kept => "already set, kept",
                };
                println!("{key}: {what} ({})", path.display());
            }
            // The file keeps its mode (SPEC §8); it now holds credentials, so a mode that lets
            // other users read it deserves a word.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(path)?.permissions().mode() & 0o777;
                if mode & 0o044 != 0 {
                    println!(
                        "warning: {} is readable by other users (mode {mode:o}) and now holds credentials; run: chmod 600 {}",
                        path.display(),
                        path.display()
                    );
                }
            }
            Ok(())
        }
        _ => Err(io::Error::other("usage: shhnote init [--env <path>]")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("shhnote-init-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn values_are_long_enough_and_distinct() {
        let values = generate().unwrap();
        assert_eq!(values.len(), 2);
        assert!(values.iter().all(|(_, v)| v.len() >= 32));
        assert_ne!(values[0].1, values[1].1);
        assert_ne!(generate().unwrap()[0].1, values[0].1);
    }

    #[test]
    fn creates_fills_appends_and_keeps() {
        let dir = dir();
        let values = generate().unwrap();
        let fresh = dir.join("fresh.env");
        let outcomes = apply(&fresh, &values).unwrap();
        assert!(outcomes.iter().all(|(_, o)| *o == Outcome::Created));
        let text = fs::read_to_string(&fresh).unwrap();
        assert_eq!(
            text,
            format!(
                "SHH_SECRET_KEY={}\nSHH_ADMIN_TOKEN={}\n",
                values[0].1, values[1].1
            )
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // Running again changes nothing.
        let again = apply(&fresh, &generate().unwrap()).unwrap();
        assert!(again.iter().all(|(_, o)| *o == Outcome::Kept));
        assert_eq!(fs::read_to_string(&fresh).unwrap(), text);

        // An example file: an empty key is filled in place, a commented one is appended,
        // everything else is left alone.
        let example = dir.join("example.env");
        fs::write(
            &example,
            "SHH_ENV=local\n# a comment\nSHH_SECRET_KEY=\n#SHH_ADMIN_TOKEN=\nSHH_DB=sqlite\n",
        )
        .unwrap();
        let outcomes = apply(&example, &values).unwrap();
        assert_eq!(
            outcomes,
            vec![
                ("SHH_SECRET_KEY", Outcome::Filled),
                ("SHH_ADMIN_TOKEN", Outcome::Appended)
            ]
        );
        let text = fs::read_to_string(&example).unwrap();
        assert_eq!(
            text,
            format!(
                "SHH_ENV=local\n# a comment\nSHH_SECRET_KEY={}\n#SHH_ADMIN_TOKEN=\nSHH_DB=sqlite\nSHH_ADMIN_TOKEN={}\n",
                values[0].1, values[1].1
            )
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // The forms the server's reader accepts are all recognised, a key set
    // twice or in a form that cannot be judged is an error, and nothing is ever appended
    // behind a set value.
    #[test]
    fn reads_lines_the_way_the_server_does() {
        // Its own directory: `dir()` is wiped by the tests that share it.
        let dir = std::env::temp_dir().join(format!("shhnote-init-forms-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let values = generate().unwrap();
        let cases: [(&str, Outcome); 7] = [
            ("export SHH_SECRET_KEY=set-by-hand\n", Outcome::Kept),
            ("SHH_SECRET_KEY = set-by-hand\n", Outcome::Kept),
            (
                "  export  SHH_SECRET_KEY =\"set-by-hand\" # c\n",
                Outcome::Kept,
            ),
            ("SHH_SECRET_KEY=\"\"\n", Outcome::Filled),
            ("SHH_SECRET_KEY=''\n", Outcome::Filled),
            ("SHH_SECRET_KEY= # comment\n", Outcome::Filled),
            ("export SHH_SECRET_KEY=\n", Outcome::Filled),
        ];
        for (i, (text, expected)) in cases.iter().enumerate() {
            let env = dir.join(format!("case{i}.env"));
            fs::write(&env, text).unwrap();
            let outcomes = apply(&env, &values).unwrap();
            assert_eq!(outcomes[0], ("SHH_SECRET_KEY", *expected), "{text:?}");
            let after = fs::read_to_string(&env).unwrap();
            assert_eq!(
                after.matches("SHH_SECRET_KEY").count(),
                1,
                "{text:?} -> {after:?}"
            );
            if *expected == Outcome::Kept {
                assert!(after.starts_with(text), "{text:?} -> {after:?}");
            } else {
                let line = after.lines().next().unwrap();
                assert!(line.ends_with(&values[0].1), "{text:?} -> {after:?}");
                assert_eq!(line.starts_with("export"), text.starts_with("export"));
            }
        }

        let twice = dir.join("twice.env");
        fs::write(
            &twice,
            "SHH_SECRET_KEY=\nSHH_ADMIN_TOKEN=x\nSHH_SECRET_KEY=y\n",
        )
        .unwrap();
        let err = apply(&twice, &values).unwrap_err().to_string();
        assert!(err.contains("lines 1 and 3"), "{err}");
        assert_eq!(
            fs::read_to_string(&twice).unwrap(),
            "SHH_SECRET_KEY=\nSHH_ADMIN_TOKEN=x\nSHH_SECRET_KEY=y\n"
        );

        let open_quote = dir.join("quote.env");
        fs::write(&open_quote, "SHH_SECRET_KEY=\"starts here\n").unwrap();
        let err = apply(&open_quote, &values).unwrap_err().to_string();
        assert!(
            err.contains("line 1") && err.contains("cannot judge"),
            "{err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // Only the Unix tests below look at the directory listing.
    #[cfg(unix)]
    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    // The file is replaced whole, keeps its mode, stays a symlink when it is
    // one, and leaves no temp file behind.
    #[cfg(unix)]
    #[test]
    fn rewrites_through_a_temp_file() {
        use std::os::unix::fs::PermissionsExt;
        // Its own directory: tests run in parallel, and `dir()` is wiped by the others.
        let dir = std::env::temp_dir().join(format!("shhnote-init-atomic-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let values = generate().unwrap();

        let env = dir.join("env");
        fs::write(&env, "SHH_SECRET_KEY=\n").unwrap();
        fs::set_permissions(&env, fs::Permissions::from_mode(0o640)).unwrap();
        apply(&env, &values).unwrap();
        assert!(fs::read_to_string(&env).unwrap().contains(&values[0].1));
        assert_eq!(
            fs::metadata(&env).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(names(&dir), ["env"], "a temp file was left behind");

        let real = dir.join("real.env");
        let link = dir.join("link.env");
        fs::write(&real, "SHH_DB=sqlite\n").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        apply(&link, &values).unwrap();
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(fs::read_to_string(&real).unwrap().contains(&values[1].1));
        let _ = fs::remove_dir_all(&dir);
    }

    // A write that cannot happen leaves the old file exactly as it was.
    #[cfg(unix)]
    #[test]
    fn a_failed_write_leaves_the_file_alone() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("shhnote-init-ro-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let env = dir.join("env");
        fs::write(&env, "SHH_SECRET_KEY=\n").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        // Root can write anyway; then there is nothing to test.
        let writable = fs::write(dir.join("probe"), b"").is_ok();
        let result = apply(&env, &generate().unwrap());
        let text = fs::read_to_string(&env).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let left = names(&dir);
        let _ = fs::remove_dir_all(&dir);
        if writable {
            return;
        }
        assert!(result.is_err());
        assert_eq!(text, "SHH_SECRET_KEY=\n");
        assert_eq!(left, ["env"]);
    }
}
