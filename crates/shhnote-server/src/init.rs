use std::{fs, io, path::Path};

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

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Created,
    Filled,
    Appended,
    Kept,
}

// Applies the generated values to the file: a missing file is created (readable by its owner
// only), an empty `KEY=` line is filled in place, a missing key is appended, a set key stays.
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
        write_private(path, &body)?;
        return Ok(values.iter().map(|(k, _)| (*k, Outcome::Created)).collect());
    };
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut outcomes = Vec::new();
    for (key, value) in values {
        let prefix = format!("{key}=");
        let found = lines.iter().position(|line| {
            line.trim_start().starts_with(&prefix) && !line.trim_start().starts_with('#')
        });
        match found {
            Some(i) if lines[i].trim_start()[prefix.len()..].trim().is_empty() => {
                lines[i] = format!("{key}={value}");
                outcomes.push((*key, Outcome::Filled));
            }
            Some(_) => outcomes.push((*key, Outcome::Kept)),
            None => {
                lines.push(format!("{key}={value}"));
                outcomes.push((*key, Outcome::Appended));
            }
        }
    }
    if outcomes.iter().any(|(_, o)| *o != Outcome::Kept) {
        let mut body = lines.join("\n");
        body.push('\n');
        fs::write(path, body)?;
    }
    Ok(outcomes)
}

fn write_private(path: &Path, body: &str) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use io::Write;
    options.open(path)?.write_all(body.as_bytes())
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
}
