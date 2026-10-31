use std::{borrow::Cow, fmt::Write as _, path::Path};

use shhnote_core::config::Database;
use sqlx::{
    AnyPool, AssertSqlSafe, SqlStr,
    any::AnyPoolOptions,
    migrate::{Migration, MigrationType, Migrator},
};

mod api_keys;
mod secrets;
mod settings;
mod stats;

pub use api_keys::{ApiKey, Scope};
pub use secrets::{Lifetime, NewSecret, PendingClaim, Served, Sweep, TtlServed};
pub use stats::{Day, Stats};

pub type Error = sqlx::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Sqlite,
    Postgres,
}

// One pool for whichever engine the instance uses. Queries are written once in SQL both
// engines accept; the few places they differ branch on `backend`.
#[derive(Clone)]
pub struct Store {
    pool: AnyPool,
    backend: Backend,
}

impl Store {
    pub async fn connect(database: &Database) -> Result<Self, Error> {
        match database {
            Database::Sqlite { path } => {
                if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                    std::fs::create_dir_all(dir).map_err(Error::Io)?;
                }
                let url = format!("sqlite://{}?mode=rwc", path.display());
                Self::connect_url(&url).await
            }
            Database::Postgres {
                host,
                port,
                database,
                username,
                password,
            } => {
                let url = format!(
                    "postgres://{}:{}@{host}:{port}/{}",
                    percent_encode(username),
                    percent_encode(password.expose()),
                    percent_encode(database)
                );
                Self::connect_url(&url).await
            }
        }
    }

    // Takes a `sqlite://` or `postgres://` URL. Runs the engine's migrations before returning.
    // Is the database there and answering? Used by the health endpoint and `shhnote check`.
    pub async fn ping(&self) -> Result<(), Error> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn connect_url(url: &str) -> Result<Self, Error> {
        sqlx::any::install_default_drivers();
        let backend = if url.starts_with("sqlite:") {
            Backend::Sqlite
        } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
            Backend::Postgres
        } else {
            return Err(Error::Configuration(
                "database URL must be sqlite:// or postgres://".into(),
            ));
        };

        let mut options = AnyPoolOptions::new().max_connections(8);
        if backend == Backend::Sqlite {
            options = options.after_connect(|conn, _| {
                Box::pin(async move {
                    // WAL lets readers and the scheduler overlap; secure_delete overwrites deleted
                    // rows so a destroyed secret's bytes don't linger in free pages, and
                    // journal_size_limit = 0 lets each checkpoint shrink the WAL back to nothing,
                    // so destroyed ciphertext does not linger there either (SPEC §6.1).
                    for pragma in [
                        "PRAGMA journal_mode = WAL",
                        "PRAGMA secure_delete = ON",
                        "PRAGMA synchronous = NORMAL",
                        "PRAGMA busy_timeout = 5000",
                        "PRAGMA journal_size_limit = 0",
                    ] {
                        sqlx::query(pragma).execute(&mut *conn).await?;
                    }
                    Ok(())
                })
            });
        }
        let pool = options.connect(url).await?;
        migrator(backend).run(&pool).await?;
        Ok(Self { pool, backend })
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    // Folds the WAL into the main file and truncates it, so the frames of rows destroyed
    // since the last checkpoint are gone from disk (SPEC §6.1). SQLite only; a checkpoint
    // that cannot complete because a reader is mid-transaction just waits for the next one.
    pub async fn checkpoint(&self) -> Result<(), Error> {
        if self.backend == Backend::Sqlite {
            sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }
}

// One table per migration, both engines side by side. Add new entries at the end; never edit
// an entry once it has been committed.
const MIGRATIONS: &[(i64, &str, &str, &str)] = &[
    (
        1,
        "secrets",
        include_str!("../../../migrations/sqlite/0001_secrets.sql"),
        include_str!("../../../migrations/postgres/0001_secrets.sql"),
    ),
    (
        2,
        "stats_daily",
        include_str!("../../../migrations/sqlite/0002_stats_daily.sql"),
        include_str!("../../../migrations/postgres/0002_stats_daily.sql"),
    ),
    (
        3,
        "settings",
        include_str!("../../../migrations/sqlite/0003_settings.sql"),
        include_str!("../../../migrations/postgres/0003_settings.sql"),
    ),
    (
        4,
        "api_keys",
        include_str!("../../../migrations/sqlite/0004_api_keys.sql"),
        include_str!("../../../migrations/postgres/0004_api_keys.sql"),
    ),
    (
        5,
        "api_key_sessions",
        include_str!("../../../migrations/sqlite/0005_api_key_sessions.sql"),
        include_str!("../../../migrations/postgres/0005_api_key_sessions.sql"),
    ),
    (
        6,
        "admin_state",
        include_str!("../../../migrations/sqlite/0006_admin_state.sql"),
        include_str!("../../../migrations/postgres/0006_admin_state.sql"),
    ),
];

fn migrator(backend: Backend) -> Migrator {
    let migrations = MIGRATIONS
        .iter()
        .map(|&(version, name, sqlite, postgres)| {
            let sql = match backend {
                Backend::Sqlite => sqlite,
                Backend::Postgres => postgres,
            };
            Migration::new(
                version,
                name.into(),
                MigrationType::Simple,
                SqlStr::from_static(sql),
                false,
            )
        })
        .collect();
    Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    }
}

// Enough escaping for a URL userinfo or path segment; passwords often contain `@`, `/` or `#`.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(byte as char);
        } else {
            write!(out, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    out
}

pub fn sqlite_path_for_tests(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("shhnote-tests");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join(format!("{name}-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(Path::new(&format!("{}-wal", path.display())));
    path
}

impl Store {
    // Test helper: empties every table and resets the counters. Never called by the server.
    pub async fn wipe_for_tests(&self) -> Result<(), Error> {
        for table in [
            "secrets",
            "stats_daily",
            "settings",
            "api_keys",
            "admin_state",
        ] {
            // Table names come from the fixed list above, never from input.
            sqlx::query(AssertSqlSafe(format!("DELETE FROM {table}")))
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_awkward_passwords() {
        assert_eq!(percent_encode("p@ss/w#rd ü"), "p%40ss%2Fw%23rd%20%C3%BC");
        assert_eq!(percent_encode("plain-ok_1.2~"), "plain-ok_1.2~");
    }
}
