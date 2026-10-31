use sqlx::Row;

use crate::{Error, Store};

// Operator credentials (SPEC §8). The key itself is shown once and stored only as a hash;
// timestamps are fine here because these are not secrets. Last use is kept to the UTC day
// (`last_used_on`, unix seconds at 00:00 UTC) so it cannot be joined with a secret's expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKey {
    pub key_hash: Vec<u8>,
    pub name: String,
    pub scope: Scope,
    pub created_at: i64,
    pub last_used_on: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Admin,
    User,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Self::Admin),
            "user" => Some(Self::User),
            _ => None,
        }
    }
}

impl Store {
    pub async fn create_api_key(
        &self,
        key_hash: &[u8; 32],
        name: &str,
        scope: Scope,
        now: i64,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO api_keys (key_hash, name, scopes, created_at, last_used_on) VALUES ($1, $2, $3, $4, NULL)",
        )
        .bind(key_hash.to_vec())
        .bind(name)
        .bind(scope.as_str())
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // A keyed lookup by the hash of the presented key: nothing to compare, nothing to time.
    pub async fn find_api_key(&self, key_hash: &[u8; 32]) -> Result<Option<ApiKey>, Error> {
        let row = sqlx::query(
            "SELECT key_hash, name, scopes, created_at, last_used_on FROM api_keys WHERE key_hash = $1",
        )
        .bind(key_hash.to_vec())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| api_key(&row)).transpose()
    }

    // Records the UTC day of use, never the time (D-23).
    pub async fn touch_api_key(&self, key_hash: &[u8; 32], now: i64) -> Result<(), Error> {
        let day = now - now.rem_euclid(86_400);
        sqlx::query("UPDATE api_keys SET last_used_on = $2 WHERE key_hash = $1")
            .bind(key_hash.to_vec())
            .bind(day)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_api_keys(&self) -> Result<Vec<ApiKey>, Error> {
        let rows = sqlx::query(
            "SELECT key_hash, name, scopes, created_at, last_used_on FROM api_keys ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(api_key).collect()
    }

    pub async fn delete_api_key(&self, key_hash: &[u8]) -> Result<bool, Error> {
        let result = sqlx::query("DELETE FROM api_keys WHERE key_hash = $1")
            .bind(key_hash.to_vec())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn admin_key_count(&self) -> Result<i64, Error> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM api_keys WHERE scopes = 'admin'")
            .fetch_one(&self.pool)
            .await?;
        row.try_get("n")
    }

    // Lockout recovery (`shhnote reset-admin`): with no admin keys left, the bootstrap token works again.
    pub async fn delete_admin_keys(&self) -> Result<u64, Error> {
        let result = sqlx::query("DELETE FROM api_keys WHERE scopes = 'admin'")
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

fn api_key(row: &sqlx::any::AnyRow) -> Result<ApiKey, Error> {
    let scopes: String = row.try_get("scopes")?;
    Ok(ApiKey {
        key_hash: row.try_get("key_hash")?,
        name: row.try_get("name")?,
        scope: Scope::parse(&scopes).unwrap_or(Scope::User),
        created_at: row.try_get("created_at")?,
        last_used_on: row.try_get("last_used_on")?,
    })
}
