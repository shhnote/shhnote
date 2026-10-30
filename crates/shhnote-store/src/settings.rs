use std::collections::HashMap;

use sqlx::Row;

use crate::{Error, Store};

// The settings table holds only overrides; defaults live in code (SPEC §7.2).
impl Store {
    pub async fn setting_overrides(&self) -> Result<HashMap<String, String>, Error> {
        let rows = sqlx::query("SELECT key, value FROM settings")
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| Ok((row.try_get("key")?, row.try_get("value")?)))
            .collect()
    }

    pub async fn set_setting(&self, key: &str, value: &str) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES ($1, $2) \
             ON CONFLICT (key) DO UPDATE SET value = $2",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // Removing the row means "back to the default".
    pub async fn clear_setting(&self, key: &str) -> Result<(), Error> {
        sqlx::query("DELETE FROM settings WHERE key = $1")
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
