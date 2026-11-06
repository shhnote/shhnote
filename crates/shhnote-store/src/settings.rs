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

#[cfg(test)]
mod tests {
    use super::*;

    // Values stored before sizes took a unit are bytes; migration 7 appends the unit so they
    // keep their meaning. Replayed here against old-style rows, since a fresh database has
    // already run it.
    #[tokio::test]
    async fn size_units_migration_rewrites_old_values() {
        let path = crate::sqlite_path_for_tests("size-units-migration");
        let store = Store::connect_url(&format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .unwrap();
        for (key, value) in [
            ("padding_min", "131072"),
            ("padding_ladder", "65536, 1048576,4194304"),
            ("text_max_bytes", "65536"),
            ("site_name", "shh"),
        ] {
            store.set_setting(key, value).await.unwrap();
        }
        for statement in include_str!("../../../migrations/sqlite/0007_size_units.sql")
            .lines()
            .filter(|l| l.starts_with("UPDATE"))
        {
            sqlx::query(statement).execute(&store.pool).await.unwrap();
        }
        let all = store.setting_overrides().await.unwrap();
        assert_eq!(all["padding_min"], "131072B");
        assert_eq!(all["padding_ladder"], "65536B,1048576B,4194304B");
        assert_eq!(all["text_max_bytes"], "65536B");
        assert_eq!(all["site_name"], "shh");
    }
}
