use sqlx::{Any, AssertSqlSafe, Row, Transaction, any::AnyRow};

use crate::{Error, Store};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifetime {
    SingleView,
    Ttl,
}

impl Lifetime {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleView => "single_view",
            Self::Ttl => "ttl",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "single_view" => Some(Self::SingleView),
            "ttl" => Some(Self::Ttl),
            _ => None,
        }
    }
}

pub struct NewSecret {
    pub lookup_key: [u8; 32],
    pub burn_key: [u8; 32],
    pub lifetime: Lifetime,
    pub bucket: u64,
    // Exactly one of these is set.
    pub blob: Option<Vec<u8>>,
    pub external_ref: Option<String>,
    pub expires_at: i64,
}

// A blob handed to a client: either the bytes themselves or where to stream them from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    pub blob: Option<Vec<u8>>,
    pub external_ref: Option<String>,
    pub bucket: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TtlServed {
    pub served: Served,
    pub expires_at: i64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Sweep {
    pub expired: u64,
    pub consumed: u64,
}

impl Store {
    // Returns `false` only if a key already exists, which with 256-bit random keys means the
    // client reused a seed.
    pub async fn create(&self, secret: &NewSecret, now: i64) -> Result<bool, Error> {
        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT INTO secrets (lookup_key, burn_key, status, lifetime, bucket, blob, external_ref, expires_at) \
             VALUES ($1, $2, 'active', $3, $4, $5, $6, $7)",
        )
        .bind(secret.lookup_key.to_vec())
        .bind(secret.burn_key.to_vec())
        .bind(secret.lifetime.as_str())
        .bind(secret.bucket as i64)
        .bind(secret.blob.clone())
        .bind(secret.external_ref.clone())
        .bind(secret.expires_at)
        .execute(&mut *tx)
        .await;
        match inserted {
            Ok(_) => {}
            Err(e)
                if e.as_database_error()
                    .is_some_and(|d| d.is_unique_violation()) =>
            {
                return Ok(false);
            }
            Err(e) => return Err(e),
        }
        count(&mut tx, now, Counter::Created, 1).await?;
        tx.commit().await?;
        Ok(true)
    }

    // Single-view reveal. One conditional UPDATE decides the winner under concurrency, and
    // the secret counts as consumed from here on (SPEC §5.1).
    pub async fn claim(
        &self,
        lookup_key: &[u8; 32],
        claim_key: &[u8; 32],
        now: i64,
        window_secs: i64,
    ) -> Result<Option<Served>, Error> {
        let mut tx = self.pool.begin().await?;
        // SECURITY: the lifetime and status predicates are load-bearing. Without `lifetime`
        // this would lock TTL secrets away from other readers; without `status = 'active'`
        // a second caller could take over an existing claim.
        let row = sqlx::query(
            "UPDATE secrets SET status = 'claimed', claim_key = $2, claim_expires_at = $3 \
             WHERE lookup_key = $1 AND lifetime = 'single_view' AND status = 'active' AND expires_at > $4 \
             RETURNING blob, external_ref, bucket",
        )
        .bind(lookup_key.to_vec())
        .bind(claim_key.to_vec())
        .bind(now + window_secs)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;
        let served = match row {
            Some(row) => served(&row)?,
            None => return Ok(None),
        };
        tx.commit().await?;
        Ok(Some(served))
    }

    // The claimant, and only the claimant, may fetch the blob again while the window is open.
    pub async fn redownload(
        &self,
        lookup_key: &[u8; 32],
        claim_key: &[u8; 32],
        now: i64,
    ) -> Result<Option<Served>, Error> {
        // SECURITY: `claim_key` here is the credential; it is a keyed lookup, never compared in code.
        let row = sqlx::query(
            "SELECT blob, external_ref, bucket FROM secrets \
             WHERE lookup_key = $1 AND status = 'claimed' AND claim_key = $2 AND claim_expires_at > $3",
        )
        .bind(lookup_key.to_vec())
        .bind(claim_key.to_vec())
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(served).transpose()
    }

    // Destroys a claimed secret now instead of waiting for the window to lapse.
    pub async fn confirm(
        &self,
        lookup_key: &[u8; 32],
        claim_key: &[u8; 32],
        now: i64,
    ) -> Result<bool, Error> {
        let mut tx = self.pool.begin().await?;
        // SECURITY: must match `status = 'claimed'` with this exact claim key. Widening to
        // `active` would let any link holder destroy a secret without having claimed it.
        let predicate =
            "lookup_key = $1 AND status = 'claimed' AND claim_key = $2 AND claim_expires_at > $3";
        let destroyed =
            destroy(&mut tx, predicate, &[&lookup_key[..], &claim_key[..]], now).await?;
        if destroyed > 0 {
            count(&mut tx, now, Counter::Viewed, destroyed).await?;
        }
        tx.commit().await?;
        Ok(destroyed > 0)
    }

    // TTL reveal is a pure read: no write, no counter, flat latency (SPEC §5.2).
    pub async fn read_ttl(
        &self,
        lookup_key: &[u8; 32],
        now: i64,
    ) -> Result<Option<TtlServed>, Error> {
        // SECURITY: `lifetime = 'ttl'` keeps single-view secrets off the read-only path.
        let row = sqlx::query(
            "SELECT blob, external_ref, bucket, expires_at FROM secrets \
             WHERE lookup_key = $1 AND lifetime = 'ttl' AND status = 'active' AND expires_at > $2",
        )
        .bind(lookup_key.to_vec())
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(TtlServed {
                served: served(&row)?,
                expires_at: row.try_get("expires_at")?,
            })
        })
        .transpose()
    }

    // Resolves the row by the hash of the presented token: a keyed lookup, nothing to time.
    pub async fn burn(&self, burn_key: &[u8; 32], now: i64) -> Result<bool, Error> {
        let mut tx = self.pool.begin().await?;
        // SECURITY: `status = 'active'` only. A claimed secret is already consumed and its
        // claimant may still be downloading; it is destroyed when the window lapses.
        let predicate = "burn_key = $1 AND status = 'active' AND expires_at > $2";
        let destroyed = destroy(&mut tx, predicate, &[&burn_key[..]], now).await?;
        if destroyed > 0 {
            count(&mut tx, now, Counter::Burned, destroyed).await?;
        }
        tx.commit().await?;
        Ok(destroyed > 0)
    }

    // Removes a matching active secret. Returns whether it matched. Nothing per report is
    // stored (D-19): a row keyed by the secret's hash would be a tombstone.
    pub async fn report(&self, lookup_key: &[u8; 32], now: i64) -> Result<bool, Error> {
        let mut tx = self.pool.begin().await?;
        // SECURITY: same narrowness as burn; claimed secrets are handled by the window.
        let predicate = "lookup_key = $1 AND status = 'active' AND expires_at > $2";
        let destroyed = destroy(&mut tx, predicate, &[&lookup_key[..]], now).await?;
        if destroyed > 0 {
            count(&mut tx, now, Counter::Removed, destroyed).await?;
        }
        tx.commit().await?;
        Ok(destroyed > 0)
    }

    // Scheduler duty: expired secrets are destroyed, and lapsed claims are destroyed too,
    // because their bytes were already served (SPEC §5.1 step 4).
    pub async fn sweep(&self, now: i64) -> Result<Sweep, Error> {
        let mut tx = self.pool.begin().await?;
        let consumed = destroy(
            &mut tx,
            "status = 'claimed' AND claim_expires_at <= $1",
            &[],
            now,
        )
        .await?;
        if consumed > 0 {
            count(&mut tx, now, Counter::Viewed, consumed).await?;
        }
        let expired = destroy(&mut tx, "status = 'active' AND expires_at <= $1", &[], now).await?;
        if expired > 0 {
            count(&mut tx, now, Counter::Expired, expired).await?;
        }
        tx.commit().await?;
        Ok(Sweep {
            expired: expired as u64,
            consumed: consumed as u64,
        })
    }

    // External objects still to delete; each row goes once the object is confirmed gone.
    pub async fn pending_deletes(&self) -> Result<Vec<(Vec<u8>, String)>, Error> {
        let rows = sqlx::query(
            "SELECT lookup_key, external_ref FROM secrets WHERE status = 'pending_delete'",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| Ok((row.try_get("lookup_key")?, row.try_get("external_ref")?)))
            .collect()
    }

    // Everything the external tier holds, pending deletes included, against its ceiling.
    pub async fn external_bytes(&self) -> Result<u64, Error> {
        let row = sqlx::query(
            "SELECT CAST(COALESCE(SUM(bucket), 0) AS BIGINT) AS n FROM secrets WHERE external_ref IS NOT NULL",
        )
        .fetch_one(&self.pool)
        .await?;
        let n: i64 = row.try_get("n")?;
        Ok(n.max(0) as u64)
    }

    pub async fn finish_delete(&self, lookup_key: &[u8]) -> Result<(), Error> {
        sqlx::query("DELETE FROM secrets WHERE lookup_key = $1 AND status = 'pending_delete'")
            .bind(lookup_key.to_vec())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// Terminal transition for every row matching `predicate` (which may use $1.. for `binds`
// and the next placeholder for `now`): inline rows are deleted, external rows parked in
// `pending_delete` until the scrubber confirms the object is gone. Returns rows affected.
async fn destroy(
    tx: &mut Transaction<'_, Any>,
    predicate: &str,
    binds: &[&[u8]],
    now: i64,
) -> Result<i64, Error> {
    let delete = format!("DELETE FROM secrets WHERE {predicate} AND external_ref IS NULL");
    let park = format!(
        "UPDATE secrets SET status = 'pending_delete', blob = NULL, claim_key = NULL, claim_expires_at = NULL \
         WHERE {predicate} AND external_ref IS NOT NULL"
    );
    let mut total = 0i64;
    for sql in [delete, park] {
        // `predicate` is always one of the string literals in this file; values go through binds.
        let mut query = sqlx::query(AssertSqlSafe(sql));
        for bind in binds {
            query = query.bind(bind.to_vec());
        }
        total += query.bind(now).execute(&mut **tx).await?.rows_affected() as i64;
    }
    Ok(total)
}

#[derive(Clone, Copy)]
enum Counter {
    Created,
    Viewed,
    Burned,
    Expired,
    Removed,
}

impl Counter {
    // One fixed upsert per counter, so no column name is ever built from input.
    fn daily_sql(self) -> &'static str {
        match self {
            Self::Created => {
                "INSERT INTO stats_daily (day, created) VALUES ($1, $2) ON CONFLICT (day) DO UPDATE SET created = stats_daily.created + $2"
            }
            Self::Viewed => {
                "INSERT INTO stats_daily (day, viewed) VALUES ($1, $2) ON CONFLICT (day) DO UPDATE SET viewed = stats_daily.viewed + $2"
            }
            Self::Burned => {
                "INSERT INTO stats_daily (day, burned) VALUES ($1, $2) ON CONFLICT (day) DO UPDATE SET burned = stats_daily.burned + $2"
            }
            Self::Expired => {
                "INSERT INTO stats_daily (day, expired) VALUES ($1, $2) ON CONFLICT (day) DO UPDATE SET expired = stats_daily.expired + $2"
            }
            Self::Removed => {
                "INSERT INTO stats_daily (day, removed) VALUES ($1, $2) ON CONFLICT (day) DO UPDATE SET removed = stats_daily.removed + $2"
            }
        }
    }
}

// Records a transition in today's bucket, inside the same transaction as the transition.
async fn count(
    tx: &mut Transaction<'_, Any>,
    now: i64,
    counter: Counter,
    by: i64,
) -> Result<(), Error> {
    let day = now - now.rem_euclid(86_400);
    sqlx::query(counter.daily_sql())
        .bind(day)
        .bind(by)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn served(row: &AnyRow) -> Result<Served, Error> {
    Ok(Served {
        blob: row.try_get("blob")?,
        external_ref: row.try_get("external_ref")?,
        bucket: row.try_get::<i64, _>("bucket")? as u64,
    })
}
