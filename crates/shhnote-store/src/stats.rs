use std::collections::BTreeMap;

use sqlx::Row;

use crate::{Error, Store};

const DAY: i64 = 86_400;

// Lifetime totals are the sum of `stats_daily`; `active` is counted live from `secrets`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    pub created: i64,
    pub viewed: i64,
    pub burned: i64,
    pub expired: i64,
    pub removed: i64,
    pub active: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Day {
    pub day: i64,
    pub created: i64,
    pub viewed: i64,
    pub burned: i64,
    pub expired: i64,
    pub removed: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub lookup_key: Vec<u8>,
    pub count: i64,
    pub first_reported_at: i64,
    pub last_reported_at: i64,
    pub matched: bool,
}

impl Store {
    pub async fn stats(&self) -> Result<Stats, Error> {
        let totals = sqlx::query(
            "SELECT COALESCE(SUM(created), 0) AS created, COALESCE(SUM(viewed), 0) AS viewed, \
             COALESCE(SUM(burned), 0) AS burned, COALESCE(SUM(expired), 0) AS expired, \
             COALESCE(SUM(removed), 0) AS removed FROM stats_daily",
        )
        .fetch_one(&self.pool)
        .await?;
        let active = sqlx::query("SELECT COUNT(*) AS n FROM secrets WHERE status = 'active'")
            .fetch_one(&self.pool)
            .await?;
        Ok(Stats {
            created: totals.try_get("created")?,
            viewed: totals.try_get("viewed")?,
            burned: totals.try_get("burned")?,
            expired: totals.try_get("expired")?,
            removed: totals.try_get("removed")?,
            active: active.try_get("n")?,
        })
    }

    pub async fn daily(&self, since: i64) -> Result<Vec<Day>, Error> {
        let rows = sqlx::query(
            "SELECT day, created, viewed, burned, expired, removed FROM stats_daily \
             WHERE day >= $1 ORDER BY day",
        )
        .bind(since)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(day_from_row).collect()
    }

    // Consolidates every bucket older than `before` into its year's 1 January row, so totals
    // survive forever while old days lose their resolution. Returns how many rows were folded.
    pub async fn rollup_daily(&self, before: i64) -> Result<u64, Error> {
        let rows = sqlx::query(
            "SELECT day, created, viewed, burned, expired, removed FROM stats_daily WHERE day < $1",
        )
        .bind(before)
        .fetch_all(&self.pool)
        .await?;
        let old: Vec<Day> = rows.iter().map(day_from_row).collect::<Result<_, _>>()?;

        let mut by_year: BTreeMap<i64, Day> = BTreeMap::new();
        let mut folded = 0u64;
        for day in old {
            let year = year_start(day.day);
            if day.day == year {
                // Already the accumulator row; nothing to move.
                continue;
            }
            let acc = by_year.entry(year).or_insert(Day {
                day: year,
                created: 0,
                viewed: 0,
                burned: 0,
                expired: 0,
                removed: 0,
            });
            acc.created += day.created;
            acc.viewed += day.viewed;
            acc.burned += day.burned;
            acc.expired += day.expired;
            acc.removed += day.removed;
            folded += 1;
        }
        if by_year.is_empty() {
            return Ok(0);
        }

        let mut tx = self.pool.begin().await?;
        for (year, sum) in by_year {
            sqlx::query(
                "INSERT INTO stats_daily (day, created, viewed, burned, expired, removed) \
                 VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT (day) DO UPDATE SET \
                 created = stats_daily.created + $2, viewed = stats_daily.viewed + $3, \
                 burned = stats_daily.burned + $4, expired = stats_daily.expired + $5, \
                 removed = stats_daily.removed + $6",
            )
            .bind(year)
            .bind(sum.created)
            .bind(sum.viewed)
            .bind(sum.burned)
            .bind(sum.expired)
            .bind(sum.removed)
            .execute(&mut *tx)
            .await?;
            // Every day of that year except the accumulator, bounded by `before`.
            sqlx::query("DELETE FROM stats_daily WHERE day > $1 AND day < $2 AND day < $3")
                .bind(year)
                .bind(year_start(year + 366 * DAY))
                .bind(before)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(folded)
    }

    pub async fn reports(&self) -> Result<Vec<Report>, Error> {
        let rows = sqlx::query(
            "SELECT lookup_key, count, first_reported_at, last_reported_at, matched \
             FROM reports ORDER BY last_reported_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(Report {
                    lookup_key: row.try_get("lookup_key")?,
                    count: row.try_get("count")?,
                    first_reported_at: row.try_get("first_reported_at")?,
                    last_reported_at: row.try_get("last_reported_at")?,
                    matched: row.try_get::<i64, _>("matched")? != 0,
                })
            })
            .collect()
    }
}

fn day_from_row(row: &sqlx::any::AnyRow) -> Result<Day, Error> {
    Ok(Day {
        day: row.try_get("day")?,
        created: row.try_get("created")?,
        viewed: row.try_get("viewed")?,
        burned: row.try_get("burned")?,
        expired: row.try_get("expired")?,
        removed: row.try_get("removed")?,
    })
}

// 00:00 UTC on 1 January of the year containing `secs`, without a date library
// (Howard Hinnant's civil-date algorithms).
pub fn year_start(secs: i64) -> i64 {
    let days = secs.div_euclid(DAY);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    days_from_civil(year, 1, 1) * DAY
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn year_start_is_1_january_utc() {
        // 2026-10-30 → 2026-01-01; 2024-02-29 → 2024-01-01; 1 January maps to itself.
        assert_eq!(year_start(1_793_318_400), 1_767_225_600);
        assert_eq!(year_start(1_709_164_800), 1_704_067_200);
        assert_eq!(year_start(1_767_225_600), 1_767_225_600);
        assert_eq!(year_start(0), 0);
    }
}
