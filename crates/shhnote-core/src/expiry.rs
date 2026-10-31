// Expiry values are stored rounded up (SPEC §3, D-18): an exact `now + ttl` would be a
// creation timestamp, and an exact `now + window` a reveal timestamp, both to the second.

// The grid an expiry lands on, by TTL: five minutes for short ones, an hour up to three days,
// a day beyond that. Coarser than the hour the recipient sees, never finer.
pub fn grid(ttl_seconds: i64) -> i64 {
    if ttl_seconds < 3600 {
        300
    } else if ttl_seconds < 3 * 86_400 {
        3600
    } else {
        86_400
    }
}

// `now + ttl`, rounded up to the grid. The creator gets at least the TTL asked for.
pub fn expires_at(now: i64, ttl_seconds: i64) -> i64 {
    round_up(now.saturating_add(ttl_seconds), grid(ttl_seconds))
}

// `now + window`, rounded up to the next minute.
pub fn claim_expires_at(now: i64, window_seconds: i64) -> i64 {
    round_up(now.saturating_add(window_seconds), 60)
}

fn round_up(value: i64, step: i64) -> i64 {
    value
        .checked_add(step - 1)
        .map_or(i64::MAX, |v| v - v.rem_euclid(step))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_up_to_the_grid_and_never_below_the_ttl() {
        for (ttl, step) in [
            (60, 300),
            (900, 300),
            (3599, 300),
            (3600, 3600),
            (86_400, 3600),
            (259_199, 3600),
            (259_200, 86_400),
            (1_209_600, 86_400),
        ] {
            for now in [0, 1, 1_800_012_345, 1_800_012_345 + step - 1] {
                let e = expires_at(now, ttl);
                assert_eq!(e % step, 0, "ttl {ttl} now {now}");
                assert!(e >= now + ttl, "ttl {ttl} now {now}");
                assert!(e < now + ttl + step, "ttl {ttl} now {now}");
            }
        }
        assert_eq!(expires_at(1_800_012_345, 3 * 86_400), 1_800_316_800);
    }

    #[test]
    fn claim_expiry_is_a_whole_minute() {
        assert_eq!(claim_expires_at(1_000_000, 900), 1_000_920);
        assert_eq!(claim_expires_at(1_000_020, 900), 1_000_920);
        assert_eq!(claim_expires_at(0, 60), 60);
        assert_eq!(claim_expires_at(i64::MAX - 10, 900), i64::MAX);
    }
}
