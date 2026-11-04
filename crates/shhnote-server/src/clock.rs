use std::time::{SystemTime, UNIX_EPOCH};

const DAY: i64 = 86_400;

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// Unix seconds from a civil UTC date and time (Howard Hinnant's algorithm), the inverse of
// `civil`; `None` for a field out of range.
pub(crate) fn from_civil(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
) -> Option<i64> {
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..61).contains(&second)
    {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * DAY + hour * 3600 + minute * 60 + second)
}

// Civil date from unix seconds (Howard Hinnant's algorithm), so no date crate is needed.
pub(crate) fn civil(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(DAY);
    let rem = secs.rem_euclid(DAY);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    let (hh, mm, ss) = (
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    );
    (year, month, day, hh, mm, ss)
}

pub(crate) fn format_date(secs: i64) -> String {
    let (y, m, d, ..) = civil(secs);
    format!("{y:04}-{m:02}-{d:02}")
}

pub(crate) fn format_time(secs: i64) -> String {
    let (y, m, d, hh, mm, _) = civil(secs);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02} UTC")
}

// The timestamp format SigV4 wants, e.g. 20130524T000000Z.
pub(crate) fn amz_date(secs: i64) -> String {
    let (y, m, d, hh, mm, ss) = civil(secs);
    format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_civil_inverts_civil() {
        for secs in [0, 951_782_400, 1_762_268_400, 4_102_444_799, -86_400] {
            let (y, m, d, hh, mm, ss) = civil(secs);
            assert_eq!(
                from_civil(y, m.into(), d.into(), hh.into(), mm.into(), ss.into()),
                Some(secs)
            );
        }
        assert_eq!(from_civil(2026, 13, 1, 0, 0, 0), None);
        assert_eq!(from_civil(2026, 1, 1, 24, 0, 0), None);
    }

    #[test]
    fn formats_dates() {
        assert_eq!(format_date(1_767_225_600), "2026-01-01");
        assert_eq!(format_time(1_793_318_400 + 3661), "2026-10-30 01:01 UTC");
        assert_eq!(amz_date(1_369_353_600), "20130524T000000Z");
    }
}
