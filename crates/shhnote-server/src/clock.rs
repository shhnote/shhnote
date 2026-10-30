use std::time::{SystemTime, UNIX_EPOCH};

const DAY: i64 = 86_400;

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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
    fn formats_dates() {
        assert_eq!(format_date(1_767_225_600), "2026-01-01");
        assert_eq!(format_time(1_793_318_400 + 3661), "2026-10-30 01:01 UTC");
        assert_eq!(amz_date(1_369_353_600), "20130524T000000Z");
    }
}
