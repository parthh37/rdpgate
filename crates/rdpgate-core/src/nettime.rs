//! The real time, from the internet, for when this computer's clock is wrong.
//!
//! Signed requests, one-time codes and the beacon all depend on the clock.
//! A PC whose clock is off by hours (a virtual machine whose hardware clock
//! is read in the wrong time zone at boot, a dead CMOS battery, Windows Time
//! not running) would refuse every sign-in. So the time is also read from the
//! `Date` header of a few well-known HTTPS sites: TLS proves the answers are
//! genuine, and at least two of them must agree.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Asked in order until two agree.
pub const SOURCES: &[&str] =
    &["https://www.google.com", "https://www.cloudflare.com", "https://api.github.com", "https://www.microsoft.com"];
/// Two answers this close (in seconds) agree. `Date` has 1-second resolution
/// and some CDNs are a few seconds apart.
const AGREE: i64 = 10;

fn system_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// What [`measure`] found.
#[derive(Debug, Clone, Copy)]
pub struct Measured {
    /// The real Unix time, in seconds, at `at`.
    pub unix: i64,
    pub at: Instant,
    /// Seconds to add to this computer's clock to get the real time.
    pub offset: i64,
}

/// Reads the real time from [`SOURCES`]. Blocking: run it off async threads.
pub fn measure() -> Result<Measured, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(8)))
        .http_status_as_error(false)
        .user_agent(concat!("rdpgate/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let mut seen: Vec<Measured> = Vec::new();
    let mut errors = Vec::new();
    for url in SOURCES {
        let (before, sys_before) = (Instant::now(), system_secs());
        match agent.head(*url).call() {
            Ok(resp) => {
                let rtt = before.elapsed();
                let Some(t) = resp.headers().get("date").and_then(|v| v.to_str().ok()).and_then(parse_http_date) else {
                    errors.push(format!("{url}: no Date header"));
                    continue;
                };
                // The server stamped its reply about halfway through.
                let at = before + rtt / 2;
                let local = sys_before + rtt.as_secs_f64() / 2.0;
                seen.push(Measured { unix: t, at, offset: t - local.round() as i64 });
            }
            Err(e) => errors.push(format!("{url}: {e}")),
        }
        if let Some(m) = agreed(&seen) {
            return Ok(m);
        }
    }
    if errors.is_empty() {
        errors.push("the time servers disagree".into());
    }
    Err(format!("could not read the time from the internet ({})", errors.join("; ")))
}

/// The first two answers that agree.
fn agreed(seen: &[Measured]) -> Option<Measured> {
    for (i, a) in seen.iter().enumerate() {
        if let Some(b) = seen[i + 1..].iter().find(|b| (a.offset - b.offset).abs() <= AGREE) {
            // The later answer, with the two offsets averaged.
            return Some(Measured { offset: (a.offset + b.offset) / 2, ..*b });
        }
    }
    None
}

/// Parses an HTTP date (`Wed, 04 Nov 2026 04:58:06 GMT`) into Unix seconds.
pub fn parse_http_date(s: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let mut it = s.split_whitespace();
    let _weekday = it.next()?;
    let day: i64 = it.next()?.parse().ok()?;
    let month = it.next()?;
    let month = MONTHS.iter().position(|m| m.eq_ignore_ascii_case(month))? as i64 + 1;
    let year: i64 = it.next()?.parse().ok()?;
    let mut hms = it.next()?.split(':').map(|p| p.parse::<i64>().ok());
    let (h, m, sec) = (hms.next()??, hms.next()??, hms.next()??);
    if it.next()? != "GMT" || !(1..=31).contains(&day) || !(0..24).contains(&h) || !(0..60).contains(&m) || !(0..=60).contains(&sec) {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86400 + h * 3600 + m * 60 + sec)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_dates() {
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(parse_http_date("Wed, 04 Nov 2026 04:58:06 GMT"), Some(1_793_768_286));
        assert_eq!(parse_http_date("Tue, 29 Feb 2028 23:59:59 GMT"), Some(1_835_481_599));
        assert_eq!(parse_http_date("Wed, 04 Nov 2026 04:58:06 PST"), None);
        assert_eq!(parse_http_date("Wed, 04 Foo 2026 04:58:06 GMT"), None);
        assert_eq!(parse_http_date("nonsense"), None);
    }

    #[test]
    fn needs_two_answers_that_agree() {
        let at = Instant::now();
        let m = |offset| Measured { unix: 0, at, offset };
        assert!(agreed(&[m(19_800)]).is_none(), "one answer isn't enough");
        assert!(agreed(&[m(19_800), m(0)]).is_none(), "two that disagree aren't either");
        assert_eq!(agreed(&[m(0), m(19_800), m(19_806)]).unwrap().offset, 19_803);
    }
}
