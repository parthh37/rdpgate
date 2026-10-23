//! Slows down sources that fail authentication. The limiter only ever delays
//! or refuses, it never grants anything, so a bug here cannot open the door.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// After this much quiet, a source's failure count starts over.
const FORGET: Duration = Duration::from_secs(24 * 3600);
/// Bounds memory if a botnet sprays from many addresses.
const MAX_ENTRIES: usize = 100_000;

#[derive(Default)]
pub struct Limiter {
    entries: Mutex<HashMap<String, Entry>>,
}

struct Entry {
    failures: u32,
    last_failure: Instant,
    banned_until: Option<Instant>,
}

impl Limiter {
    /// Whether `key` may attempt authentication right now.
    pub fn allowed(&self, key: &str) -> bool {
        let m = self.entries.lock().unwrap();
        match m.get(key).and_then(|e| e.banned_until) {
            Some(until) => Instant::now() >= until,
            None => true,
        }
    }

    /// Records a failure; returns how long `key` is now blocked.
    pub fn fail(&self, key: &str) -> Duration {
        let mut m = self.entries.lock().unwrap();
        let now = Instant::now();
        if !m.contains_key(key) && m.len() >= MAX_ENTRIES {
            prune(&mut m, now);
            // Still full: forget the quietest source that isn't banned, so
            // new attackers are still tracked.
            if m.len() >= MAX_ENTRIES
                && let Some(oldest) = m
                    .iter()
                    .filter(|(_, e)| e.banned_until.is_none_or(|u| now >= u))
                    .min_by_key(|(_, e)| e.last_failure)
                    .map(|(k, _)| k.clone())
            {
                m.remove(&oldest);
            }
            if m.len() >= MAX_ENTRIES {
                return Duration::ZERO;
            }
        }
        let e = m.entry(key.to_string()).or_insert(Entry { failures: 0, last_failure: now, banned_until: None });
        if now.duration_since(e.last_failure) > FORGET {
            e.failures = 0;
        }
        e.failures += 1;
        e.last_failure = now;
        let d = penalty(e.failures);
        if !d.is_zero() {
            e.banned_until = Some(now + d);
        }
        d
    }

    /// Clears `key` after a successful sign-in.
    pub fn reset(&self, key: &str) {
        self.entries.lock().unwrap().remove(key);
    }

    pub fn prune(&self) {
        prune(&mut self.entries.lock().unwrap(), Instant::now());
    }
}

fn prune(m: &mut HashMap<String, Entry>, now: Instant) {
    m.retain(|_, e| e.banned_until.is_some_and(|u| now < u) || now.duration_since(e.last_failure) <= FORGET);
}

/// How long to block a source after its Nth failure in a row (`failures`
/// starts at 1). `Duration::ZERO` means "not blocked yet".
///
/// Things to weigh:
/// - Desktop sign-in needs a valid device signature before a 6-digit code is
///   even checked, so strangers cannot brute-force your codes that way. Most
///   failures you will see are internet scanners, or you mistyping a code.
/// - Browser sign-in failures are counted too (bad passkey responses, expired
///   enrollment links).
/// - Blocks are per source address (per /64 for IPv6). Too harsh, and someone
///   sharing your hotel Wi-Fi can lock *you* out for hours; too soft, and the
///   log just gets noisier.
/// - A blocked source gets no reply at all, which also hides the service.
pub fn penalty(failures: u32) -> Duration {
    // TODO(you): replace this placeholder with your own policy (5-10 lines).
    // Ideas: a free allowance then exponential backoff (1m, 2m, 4m … capped),
    // or a flat ban after N failures. See the notes above for the trade-offs.
    if failures < 5 { Duration::ZERO } else { Duration::from_secs(15 * 60) }
}

/// Groups addresses one attacker controls: one key per IPv4 address, one per
/// IPv6 /64 (the smallest block an ISP normally hands a customer).
pub fn source_key(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_repeated_failures_and_resets() {
        let l = Limiter::default();
        let mut blocked = false;
        for _ in 0..50 {
            if !l.fail("1.2.3.4").is_zero() {
                blocked = true;
                break;
            }
        }
        assert!(blocked, "penalty() must eventually block a source");
        assert!(!l.allowed("1.2.3.4"));
        assert!(l.allowed("5.6.7.8"));
        l.reset("1.2.3.4");
        assert!(l.allowed("1.2.3.4"));
    }

    #[test]
    fn ipv6_groups_by_slash_64() {
        let a = source_key("2001:db8:1:2:aaaa::1".parse().unwrap());
        let b = source_key("2001:db8:1:2:bbbb::9".parse().unwrap());
        assert_eq!(a, b);
        assert_eq!(source_key("::ffff:1.2.3.4".parse().unwrap()), "1.2.3.4");
    }
}
