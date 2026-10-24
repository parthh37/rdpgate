//! Decides when to tell you about the service: once it has stayed down for
//! a while (a restart for a changed setting or an update takes a few
//! seconds and isn't worth a notification), and again when it's back.

use crate::icon::Level;
use std::time::{Duration, Instant};

/// How long the service must stay stopped before you're told.
pub const DOWN_FOR: Duration = Duration::from_secs(15);

#[derive(Debug, PartialEq, Eq)]
pub enum Note {
    /// It stopped and hasn't come back.
    Down,
    /// It's running again after a `Down`.
    Up,
}

#[derive(Default)]
pub struct Watch {
    down_since: Option<Instant>,
    told: bool,
}

impl Watch {
    /// Takes the service's state at `now`; returns what to tell, if anything.
    pub fn update(&mut self, level: Level, now: Instant) -> Option<Note> {
        match level {
            Level::Good => {
                self.down_since = None;
                std::mem::take(&mut self.told).then_some(Note::Up)
            }
            Level::Bad => {
                let since = *self.down_since.get_or_insert(now);
                if !self.told && now.duration_since(since) >= DOWN_FOR {
                    self.told = true;
                    return Some(Note::Down);
                }
                None
            }
            // Starting, stopping or unknown: wait to see where it settles.
            Level::Busy | Level::Unknown => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TICK: Duration = Duration::from_secs(3);

    /// Feeds one state per tick; returns the notes, with the tick they came at.
    fn run(states: &[Level]) -> Vec<(usize, Note)> {
        let (mut w, start) = (Watch::default(), Instant::now());
        states.iter().enumerate().filter_map(|(i, &l)| w.update(l, start + TICK * i as u32).map(|n| (i, n))).collect()
    }

    #[test]
    fn a_restart_is_not_worth_a_notification() {
        use Level::*;
        assert!(run(&[Good, Busy, Bad, Bad, Busy, Good, Good]).is_empty());
    }

    #[test]
    fn staying_down_is_told_once_then_coming_back() {
        use Level::*;
        let notes = run(&[Good, Bad, Bad, Bad, Bad, Bad, Bad, Bad, Bad, Busy, Bad, Good, Good]);
        assert_eq!(notes, vec![(6, Note::Down), (11, Note::Up)]);
    }

    #[test]
    fn down_when_signing_in_is_told_too() {
        use Level::*;
        assert_eq!(run(&[Bad, Bad, Bad, Bad, Bad, Bad]), vec![(5, Note::Down)]);
    }

    #[test]
    fn starting_attempts_do_not_reset_the_wait() {
        use Level::*;
        // A service that keeps failing to start is still down.
        let notes = run(&[Bad, Busy, Bad, Busy, Bad, Busy, Bad]);
        assert_eq!(notes, vec![(6, Note::Down)]);
    }
}
