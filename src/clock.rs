use std::time::{Instant, SystemTime, UNIX_EPOCH};

mod private {
    pub trait Sealed {}
}

/// Clock implementations are sealed so a deployment cannot inject caller time.
pub trait TrustedClock: private::Sealed {
    fn now_epoch_s(&self) -> i64;
    fn healthy(&self) -> bool;
}

#[derive(Clone, Debug)]
pub struct SystemTrustedClock {
    epoch_anchor_s: i64,
    monotonic_anchor: Instant,
}

impl SystemTrustedClock {
    /// Anchors wall time once and advances it only from the monotonic clock.
    ///
    /// # Errors
    ///
    /// Fails when system time cannot be represented safely.
    pub fn new() -> Result<Self, crate::BridgeError> {
        let epoch_anchor_s = system_epoch_s()?;
        Ok(Self {
            epoch_anchor_s,
            monotonic_anchor: Instant::now(),
        })
    }
}

impl private::Sealed for SystemTrustedClock {}

impl TrustedClock for SystemTrustedClock {
    fn now_epoch_s(&self) -> i64 {
        self.epoch_anchor_s.saturating_add(
            i64::try_from(self.monotonic_anchor.elapsed().as_secs()).unwrap_or(i64::MAX),
        )
    }

    fn healthy(&self) -> bool {
        system_epoch_s().is_ok_and(|wall| wall.abs_diff(self.now_epoch_s()) <= 300)
    }
}

fn system_epoch_s() -> Result<i64, crate::BridgeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| crate::BridgeError::Time)
        .and_then(|value| i64::try_from(value.as_secs()).map_err(|_| crate::BridgeError::Time))
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct TestClock {
    now_epoch_s: i64,
    healthy: bool,
}

#[cfg(test)]
impl TestClock {
    pub(crate) const fn new(now_epoch_s: i64) -> Self {
        Self {
            now_epoch_s,
            healthy: true,
        }
    }

    pub(crate) const fn set(&mut self, now_epoch_s: i64) {
        if now_epoch_s < self.now_epoch_s {
            self.healthy = false;
        }
        self.now_epoch_s = now_epoch_s;
    }
}

#[cfg(test)]
impl private::Sealed for TestClock {}

#[cfg(test)]
impl TrustedClock for TestClock {
    fn now_epoch_s(&self) -> i64 {
        self.now_epoch_s
    }

    fn healthy(&self) -> bool {
        self.healthy
    }
}
