use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// simple sliding-window rate limiter per ip
pub struct RateLimiter {
    limits: DashMap<IpAddr, Vec<Instant>>,
    max: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max: usize, window: Duration) -> Self {
        Self {
            limits: DashMap::new(),
            max,
            window,
        }
    }

    /// returns true if the request is allowed, false if rate limited
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut entry = self.limits.entry(ip).or_default();
        entry.retain(|t| now.duration_since(*t) < self.window);

        if entry.len() >= self.max {
            return false;
        }

        entry.push(now);
        true
    }
}
