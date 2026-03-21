use std::time::{Duration, Instant};

use dashmap::DashMap;
use uuid::Uuid;

const TTL: Duration = Duration::from_secs(900); // 15 min

/// in-memory blocklist for force-revoked jtis
pub struct Blocklist {
    entries: DashMap<Uuid, Instant>,
}

impl Default for Blocklist {
    fn default() -> Self {
        Self::new()
    }
}

impl Blocklist {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// adds a jti to the blocklist
    pub fn add(&self, jti: Uuid) {
        self.entries.insert(jti, Instant::now());
    }

    /// checks if a jti is blocked
    pub fn contains(&self, jti: &Uuid) -> bool {
        if let Some(entry) = self.entries.get(jti) {
            if entry.elapsed() < TTL {
                return true;
            }
            drop(entry);
            self.entries.remove(jti);
        }
        false
    }

    /// returns all active (non-expired) jtis
    pub fn list(&self) -> Vec<Uuid> {
        self.entries.retain(|_, added| added.elapsed() < TTL);
        self.entries.iter().map(|e| *e.key()).collect()
    }
}
