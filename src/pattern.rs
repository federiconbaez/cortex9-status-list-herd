//! Revocation patterns. `Random`: distinct uniformly random indices.
//! `Clustered`: runs of [`RUN`] consecutive indices at random run starts
//! (for example a batch revoked together).

use crate::Rng;
use std::collections::HashSet;

pub const RUN: u64 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pattern {
    Random,
    Clustered,
}

impl Pattern {
    pub fn name(&self) -> &'static str {
        match self {
            Pattern::Random => "random",
            Pattern::Clustered => "clustered",
        }
    }
}

/// Revoked entries for `n` entries at `rate` (a fraction), at least 1.
pub fn revoked_count(n: u64, rate: f64) -> u64 {
    ((n as f64 * rate).round() as u64).clamp(1, n)
}

/// Sorted distinct revoked indices.
pub fn indices(n: u64, count: u64, p: Pattern, seed: u64) -> Vec<u64> {
    let mut rng = Rng(seed);
    let mut set: HashSet<u64> = HashSet::with_capacity(count as usize);
    match p {
        Pattern::Random => {
            // Floyd's algorithm: exactly `count` distinct values.
            for j in (n - count)..n {
                let t = rng.below(j + 1);
                if !set.insert(t) {
                    set.insert(j);
                }
            }
        }
        Pattern::Clustered => {
            let runs = n.div_ceil(RUN);
            while (set.len() as u64) < count {
                let start = rng.below(runs) * RUN;
                for i in start..(start + RUN).min(n) {
                    if (set.len() as u64) == count {
                        break;
                    }
                    set.insert(i);
                }
            }
        }
    }
    let mut v: Vec<u64> = set.into_iter().collect();
    v.sort_unstable();
    v
}
