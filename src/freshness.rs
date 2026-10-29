//! How long a revocation stays invisible to a Relying Party, as a function of
//! the Status Issuer's update interval and the `ttl` claim.
//!
//! Model (draft section 13.7, RECOMMENDED caching option): the issuer signs a
//! new Status List Token every `update_s` seconds; a revocation at time `t`
//! first appears in the next token. The RP re-fetches `ttl` seconds after its
//! previous fetch, at a random phase. Staleness = the first moment the RP
//! holds a token with the revocation, minus `t`. Network and signing delays
//! are zero. Values are sampled, not derived in closed form; the bound
//! `staleness <= update_s + ttl` is checked in the tests.

use crate::Rng;

#[derive(Clone, Debug)]
pub struct Stats {
    pub mean_s: f64,
    pub p50_s: f64,
    pub p95_s: f64,
    pub max_s: f64,
    pub fetches_per_day: f64,
}

/// Staleness of one revocation at `t`, RP fetching at `phase + k * ttl`.
pub fn staleness(update_s: f64, ttl_s: f64, t: f64, phase: f64) -> f64 {
    let publish = (t / update_s).floor() * update_s + update_s;
    let k = ((publish - phase) / ttl_s).ceil().max(0.0);
    phase + k * ttl_s - t
}

pub fn simulate(update_s: f64, ttl_s: f64, samples: usize, seed: u64) -> Stats {
    let mut rng = Rng(seed);
    let horizon = 10.0 * update_s.max(ttl_s);
    let mut v: Vec<f64> = (0..samples)
        .map(|_| {
            let t = horizon + rng.unit() * horizon;
            let phase = rng.unit() * ttl_s;
            staleness(update_s, ttl_s, t, phase)
        })
        .collect();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let q = |p: f64| v[((v.len() - 1) as f64 * p).round() as usize];
    Stats {
        mean_s: v.iter().sum::<f64>() / v.len() as f64,
        p50_s: q(0.5),
        p95_s: q(0.95),
        max_s: *v.last().unwrap(),
        fetches_per_day: 86400.0 / ttl_s,
    }
}
