//! Sweep harness for IETF Token Status Lists (draft-ietf-oauth-status-list-21)
//! built on the `affinidi-status-list` crate.
//!
//! * [`reference`]: an independent decoder written from section 4 of the
//!   draft, used to cross-check the crate.
//! * [`pattern`]: deterministic revocation patterns.
//! * [`jws`]: ES256 compact signing and verification for Status List Tokens.
//! * [`freshness`]: a sampled model of revocation visibility vs `ttl`.

pub mod freshness;
pub mod jws;
pub mod pattern;
pub mod reference;
pub mod sweep;

/// SplitMix64: small deterministic PRNG so every run sees the same lists.
#[derive(Clone, Debug)]
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    /// Uniform in `0..n` (n > 0), rejection sampled.
    pub fn below(&mut self, n: u64) -> u64 {
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let v = self.next_u64();
            if v < zone {
                return v % n;
            }
        }
    }
    /// Uniform in [0, 1).
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}
