//! One sweep point: build a list, sign it as a Status List Token, measure
//! sizes, then time verification through the crate.

use crate::{jws, pattern, reference};
use affinidi_status_list::{
    StatusListReference, TokenStatus, TokenStatusList, VerifiedStatusListToken, VerifyOptions,
    status_list_token_payload,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::time::Instant;

/// Fixed times so the tokens (and sizes) are reproducible.
pub const IAT: i64 = 1_793_000_000;
pub const EXP: i64 = IAT + 86_400;
pub const TTL: u64 = 43_200;
pub const SUB: &str = "https://issuer.example/statuslists/1";

pub fn reference_for(idx: u64) -> StatusListReference {
    StatusListReference {
        idx,
        uri: SUB.to_string(),
    }
}

pub fn build_list(n: u64, revoked: &[u64]) -> TokenStatusList {
    let mut l = TokenStatusList::new(1, n as usize).expect("list");
    for &i in revoked {
        l.set(i as usize, TokenStatus::Invalid).expect("set");
    }
    l
}

pub fn token(list: &TokenStatusList) -> String {
    let payload = status_list_token_payload(SUB, IAT, Some(EXP), Some(TTL), list).expect("payload");
    jws::sign(&payload, &jws::signing_key())
}

/// Verify through the crate and read entry `idx`.
pub fn check(jwt: &str, idx: u64, now: i64) -> Result<TokenStatus, String> {
    let vk = *jws::signing_key().verifying_key();
    let r = reference_for(idx);
    let t = VerifiedStatusListToken::verify(jwt, &r, &VerifyOptions::at(now), |j, _| {
        jws::verify(j, &vk)
    })
    .map_err(|e| e.to_string())?;
    t.status_of(&r).map_err(|e| e.to_string())
}

#[derive(Clone, Debug)]
pub struct Row {
    pub entries: u64,
    pub revocation_pct: f64,
    pub pattern: &'static str,
    pub revoked: u64,
    pub raw_bytes: usize,
    pub zlib_bytes: usize,
    pub lst_chars: usize,
    pub jwt_bytes: usize,
    pub k_list: u64,
    pub k_valid: u64,
    pub reference_agrees: bool,
    pub encode_ms: f64,
    pub verify_ms_median: f64,
    pub verify_ms_p90: f64,
    pub decode_ms_median: f64,
    pub reps: usize,
}

fn median_p90(mut v: Vec<f64>) -> (f64, f64) {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let q = |p: f64| v[((v.len() - 1) as f64 * p).round() as usize];
    (q(0.5), q(0.9))
}

pub fn run(n: u64, rate: f64, p: pattern::Pattern, reps: usize, timing: bool) -> Row {
    let count = pattern::revoked_count(n, rate);
    let seed = n ^ ((rate * 1e6) as u64).rotate_left(32) ^ (p as u64 + 1);
    let rev = pattern::indices(n, count, p, seed);
    let list = build_list(n, &rev);

    let t = Instant::now();
    let enc = list.encode().expect("encode");
    let encode_ms = t.elapsed().as_secs_f64() * 1e3;
    let zlib_bytes = URL_SAFE_NO_PAD.decode(&enc.lst).unwrap().len();
    let jwt = token(&list);

    // Cross-check against the reference decoder: every byte, the population
    // count, and every revoked index.
    let r = reference::decode(1, &enc.lst, 64 << 20).expect("reference decode");
    let ones: u64 = r.iter().map(|b| b.count_ones() as u64).sum();
    let mut agrees = r == list.as_bytes() && ones == count;
    agrees &= rev
        .iter()
        .all(|&i| reference::get(&r, 1, i as usize) == Some(1));

    let (mut verify, mut decode) = (Vec::new(), Vec::new());
    if timing {
        let probe = rev[rev.len() / 2];
        for _ in 0..reps {
            let t = Instant::now();
            let s = check(&jwt, probe, IAT + 60).expect("verify");
            verify.push(t.elapsed().as_secs_f64() * 1e3);
            agrees &= s == TokenStatus::Invalid;
            let t = Instant::now();
            let d = TokenStatusList::decode(&enc).expect("decode");
            decode.push(t.elapsed().as_secs_f64() * 1e3);
            agrees &= d.len() >= n as usize;
        }
        // A valid entry next to nothing revoked reads as VALID.
        if let Some(v) = (0..n).find(|i| rev.binary_search(i).is_err()) {
            agrees &= check(&jwt, v, IAT + 60) == Ok(TokenStatus::Valid);
        }
    } else {
        verify.push(f64::NAN);
        decode.push(f64::NAN);
    }
    let (vm, vp) = median_p90(verify);
    let (dm, _) = median_p90(decode);
    Row {
        entries: n,
        revocation_pct: rate * 100.0,
        pattern: p.name(),
        revoked: count,
        raw_bytes: list.as_bytes().len(),
        zlib_bytes,
        lst_chars: enc.lst.len(),
        jwt_bytes: jwt.len(),
        k_list: n,
        k_valid: n - count,
        reference_agrees: agrees,
        encode_ms,
        verify_ms_median: vm,
        verify_ms_p90: vp,
        decode_ms_median: dm,
        reps,
    }
}
