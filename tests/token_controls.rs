//! Negative controls through the crate's Status List Token verification, and
//! recorded observations where the crate is stricter or looser than the draft.

use affinidi_status_list::TokenStatus;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use status_list_herd::jws;
use status_list_herd::sweep::{self, EXP, IAT, SUB, TTL};

fn list_payload() -> Value {
    let l = sweep::build_list(1000, &[3, 500]);
    affinidi_status_list::status_list_token_payload(SUB, IAT, Some(EXP), Some(TTL), &l).unwrap()
}

fn signed(p: &Value) -> String {
    jws::sign(p, &jws::signing_key())
}

#[test]
fn valid_token_reads_statuses() {
    let jwt = signed(&list_payload());
    assert_eq!(sweep::check(&jwt, 3, IAT + 60), Ok(TokenStatus::Invalid));
    assert_eq!(sweep::check(&jwt, 4, IAT + 60), Ok(TokenStatus::Valid));
    assert_eq!(sweep::check(&jwt, 500, IAT + 60), Ok(TokenStatus::Invalid));
}

#[test]
fn rejections() {
    let p = list_payload();
    let good = signed(&p);
    let now = IAT + 60;
    // Tampered signature.
    let mut b = good.clone().into_bytes();
    let n = b.len();
    b[n - 5] = if b[n - 5] == b'A' { b'B' } else { b'A' };
    assert!(sweep::check(std::str::from_utf8(&b).unwrap(), 3, now).is_err());
    // Payload swapped under the same signature.
    let mut p2 = p.clone();
    p2["status_list"] =
        serde_json::to_value(sweep::build_list(1000, &[]).encode().unwrap()).unwrap();
    let other = signed(&p2);
    let parts: Vec<&str> = good.split('.').collect();
    let o: Vec<&str> = other.split('.').collect();
    assert!(sweep::check(&format!("{}.{}.{}", parts[0], o[1], parts[2]), 3, now).is_err());
    // Expired, iat in the future.
    assert!(sweep::check(&good, 3, EXP + 120).is_err());
    assert!(sweep::check(&good, 3, IAT - 3600).is_err());
    // Wrong sub.
    let mut q = p.clone();
    q["sub"] = json!("https://issuer.example/statuslists/2");
    assert!(sweep::check(&signed(&q), 3, now).is_err());
    // Wrong typ.
    let h = json!({"alg": "ES256", "typ": "JWT"});
    assert!(sweep::check(&jws::sign_with_header(&h, &p, &jws::signing_key()), 3, now).is_err());
    // bits = 3.
    let mut q = p.clone();
    q["status_list"]["bits"] = json!(3);
    assert!(sweep::check(&signed(&q), 3, now).is_err());
    // Index out of bounds (1000 entries, 1 bit: 125 bytes).
    assert!(sweep::check(&good, 1000, now).is_err());
    // Missing status_list, broken lst.
    let mut q = p.clone();
    q.as_object_mut().unwrap().remove("status_list");
    assert!(sweep::check(&signed(&q), 3, now).is_err());
    let mut q = p.clone();
    q["status_list"]["lst"] = json!("@@@");
    assert!(sweep::check(&signed(&q), 3, now).is_err());
    // Inflation bomb: 17 MiB of zeros, over the crate's 16 MiB default cap.
    let zeros = vec![0u8; 17 << 20];
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    std::io::Write::write_all(&mut e, &zeros).unwrap();
    let z = e.finish().unwrap();
    assert!(z.len() < 64 * 1024);
    let mut q = p.clone();
    q["status_list"]["lst"] = json!(URL_SAFE_NO_PAD.encode(z));
    let err = sweep::check(&signed(&q), 3, now).unwrap_err();
    assert!(err.contains("limit"), "{err}");
}

/// Draft section 5.1: ttl "MUST be a positive number". These record what
/// the crate does; they are observations, asserted so a change is noticed.
#[test]
fn ttl_observations() {
    let now = IAT + 60;
    let with_ttl = |ttl: Value| {
        let mut q = list_payload();
        q["ttl"] = ttl;
        sweep::check(&signed(&q), 3, now)
    };
    // ttl = 0 is not positive, but accepted.
    assert!(with_ttl(json!(0)).is_ok());
    // A positive non-integer number is rejected.
    assert!(with_ttl(json!(43200.5)).is_err());
    // Negative is rejected.
    assert!(with_ttl(json!(-1)).is_err());
    // No exp and no ttl: accepted (both are RECOMMENDED, not REQUIRED).
    let mut q = list_payload();
    q.as_object_mut().unwrap().remove("exp");
    q.as_object_mut().unwrap().remove("ttl");
    assert!(sweep::check(&signed(&q), 3, now).is_ok());
}
