//! ES256 compact JWS for Status List Tokens (`typ: statuslist+jwt`).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde_json::{Value, json};

/// Fixed test key (bytes 1..=32 as the scalar); not a real key.
pub fn signing_key() -> SigningKey {
    let mut d = [0u8; 32];
    for (i, b) in d.iter_mut().enumerate() {
        *b = i as u8 + 1;
    }
    SigningKey::from_slice(&d).expect("valid scalar")
}

pub fn sign_with_header(header: &Value, payload: &Value, key: &SigningKey) -> String {
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
    let input = format!("{h}.{p}");
    let sig: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

pub fn sign(payload: &Value, key: &SigningKey) -> String {
    let header = json!({"alg": "ES256", "kid": "herd-1", "typ": "statuslist+jwt"});
    sign_with_header(&header, payload, key)
}

/// Verify the signature and return the payload; used as the crate's callback.
pub fn verify(jwt: &str, key: &VerifyingKey) -> Result<Value, String> {
    let (input, sig) = jwt.rsplit_once('.').ok_or("no signature")?;
    let (h, p) = input.split_once('.').ok_or("no payload")?;
    let header: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if header["alg"] != "ES256" {
        return Err("alg is not ES256".into());
    }
    let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(sig).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    key.verify(input.as_bytes(), &sig)
        .map_err(|_| "bad signature".to_string())?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}
