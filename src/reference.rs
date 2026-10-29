//! Independent decoder from draft-ietf-oauth-status-list-21 sections 4.1 and
//! 4.2: base64url (no padding) of a ZLIB stream; entries `bits` wide packed
//! from the least significant bit of each byte.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::io::Read;

pub fn decode(bits: u8, lst: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    if ![1, 2, 4, 8].contains(&bits) {
        return Err(format!("bits {bits} not allowed"));
    }
    let z = URL_SAFE_NO_PAD
        .decode(lst)
        .map_err(|e| format!("base64url: {e}"))?;
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(&z[..])
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| format!("zlib: {e}"))?;
    if out.len() > max_bytes {
        return Err("inflates past the limit".into());
    }
    Ok(out)
}

/// Status of entry `idx`, or None past the end.
pub fn get(bytes: &[u8], bits: u8, idx: usize) -> Option<u8> {
    let per = 8 / bits as usize;
    let b = *bytes.get(idx / per)?;
    let shift = (idx % per) * bits as usize;
    Some((b >> shift) & (((1u16 << bits) - 1) as u8))
}
