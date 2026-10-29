//! Positive controls: the examples of draft-ietf-oauth-status-list-21
//! (sections 4.1/4.2 and Appendix C), decoded by the crate and by the
//! independent reference decoder.

use affinidi_status_list::{EncodedStatusList, TokenStatusList};
use status_list_herd::reference;

fn enc(bits: u8, lst: &str) -> EncodedStatusList {
    EncodedStatusList {
        bits,
        lst: lst.to_string(),
        aggregation_uri: None,
    }
}

fn vector(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
    .trim()
    .to_string()
}

#[test]
fn section_4_examples() {
    for (bits, lst, bytes) in [
        (1u8, "eNrbuRgAAhcBXQ", vec![0xb9u8, 0xa3]),
        (2, "eNo76fITAAPfAgc", vec![0xc9, 0x44, 0xf9]),
    ] {
        let crate_list = TokenStatusList::decode(&enc(bits, lst)).unwrap();
        assert_eq!(crate_list.as_bytes(), &bytes[..]);
        assert_eq!(reference::decode(bits, lst, 1 << 20).unwrap(), bytes);
    }
    // status[0..16] of the 1-bit example.
    let l = TokenStatusList::decode(&enc(1, "eNrbuRgAAhcBXQ")).unwrap();
    let want = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
    for (i, w) in want.iter().enumerate() {
        assert_eq!(l.get(i).unwrap().value(), *w, "index {i}");
    }
    // status[0..12] of the 2-bit example.
    let l = TokenStatusList::decode(&enc(2, "eNo76fITAAPfAgc")).unwrap();
    let want = [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3];
    for (i, w) in want.iter().enumerate() {
        assert_eq!(l.get(i).unwrap().value(), *w, "index {i}");
    }
}

fn check_appendix(bits: u8, file: &str, set: &[(usize, u8)]) {
    let lst = vector(file);
    let l = TokenStatusList::decode(&enc(bits, &lst)).unwrap();
    let r = reference::decode(bits, &lst, 1 << 24).unwrap();
    assert_eq!(l.as_bytes(), &r[..]);
    assert_eq!(l.len(), 1 << 20, "Appendix C lists have 2^20 entries");
    for i in 0..l.len() {
        let want = set
            .iter()
            .find(|(j, _)| *j == i)
            .map(|(_, v)| *v)
            .unwrap_or(0);
        assert_eq!(l.get(i).unwrap().value(), want, "{file} index {i}");
        assert_eq!(reference::get(&r, bits, i), Some(want));
    }
}

#[test]
fn appendix_c_1bit() {
    let idx = [
        0, 1993, 25460, 159495, 495669, 554353, 645645, 723232, 854545, 934534, 1000345,
    ];
    let set: Vec<_> = idx.iter().map(|&i| (i, 1u8)).collect();
    check_appendix(1, "appendix_c_1bit.lst", &set);
}

#[test]
fn appendix_c_2bit() {
    let set = [
        (0, 1),
        (1993, 2),
        (25460, 1),
        (159495, 3),
        (495669, 1),
        (554353, 1),
        (645645, 2),
        (723232, 1),
        (854545, 1),
        (934534, 2),
        (1000345, 3),
    ];
    check_appendix(2, "appendix_c_2bit.lst", &set);
}

#[test]
fn appendix_c_4bit() {
    let set = [
        (0, 1),
        (1993, 2),
        (35460, 3),
        (459495, 4),
        (595669, 5),
        (754353, 6),
        (845645, 7),
        (923232, 8),
        (924445, 9),
        (934534, 10),
        (1004534, 11),
        (1000345, 12),
        (1030203, 13),
        (1030204, 14),
        (1030205, 15),
    ];
    check_appendix(4, "appendix_c_4bit.lst", &set);
}
