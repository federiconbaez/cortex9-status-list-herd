use affinidi_status_list::{TokenStatus, TokenStatusList};
use status_list_herd::{freshness, pattern, reference};

#[test]
fn patterns_have_exact_counts() {
    for p in [pattern::Pattern::Random, pattern::Pattern::Clustered] {
        for (n, rate) in [
            (1000u64, 0.001),
            (1000, 0.1),
            (100_000, 0.05),
            (1_000_003, 0.02),
        ] {
            let c = pattern::revoked_count(n, rate);
            let v = pattern::indices(n, c, p, 7);
            assert_eq!(v.len() as u64, c);
            assert!(v.windows(2).all(|w| w[0] < w[1]));
            assert!(*v.last().unwrap() < n);
            assert_eq!(v, pattern::indices(n, c, p, 7), "deterministic");
        }
    }
    assert_eq!(pattern::revoked_count(1000, 0.001), 1);
    assert_eq!(pattern::revoked_count(10, 0.001), 1);
}

#[test]
fn clustered_is_runs() {
    let v = pattern::indices(100_000, 2560, pattern::Pattern::Clustered, 3);
    let starts = v.iter().filter(|&&i| i % pattern::RUN == 0).count();
    assert_eq!(starts, 10);
}

#[test]
fn crate_and_reference_agree_on_a_random_list() {
    let n = 50_000u64;
    let rev = pattern::indices(n, 500, pattern::Pattern::Random, 11);
    let mut l = TokenStatusList::new(1, n as usize).unwrap();
    for &i in &rev {
        l.set(i as usize, TokenStatus::Invalid).unwrap();
    }
    let e = l.encode().unwrap();
    let r = reference::decode(1, &e.lst, 1 << 20).unwrap();
    assert_eq!(r, l.as_bytes());
    let ones: u32 = r.iter().map(|b| b.count_ones()).sum();
    assert_eq!(ones, 500);
    for &i in &rev {
        assert_eq!(reference::get(&r, 1, i as usize), Some(1));
    }
    assert_eq!(reference::get(&r, 1, n as usize), None);
}

#[test]
fn staleness_bounds() {
    // Never negative and never more than update + ttl.
    for (u, t) in [
        (300.0, 60.0),
        (3600.0, 3600.0),
        (300.0, 43200.0),
        (86400.0, 300.0),
    ] {
        let s = freshness::simulate(u, t, 20_000, 5);
        assert!(s.max_s <= u + t + 1e-6, "{u} {t} {}", s.max_s);
        assert!(s.p50_s >= 0.0);
        assert!(s.mean_s > 0.0);
    }
    // Hand-checked case: revocation at 10, publication at 300, RP fetching
    // at 50 + k*60 (…, 290, 350) sees it at 350.
    assert_eq!(freshness::staleness(300.0, 60.0, 10.0, 50.0), 340.0);
    // Revocation exactly at a publication boundary waits for the next one.
    assert_eq!(freshness::staleness(300.0, 300.0, 300.0, 0.0), 300.0);
}
