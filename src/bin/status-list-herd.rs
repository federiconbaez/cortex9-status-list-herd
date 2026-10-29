//! status-list-herd [--max-n N] [--reps R] [--out DIR] [--sizes-only]
//!
//! Writes DIR/sizes.csv (deterministic), DIR/freshness.csv (deterministic)
//! and, unless --sizes-only, DIR/sweep.csv (sizes plus timings).

use status_list_herd::freshness;
use status_list_herd::pattern::Pattern;
use status_list_herd::sweep;
use std::fmt::Write as _;

const SIZES: [u64; 5] = [1_000, 10_000, 100_000, 1_000_000, 10_000_000];
const RATES: [f64; 6] = [0.001, 0.005, 0.01, 0.02, 0.05, 0.10];
const UPDATES: [f64; 3] = [300.0, 3600.0, 86400.0];
const TTLS: [f64; 5] = [60.0, 300.0, 3600.0, 43200.0, 86400.0];

fn arg(a: &[String], k: &str) -> Option<String> {
    a.iter()
        .position(|x| x == k)
        .and_then(|i| a.get(i + 1).cloned())
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let max_n: u64 = arg(&a, "--max-n")
        .map(|v| v.parse().unwrap())
        .unwrap_or(10_000_000);
    let reps: usize = arg(&a, "--reps").map(|v| v.parse().unwrap()).unwrap_or(15);
    let out = arg(&a, "--out").unwrap_or_else(|| "results".into());
    let sizes_only = a.iter().any(|x| x == "--sizes-only");
    std::fs::create_dir_all(&out).unwrap();

    let mut sizes = String::from(
        "entries,revocation_pct,pattern,revoked,raw_bytes,zlib_bytes,lst_chars,jwt_bytes,zlib_bits_per_entry,k_list,k_valid,reference_agrees\n",
    );
    let mut sweep_csv = String::from(
        "entries,revocation_pct,pattern,revoked,raw_bytes,zlib_bytes,lst_chars,jwt_bytes,k_list,k_valid,reference_agrees,encode_ms,verify_ms_median,verify_ms_p90,decode_ms_median,reps\n",
    );
    let mut all_agree = true;
    for &n in SIZES.iter().filter(|&&n| n <= max_n) {
        for &rate in &RATES {
            for p in [Pattern::Random, Pattern::Clustered] {
                let r = sweep::run(n, rate, p, reps, !sizes_only);
                all_agree &= r.reference_agrees;
                writeln!(
                    sizes,
                    "{},{:.1},{},{},{},{},{},{},{:.4},{},{},{}",
                    r.entries,
                    r.revocation_pct,
                    r.pattern,
                    r.revoked,
                    r.raw_bytes,
                    r.zlib_bytes,
                    r.lst_chars,
                    r.jwt_bytes,
                    r.zlib_bytes as f64 * 8.0 / n as f64,
                    r.k_list,
                    r.k_valid,
                    r.reference_agrees
                )
                .unwrap();
                writeln!(
                    sweep_csv,
                    "{},{:.1},{},{},{},{},{},{},{},{},{},{:.3},{:.3},{:.3},{:.3},{}",
                    r.entries,
                    r.revocation_pct,
                    r.pattern,
                    r.revoked,
                    r.raw_bytes,
                    r.zlib_bytes,
                    r.lst_chars,
                    r.jwt_bytes,
                    r.k_list,
                    r.k_valid,
                    r.reference_agrees,
                    r.encode_ms,
                    r.verify_ms_median,
                    r.verify_ms_p90,
                    r.decode_ms_median,
                    r.reps
                )
                .unwrap();
                eprintln!(
                    "n={n} rate={rate} {}: zlib {} B, verify {:.3} ms",
                    r.pattern, r.zlib_bytes, r.verify_ms_median
                );
            }
        }
    }
    std::fs::write(format!("{out}/sizes.csv"), sizes).unwrap();
    if !sizes_only {
        std::fs::write(format!("{out}/sweep.csv"), sweep_csv).unwrap();
    }

    let mut fr = String::from(
        "update_interval_s,ttl_s,samples,staleness_mean_s,staleness_p50_s,staleness_p95_s,staleness_max_s,bound_update_plus_ttl_s,fetches_per_day,ttl_ge_update\n",
    );
    for &u in &UPDATES {
        for &t in &TTLS {
            let s = freshness::simulate(u, t, 200_000, 42);
            writeln!(
                fr,
                "{u},{t},200000,{:.1},{:.1},{:.1},{:.1},{},{:.2},{}",
                s.mean_s,
                s.p50_s,
                s.p95_s,
                s.max_s,
                u + t,
                s.fetches_per_day,
                t >= u
            )
            .unwrap();
        }
    }
    std::fs::write(format!("{out}/freshness.csv"), fr).unwrap();
    if !all_agree {
        eprintln!("reference decoder disagreed with the crate");
        std::process::exit(1);
    }
}
