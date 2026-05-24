use globacl_core::{
    now_unix, shard_for_hash, stable_key_hash, Action, ActiveState, DenyEntry, Snapshot,
    DEFAULT_SHARD_COUNT,
};
use std::env;
use std::fs;
use std::hint::black_box;
use std::process::{self, Command};
use std::str::FromStr;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
struct BenchConfig {
    entries: usize,
    lookups: usize,
    shard_count: u16,
    positive_pool: usize,
    negative_pool: usize,
    sample_limit: usize,
}

#[derive(Clone, Copy, Debug)]
enum CliAction {
    Run(BenchConfig),
    Help,
}

#[derive(Clone, Debug)]
struct LookupStats {
    denies: usize,
    elapsed: Duration,
    samples_ns: Vec<u64>,
}

pub(crate) fn run_cli() {
    match BenchConfig::from_env() {
        Ok(CliAction::Run(config)) => run(config),
        Ok(CliAction::Help) => print_usage(),
        Err(error) => {
            eprintln!("{error}\n");
            print_usage();
            process::exit(2);
        }
    }
}

fn run(config: BenchConfig) {
    let positive_pool = config.positive_pool.min(config.entries);
    let negative_pool = config.negative_pool.max(1);
    let rss_before_snapshot = current_rss_bytes();

    let snapshot_start = Instant::now();
    let (snapshot, positive_keys) =
        build_snapshot(config.entries, config.shard_count, positive_pool);
    let snapshot_elapsed = snapshot_start.elapsed();
    let rss_after_snapshot = current_rss_bytes();

    let build_start = Instant::now();
    let state = ActiveState::from_snapshot(snapshot).expect("snapshot should build");
    let build_elapsed = build_start.elapsed();
    let rss_after_build = current_rss_bytes();
    let stats = state.stats();

    let now = now_unix();
    let positive_stats = if positive_keys.is_empty() {
        LookupStats::empty()
    } else {
        run_lookup_bench(config.lookups, config.sample_limit, |index| {
            let key = &positive_keys[index % positive_keys.len()];
            black_box(state.lookup("tenant-a", "user", key, now)).is_denied()
        })
    };

    let negative_keys = build_negative_keys(negative_pool);
    let mut negative_filter_positive_count = 0usize;
    let filter_probe_start = Instant::now();
    for index in 0..config.lookups {
        let key = &negative_keys[index % negative_keys.len()];
        if state.base_filter_may_contain("tenant-a", "user", key) {
            negative_filter_positive_count += 1;
        }
    }
    let filter_probe_elapsed = filter_probe_start.elapsed();

    let negative_stats = run_lookup_bench(config.lookups, config.sample_limit, |index| {
        let key = &negative_keys[index % negative_keys.len()];
        black_box(state.lookup("tenant-a", "user", key, now)).is_denied()
    });
    let rss_after_lookup = current_rss_bytes();

    println!("entries={}", config.entries);
    println!("lookups={}", config.lookups);
    println!("shard_count={}", config.shard_count);
    println!("positive_key_pool={}", positive_keys.len());
    println!("negative_key_pool={}", negative_keys.len());
    println!(
        "snapshot_build_ms={:.3}",
        snapshot_elapsed.as_secs_f64() * 1000.0
    );
    println!("build_ms={:.3}", build_elapsed.as_secs_f64() * 1000.0);
    println!("base_entries={}", stats.base_entries);
    println!("delta_adds={}", stats.delta_adds);
    println!("delta_removes={}", stats.delta_removes);
    println!("base_rules={}", stats.base_rules);
    println!("delta_rule_adds={}", stats.delta_rule_adds);
    println!("delta_rule_removes={}", stats.delta_rule_removes);
    println!("filter_bits={}", stats.filter_bits);
    println!("filter_hashes={}", stats.filter_hashes);
    println!(
        "filter_bits_per_entry={:.3}",
        ratio(stats.filter_bits, stats.base_entries)
    );
    println!("estimated_state_bytes={}", stats.estimated_bytes);
    println!(
        "rss_supported={}",
        rss_after_build.is_some() || rss_after_lookup.is_some()
    );
    print_optional_u64("rss_before_snapshot_bytes", rss_before_snapshot);
    print_optional_u64("rss_after_snapshot_bytes", rss_after_snapshot);
    print_optional_u64("rss_after_build_bytes", rss_after_build);
    print_optional_u64("rss_after_lookup_bytes", rss_after_lookup);
    print_optional_i128(
        "rss_snapshot_delta_bytes",
        optional_delta(rss_after_snapshot, rss_before_snapshot),
    );
    print_optional_i128(
        "rss_build_delta_bytes",
        optional_delta(rss_after_build, rss_after_snapshot),
    );
    print_optional_i128(
        "rss_lookup_delta_bytes",
        optional_delta(rss_after_lookup, rss_after_build),
    );
    print_lookup_stats("positive", &positive_stats, config.lookups);
    print_lookup_stats("negative", &negative_stats, config.lookups);
    println!("negative_filter_positive_count={negative_filter_positive_count}");
    println!(
        "negative_filter_positive_rate={:.8}",
        ratio(negative_filter_positive_count, config.lookups)
    );
    println!(
        "negative_filter_probe_ms={:.3}",
        filter_probe_elapsed.as_secs_f64() * 1000.0
    );
}
