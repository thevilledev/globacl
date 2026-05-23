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

fn main() {
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

impl BenchConfig {
    fn default() -> Self {
        Self {
            entries: 100_000,
            lookups: 1_000_000,
            shard_count: DEFAULT_SHARD_COUNT,
            positive_pool: 100_000,
            negative_pool: 100_000,
            sample_limit: 1_000_000,
        }
    }

    fn ci() -> Self {
        Self {
            entries: 50_000,
            lookups: 100_000,
            shard_count: DEFAULT_SHARD_COUNT,
            positive_pool: 50_000,
            negative_pool: 50_000,
            sample_limit: 20_000,
        }
    }

    fn from_env() -> Result<CliAction, String> {
        let mut config = Self::default();
        let mut positional = Vec::new();
        let mut args = env::args().skip(1);

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-h" | "--help" => return Ok(CliAction::Help),
                "--ci" => config = Self::ci(),
                "--entries" => config.entries = parse_next(&mut args, "--entries")?,
                "--lookups" => config.lookups = parse_next(&mut args, "--lookups")?,
                "--shards" | "--shard-count" => {
                    config.shard_count = parse_next(&mut args, "--shards")?
                }
                "--positive-pool" => {
                    config.positive_pool = parse_next(&mut args, "--positive-pool")?
                }
                "--negative-pool" => {
                    config.negative_pool = parse_next(&mut args, "--negative-pool")?
                }
                "--sample-limit" => config.sample_limit = parse_next(&mut args, "--sample-limit")?,
                value if value.starts_with("--entries=") => {
                    config.entries = parse_inline(value, "--entries=")?
                }
                value if value.starts_with("--lookups=") => {
                    config.lookups = parse_inline(value, "--lookups=")?
                }
                value if value.starts_with("--shards=") => {
                    config.shard_count = parse_inline(value, "--shards=")?
                }
                value if value.starts_with("--shard-count=") => {
                    config.shard_count = parse_inline(value, "--shard-count=")?
                }
                value if value.starts_with("--positive-pool=") => {
                    config.positive_pool = parse_inline(value, "--positive-pool=")?
                }
                value if value.starts_with("--negative-pool=") => {
                    config.negative_pool = parse_inline(value, "--negative-pool=")?
                }
                value if value.starts_with("--sample-limit=") => {
                    config.sample_limit = parse_inline(value, "--sample-limit=")?
                }
                value if value.starts_with("--") => {
                    return Err(format!("unknown argument: {value}"));
                }
                value => positional.push(value.to_owned()),
            }
        }

        if positional.len() > 3 {
            return Err("too many positional arguments".to_owned());
        }
        if let Some(value) = positional.first() {
            config.entries = parse_value(value, "entry_count")?;
        }
        if let Some(value) = positional.get(1) {
            config.lookups = parse_value(value, "lookup_count")?;
        }
        if let Some(value) = positional.get(2) {
            config.shard_count = parse_value(value, "shard_count")?;
        }
        if config.shard_count == 0 {
            return Err("shard_count must be greater than zero".to_owned());
        }

        Ok(CliAction::Run(config))
    }
}

impl LookupStats {
    fn empty() -> Self {
        Self {
            denies: 0,
            elapsed: Duration::ZERO,
            samples_ns: Vec::new(),
        }
    }
}

fn parse_next<T>(args: &mut impl Iterator<Item = String>, name: &str) -> Result<T, String>
where
    T: FromStr,
{
    let value = args
        .next()
        .ok_or_else(|| format!("missing value for {name}"))?;
    parse_value(&value, name)
}

fn parse_inline<T>(arg: &str, prefix: &str) -> Result<T, String>
where
    T: FromStr,
{
    parse_value(&arg[prefix.len()..], prefix.trim_end_matches('='))
}

fn parse_value<T>(value: &str, name: &str) -> Result<T, String>
where
    T: FromStr,
{
    value
        .parse::<T>()
        .map_err(|_| format!("invalid value for {name}: {value}"))
}

fn run_lookup_bench<F>(lookups: usize, sample_limit: usize, mut lookup: F) -> LookupStats
where
    F: FnMut(usize) -> bool,
{
    if lookups == 0 {
        return LookupStats::empty();
    }

    let mut samples_ns = Vec::with_capacity(sample_limit.min(lookups));
    let sample_stride = if sample_limit == 0 {
        0
    } else {
        lookups.div_ceil(sample_limit).max(1)
    };

    let start = Instant::now();
    let mut denies = 0usize;
    for index in 0..lookups {
        let should_sample =
            sample_limit > 0 && index % sample_stride == 0 && samples_ns.len() < sample_limit;
        if should_sample {
            let sample_start = Instant::now();
            let denied = lookup(index);
            samples_ns.push(sample_start.elapsed().as_nanos() as u64);
            if denied {
                denies += 1;
            }
        } else if lookup(index) {
            denies += 1;
        }
    }

    LookupStats {
        denies,
        elapsed: start.elapsed(),
        samples_ns,
    }
}

fn print_lookup_stats(prefix: &str, stats: &LookupStats, lookups: usize) {
    let mut samples = stats.samples_ns.clone();
    samples.sort_unstable();
    let avg = if lookups == 0 {
        0.0
    } else {
        stats.elapsed.as_nanos() as f64 / lookups as f64
    };

    println!("{prefix}_denies={}", stats.denies);
    println!("{prefix}_ns_per_lookup={avg:.3}");
    println!("{prefix}_avg_ns_per_lookup={avg:.3}");
    println!("{prefix}_sample_count={}", samples.len());
    println!("{prefix}_p50_ns={}", percentile(&samples, 50.0));
    println!("{prefix}_p95_ns={}", percentile(&samples, 95.0));
    println!("{prefix}_p99_ns={}", percentile(&samples, 99.0));
    println!("{prefix}_p999_ns={}", percentile(&samples, 99.9));
}

fn percentile(sorted_samples: &[u64], percentile: f64) -> u64 {
    if sorted_samples.is_empty() {
        return 0;
    }
    let index = (((sorted_samples.len() - 1) as f64) * (percentile / 100.0)).round() as usize;
    sorted_samples[index.min(sorted_samples.len() - 1)]
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn current_rss_bytes() -> Option<u64> {
    linux_proc_status_rss_bytes().or_else(ps_rss_bytes)
}

fn linux_proc_status_rss_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb = rest.split_whitespace().next()?.parse::<u64>().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

fn ps_rss_bytes() -> Option<u64> {
    let pid = process::id().to_string();
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let kb = stdout.split_whitespace().next()?.parse::<u64>().ok()?;
    Some(kb * 1024)
}

fn print_optional_u64(name: &str, value: Option<u64>) {
    match value {
        Some(value) => println!("{name}={value}"),
        None => println!("{name}=unknown"),
    }
}

fn print_optional_i128(name: &str, value: Option<i128>) {
    match value {
        Some(value) => println!("{name}={value}"),
        None => println!("{name}=unknown"),
    }
}

fn optional_delta(after: Option<u64>, before: Option<u64>) -> Option<i128> {
    Some(after? as i128 - before? as i128)
}

fn build_snapshot(
    entries: usize,
    shard_count: u16,
    positive_pool: usize,
) -> (Snapshot, Vec<String>) {
    let mut watermarks = vec![0u64; shard_count as usize];
    let mut snapshot_entries = Vec::with_capacity(entries);
    let mut raw_keys = Vec::with_capacity(positive_pool.min(entries));

    for index in 0..entries {
        let raw_key = format!("user-{index}");
        if raw_keys.len() < positive_pool {
            raw_keys.push(raw_key.clone());
        }
        let key_hash = stable_key_hash("tenant-a", "user", &raw_key);
        let shard_id = shard_for_hash(key_hash, shard_count);
        watermarks[shard_id as usize] += 1;
        let commit_seq = watermarks[shard_id as usize];

        snapshot_entries.push(DenyEntry {
            tenant_id: "tenant-a".to_owned(),
            namespace: "user".to_owned(),
            key_hash,
            action: Action::Deny,
            priority: 100,
            reason_code: "benchmark".to_owned(),
            expires_at: 0,
            created_by: "globacl-bench".to_owned(),
            commit_seq,
            shard_id,
        });
    }

    (
        Snapshot {
            shard_count,
            watermarks,
            entries: snapshot_entries,
            rules: Vec::new(),
        },
        raw_keys,
    )
}

fn build_negative_keys(count: usize) -> Vec<String> {
    (0..count).map(|index| format!("missing-{index}")).collect()
}

fn print_usage() {
    println!(
        "Usage: globacl-bench [entry_count lookup_count shard_count] [options]\n\
\n\
Options:\n\
  --entries N         Number of synthetic deny entries\n\
  --lookups N         Number of positive and negative lookups\n\
  --shards N          Logical shard count\n\
  --positive-pool N   Number of existing keys reused during positive lookups\n\
  --negative-pool N   Number of missing keys reused during negative lookups\n\
  --sample-limit N    Maximum per-lookup latency samples for p50/p95/p99 output\n\
  --ci                Use a small CI-sized benchmark profile\n\
  -h, --help          Show this help"
    );
}
