use globacl_core::{
    now_unix, shard_for_hash, stable_key_hash, Action, ActiveState, DenyEntry, Snapshot,
    DEFAULT_SHARD_COUNT,
};
use std::env;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let entries = args
        .get(1)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100_000);
    let lookups = args
        .get(2)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1_000_000);
    let shard_count = args
        .get(3)
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(DEFAULT_SHARD_COUNT);

    let (snapshot, positive_keys) = build_snapshot(entries, shard_count);

    let build_start = Instant::now();
    let state = ActiveState::from_snapshot(snapshot).expect("snapshot should build");
    let build_elapsed = build_start.elapsed();
    let stats = state.stats();

    let positive_start = Instant::now();
    let mut positive_denies = 0usize;
    if !positive_keys.is_empty() {
        for index in 0..lookups {
            let key = &positive_keys[index % positive_keys.len()];
            if black_box(state.lookup("tenant-a", "user", key, now_unix())).is_denied() {
                positive_denies += 1;
            }
        }
    }
    let positive_elapsed = positive_start.elapsed();

    let negative_start = Instant::now();
    let mut negative_denies = 0usize;
    for index in 0..lookups {
        let key = format!("missing-{index}");
        if black_box(state.lookup("tenant-a", "user", &key, now_unix())).is_denied() {
            negative_denies += 1;
        }
    }
    let negative_elapsed = negative_start.elapsed();

    println!("entries={entries}");
    println!("lookups={lookups}");
    println!("shard_count={shard_count}");
    println!("build_ms={:.3}", build_elapsed.as_secs_f64() * 1000.0);
    println!("base_entries={}", stats.base_entries);
    println!("delta_adds={}", stats.delta_adds);
    println!("delta_removes={}", stats.delta_removes);
    println!("filter_bits={}", stats.filter_bits);
    println!("estimated_state_bytes={}", stats.estimated_bytes);
    println!("positive_denies={positive_denies}");
    println!(
        "positive_ns_per_lookup={:.3}",
        positive_elapsed.as_nanos() as f64 / lookups as f64
    );
    println!("negative_denies={negative_denies}");
    println!(
        "negative_ns_per_lookup={:.3}",
        negative_elapsed.as_nanos() as f64 / lookups as f64
    );
}

fn build_snapshot(entries: usize, shard_count: u16) -> (Snapshot, Vec<String>) {
    let mut watermarks = vec![0u64; shard_count as usize];
    let mut snapshot_entries = Vec::with_capacity(entries);
    let mut raw_keys = Vec::with_capacity(entries.min(100_000));

    for index in 0..entries {
        let raw_key = format!("user-{index}");
        if raw_keys.len() < 100_000 {
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
        },
        raw_keys,
    )
}
