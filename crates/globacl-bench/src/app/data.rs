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
