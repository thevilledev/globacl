fn publisher_loop(app: Arc<App>, interval: Duration) {
    loop {
        if let Err(err) = publish_committed_mutations(&app) {
            eprintln!("commitd JetStream publish failed: {err}");
            if let Ok(mut status) = lock_publisher_status(&app) {
                status.publish_errors += 1;
            }
        }
        thread::sleep(interval);
    }
}

fn publish_committed_mutations(app: &App) -> Result<()> {
    let Some(publisher) = &app.publisher else {
        return Ok(());
    };
    if app.replication.is_clustered() && !is_write_leader(app)? {
        return Ok(());
    }

    let last_published = lock_publisher_status(app)?.last_published.clone();
    let mutations = {
        let state = lock_state(app)?;
        let mut mutations = Vec::new();
        for shard_id in 0..state.shard_count() {
            let from_seq = last_published.get(shard_id as usize).copied().unwrap_or(0);
            mutations.extend(state.mutations_for_shard(shard_id, from_seq));
        }
        mutations.sort_by_key(|mutation| {
            (
                mutation.committed_at_unix,
                mutation.commit_id.shard_id,
                mutation.commit_id.seq,
            )
        });
        mutations
    };

    if mutations.is_empty() {
        return Ok(());
    }

    let mut next_published = last_published;
    for mutation in mutations {
        let subject = mutation_subject(&publisher.subject_prefix, &mutation);
        nats_jetstream_publish(&publisher.nats_addr, &subject, &encode_mutation(&mutation))?;
        let slot = mutation.commit_id.shard_id as usize;
        if let Some(seq) = next_published.get_mut(slot) {
            *seq = (*seq).max(mutation.commit_id.seq);
        }
    }

    let mut status = lock_publisher_status(app)?;
    persist_publisher_offsets(&app.publisher_offsets_path, &next_published)?;
    status.last_published = next_published;
    status.last_publish_unix = now_unix();
    Ok(())
}

fn mutation_subject(prefix: &str, mutation: &Mutation) -> String {
    format!(
        "{}.{}.shard.{}",
        prefix,
        mutation.delivery_priority.as_str(),
        mutation.commit_id.shard_id
    )
}

fn load_publisher_offsets(path: &Path, shard_count: u16) -> Result<Vec<u64>> {
    let mut offsets = vec![0; shard_count as usize];
    if !path.exists() {
        return Ok(offsets);
    }
    let bytes = fs::read(path)?;
    let fields = parse_json_fields(&bytes)?;
    for (shard_id, offset) in offsets.iter_mut().enumerate() {
        let key = format!("shard_{shard_id:04}");
        if let Some(value) = fields.get(&key) {
            *offset = parse_query_u64(value, &key)?;
        }
    }
    Ok(offsets)
}

fn persist_publisher_offsets(path: &Path, offsets: &[u64]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        let mut body = json!({"shard_count": offsets.len()});
        for (shard_id, seq) in offsets.iter().enumerate() {
            if let Some(object) = body.as_object_mut() {
                object.insert(format!("shard_{shard_id:04}"), json!(seq));
            }
        }
        file.write_all(body.to_string().as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

fn record_propagation_ack(app: &App, ack: PropagationAck) -> Result<()> {
    if app.replication.is_clustered() {
        ensure_write_authority(app)?;
    }
    apply_propagation_ack(app, ack.clone())?;
    replicate_propagation_ack_on_quorum(app, &ack)
}

fn apply_propagation_ack(app: &App, ack: PropagationAck) -> Result<bool> {
    let mut acks = lock_propagation_acks(app)?;
    apply_propagation_ack_to_store(&app.propagation_acks_path, &mut acks, ack)
}

fn apply_propagation_ack_to_store(
    path: &Path,
    acks: &mut HashMap<String, PropagationAck>,
    ack: PropagationAck,
) -> Result<bool> {
    let key = ack.key();
    if let Some(existing) = acks.get(&key) {
        if existing.seq > ack.seq || existing == &ack {
            return Ok(false);
        }
    }
    append_propagation_ack(path, &ack)?;
    acks.insert(key, ack);
    Ok(true)
}

fn replicate_propagation_ack_on_quorum(app: &App, ack: &PropagationAck) -> Result<()> {
    if !app.replication.is_clustered() {
        return Ok(());
    }

    let payload = ack.to_json_body();
    let mut replicated = 1usize;
    let mut failures = Vec::new();
    for peer in app.replication.remote_peers() {
        match http_post(&peer.addr, "/internal/replication/ack", payload.as_bytes()) {
            Ok(response) if response.status_code == 200 => replicated += 1,
            Ok(response) => {
                failures.push(format!(
                    "{}:http_status:{}",
                    peer.node_id, response.status_code
                ))
            }
            Err(err) => failures.push(format!("{}:{err}", peer.node_id)),
        }
    }

    if replicated >= app.replication.quorum {
        return Ok(());
    }

    Err(GlobAclError::InvalidData(format!(
        "commitd ack quorum unavailable: replicated={replicated} quorum={} failures={}",
        app.replication.quorum,
        failures.join(",")
    )))
}

fn load_propagation_acks(path: &Path) -> Result<HashMap<String, PropagationAck>> {
    let mut acks = HashMap::new();
    if !path.exists() {
        return Ok(acks);
    }
    let text = String::from_utf8(fs::read(path)?)
        .map_err(|err| GlobAclError::Parse(format!("ack log is not utf8: {err}")))?;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let ack = parse_propagation_ack_json(parse_json_body(line.as_bytes())?)?;
        let key = ack.key();
        if acks
            .get(&key)
            .map(|existing| existing.seq <= ack.seq)
            .unwrap_or(true)
        {
            acks.insert(key, ack);
        }
    }
    Ok(acks)
}

fn append_propagation_ack(path: &Path, ack: &PropagationAck) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", ack.to_json_body())?;
    file.sync_all()?;
    Ok(())
}

fn propagation_ack_json(ack: &PropagationAck) -> JsonValue {
    json!({
        "relay_id": ack.relay_id.as_str(),
        "location": ack.location.as_str(),
        "agent_id": ack.agent_id.as_str(),
        "shard_id": ack.shard_id,
        "seq": ack.seq,
        "entries": ack.entries,
        "applied_at_unix": ack.applied_at_unix,
        "relay_received_at_unix": ack.relay_received_at_unix
    })
}

fn parse_propagation_ack_json(value: JsonValue) -> Result<PropagationAck> {
    PropagationAck::from_json_fields(&globacl_core::json_object_to_string_map(value)?)
}

fn format_propagation_ack_log_snapshot(app: &App) -> Result<String> {
    let mut acks = lock_propagation_acks(app)?
        .values()
        .cloned()
        .collect::<Vec<_>>();
    acks.sort_by(|left, right| {
        left.relay_id
            .cmp(&right.relay_id)
            .then(left.agent_id.cmp(&right.agent_id))
            .then(left.shard_id.cmp(&right.shard_id))
    });
    Ok(json!({
        "acks": acks.iter().map(propagation_ack_json).collect::<Vec<_>>()
    })
    .to_string())
}

fn apply_propagation_ack_log_snapshot(app: &App, body: &[u8]) -> Result<usize> {
    let value = parse_json_body(body)?;
    let ack_values = value
        .get("acks")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| GlobAclError::Parse("ack snapshot missing acks array".to_owned()))?;
    let mut applied = 0usize;
    let mut acks = lock_propagation_acks(app)?;
    for value in ack_values {
        let ack = parse_propagation_ack_json(value.clone())?;
        if apply_propagation_ack_to_store(&app.propagation_acks_path, &mut acks, ack)? {
            applied += 1;
        }
    }
    Ok(applied)
}

fn sync_acks_from_peer(app: &App, peer_addr: &str) -> Result<usize> {
    let response = http_get(peer_addr, "/internal/replication/acks")?;
    if response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "peer returned status {} for ack snapshot",
            response.status_code
        )));
    }
    apply_propagation_ack_log_snapshot(app, &response.body)
}

fn sync_acks_from_peers(app: &App) -> Result<usize> {
    let mut applied = 0usize;
    let mut failures = Vec::new();
    for peer in app.replication.remote_peers() {
        match sync_acks_from_peer(app, &peer.addr) {
            Ok(count) => applied += count,
            Err(err) => failures.push(format!("{}:{err}", peer.node_id)),
        }
    }
    if failures.is_empty() {
        return Ok(applied);
    }
    Err(GlobAclError::InvalidData(format!(
        "ack peer sync failed: {}",
        failures.join(",")
    )))
}

fn format_propagation_status(app: &App) -> Result<String> {
    let watermarks = {
        let state = lock_state(app)?;
        state.watermarks().to_vec()
    };
    let now = now_unix();
    let mut acks = lock_propagation_acks(app)?
        .values()
        .cloned()
        .collect::<Vec<_>>();
    acks.sort_by(|left, right| {
        left.relay_id
            .cmp(&right.relay_id)
            .then(left.agent_id.cmp(&right.agent_id))
            .then(left.shard_id.cmp(&right.shard_id))
    });

    let source_max_seq = watermarks.iter().copied().max().unwrap_or(0);
    let ack_count = acks.len();
    let relay_count = acks
        .iter()
        .map(|ack| ack.relay_id.as_str())
        .collect::<HashSet<_>>()
        .len();
    let agent_count = acks
        .iter()
        .map(|ack| ack.agent_id.as_str())
        .collect::<HashSet<_>>()
        .len();
    let acked_shards = acks
        .iter()
        .map(|ack| ack.shard_id)
        .collect::<HashSet<_>>()
        .len();
    let min_ack_seq = acks.iter().map(|ack| ack.seq).min().unwrap_or(0);
    let max_ack_seq = acks.iter().map(|ack| ack.seq).max().unwrap_or(0);
    let mut max_seq_lag = 0u64;
    let mut lagging_ack_count = 0usize;
    let mut max_ack_age_secs = 0u64;
    for ack in &acks {
        let source_seq = watermarks
            .get(ack.shard_id as usize)
            .copied()
            .unwrap_or_default();
        let seq_lag = source_seq.saturating_sub(ack.seq);
        if seq_lag > 0 {
            lagging_ack_count += 1;
            max_seq_lag = max_seq_lag.max(seq_lag);
        }
        max_ack_age_secs = max_ack_age_secs.max(now.saturating_sub(ack.applied_at_unix));
    }
    let status = if source_max_seq > 0 && (ack_count == 0 || lagging_ack_count > 0) {
        "degraded"
    } else {
        "ok"
    };

    let mut ack_items = Vec::new();
    for ack in acks {
        let source_seq = watermarks
            .get(ack.shard_id as usize)
            .copied()
            .unwrap_or_default();
        let seq_lag = source_seq.saturating_sub(ack.seq);
        let ack_age_secs = now.saturating_sub(ack.applied_at_unix);
        ack_items.push(json!({
            "relay_id": ack.relay_id.as_str(),
            "location": ack.location.as_str(),
            "agent_id": ack.agent_id.as_str(),
            "shard_id": ack.shard_id,
            "seq": ack.seq,
            "source_seq": source_seq,
            "seq_lag": seq_lag,
            "entries": ack.entries,
            "applied_at_unix": ack.applied_at_unix,
            "relay_received_at_unix": ack.relay_received_at_unix,
            "ack_age_secs": ack_age_secs
        }));
    }
    Ok(json!({
        "status": status,
        "shard_count": watermarks.len(),
        "source_max_seq": source_max_seq,
        "ack_count": ack_count,
        "relay_count": relay_count,
        "agent_count": agent_count,
        "acked_shards": acked_shards,
        "min_ack_seq": min_ack_seq,
        "max_ack_seq": max_ack_seq,
        "max_seq_lag": max_seq_lag,
        "lagging_ack_count": lagging_ack_count,
        "max_ack_age_secs": max_ack_age_secs,
        "acks": ack_items
    })
    .to_string())
}
