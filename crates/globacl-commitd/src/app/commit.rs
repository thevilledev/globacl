fn compacted_seq_for_query(
    app: &App,
    query: &std::collections::HashMap<String, String>,
) -> Result<Option<u64>> {
    let shard_id = required_query_u16(query, "shard")?;
    let from_seq = query
        .get("from_seq")
        .or_else(|| query.get("from"))
        .map(|value| parse_query_u64(value, "from_seq"))
        .transpose()?
        .unwrap_or(0);
    let state = lock_state(app)?;
    Ok(state.mutation_history_compacted(shard_id, from_seq))
}

fn mutations_for_query(
    app: &App,
    query: &std::collections::HashMap<String, String>,
) -> Result<Vec<Mutation>> {
    let shard_id = required_query_u16(query, "shard")?;
    let from_seq = query
        .get("from_seq")
        .or_else(|| query.get("from"))
        .map(|value| parse_query_u64(value, "from_seq"))
        .transpose()?
        .unwrap_or(0);
    let priority_filter = query
        .get("delivery_priority")
        .or_else(|| query.get("channel"))
        .map(|value| DeliveryPriority::from_name(value))
        .transpose()?;
    let state = lock_state(app)?;
    let mutations = state.mutations_for_shard(shard_id, from_seq);
    Ok(if let Some(priority) = priority_filter {
        mutations
            .into_iter()
            .filter(|mutation| mutation.delivery_priority == priority)
            .collect()
    } else {
        mutations
    })
}

fn delta_bundle_for_query(
    app: &App,
    query: &std::collections::HashMap<String, String>,
) -> Result<Vec<Mutation>> {
    let shard_id = required_query_u16(query, "shard")?;
    let from_seq = query
        .get("from_seq")
        .or_else(|| query.get("from"))
        .map(|value| parse_query_u64(value, "from_seq"))
        .transpose()?
        .unwrap_or(0);
    let to_seq = query
        .get("to_seq")
        .or_else(|| query.get("to"))
        .map(|value| parse_query_u64(value, "to_seq"))
        .transpose()?
        .unwrap_or(u64::MAX);
    let state = lock_state(app)?;
    Ok(state
        .mutations_for_shard(shard_id, from_seq)
        .into_iter()
        .filter(|mutation| mutation.commit_id.seq <= to_seq)
        .collect::<Vec<_>>())
}

fn sign_payload(app: &App, payload: &[u8]) -> Result<String> {
    app.signature_signer.sign_payload(payload)
}

fn ensure_latest_snapshot_manifest(app: &App) -> Result<()> {
    if app.snapshot_manifest_path.exists() && signature_path(&app.snapshot_manifest_path).exists() {
        return Ok(());
    }
    let snapshot = {
        let state = lock_state(app)?;
        state.snapshot()
    };
    persist_latest_snapshot(app, &snapshot)
}

fn load_source_of_truth(
    log_dir: &Path,
    snapshot_path: &Path,
    idempotency_path: &Path,
    shard_count: u16,
    cluster_id: &str,
    publisher_offsets: Option<&[u64]>,
) -> Result<SourceOfTruth> {
    if snapshot_path.exists() {
        let snapshot = decode_snapshot(&fs::read(snapshot_path)?)?;
        snapshot.validate()?;
        if snapshot.shard_count != shard_count {
            return Err(GlobAclError::InvalidData(format!(
                "snapshot shard_count {} does not match configured {shard_count}",
                snapshot.shard_count
            )));
        }

        let all_log_mutations = load_all_logs(log_dir, shard_count)?;
        if publisher_offsets.is_some() && !all_log_mutations.is_empty() {
            if let Ok(replayed) =
                SourceOfTruth::from_mutations(shard_count, cluster_id, all_log_mutations.clone())
            {
                if replayed.watermarks() == snapshot.watermarks.as_slice() {
                    return Ok(replayed);
                }
            }
        }
        let mut idempotency_mutations = if idempotency_path.exists() {
            decode_mutation_stream(&fs::read(idempotency_path)?)?
        } else {
            all_log_mutations.clone()
        };
        if idempotency_path.exists() {
            idempotency_mutations.extend(all_log_mutations.iter().cloned());
        }
        if let Some(publisher_offsets) = publisher_offsets {
            if publisher_offsets.len() != shard_count as usize {
                return Err(GlobAclError::InvalidData(format!(
                    "publisher offsets has {} watermarks for {shard_count} shards",
                    publisher_offsets.len()
                )));
            }
            let compacted_watermarks = publisher_offsets
                .iter()
                .zip(snapshot.watermarks.iter())
                .map(|(published, snapshot_seq)| (*published).min(*snapshot_seq))
                .collect::<Vec<_>>();
            return SourceOfTruth::from_snapshot_and_retained_history(
                shard_count,
                cluster_id,
                snapshot,
                idempotency_mutations,
                all_log_mutations,
                compacted_watermarks,
            );
        }
        let tail_mutations = all_log_mutations
            .into_iter()
            .filter(|mutation| {
                mutation.commit_id.seq > snapshot.watermarks[mutation.commit_id.shard_id as usize]
            })
            .collect::<Vec<_>>();
        return SourceOfTruth::from_snapshot_and_mutations(
            shard_count,
            cluster_id,
            snapshot,
            idempotency_mutations,
            tail_mutations,
        );
    }

    let mutations = load_all_logs(log_dir, shard_count)?;
    SourceOfTruth::from_mutations(shard_count, cluster_id, mutations)
}

fn compaction_config() -> Result<CompactionConfig> {
    let min_log_entries = commitd_env("COMPACTION_MIN_LOG_ENTRIES")
        .ok()
        .map(|value| parse_env_usize(&value, "GLOBACL_COMMITD_COMPACTION_MIN_LOG_ENTRIES"))
        .transpose()?
        .unwrap_or(10_000);
    let compact_on_startup = commitd_env("COMPACT_ON_STARTUP")
        .ok()
        .map(|value| env_bool_value(&value))
        .unwrap_or(true);
    Ok(CompactionConfig {
        min_log_entries,
        compact_on_startup,
    })
}

fn commit_request(app: &App, deny_request: DenyRequest) -> Result<globacl_core::CommitOutcome> {
    let term = ensure_write_authority(app)?;
    let mut state = lock_state(app)?;
    state.set_epoch(term);
    let outcome = state.prepare_commit(deny_request)?;
    commit_prepared_outcome(app, &mut state, outcome)
}

fn commit_prepared_outcome(
    app: &App,
    state: &mut SourceOfTruth,
    outcome: globacl_core::CommitOutcome,
) -> Result<globacl_core::CommitOutcome> {
    if outcome.duplicate {
        return Ok(outcome);
    }

    let term = ensure_write_authority(app)?;
    if outcome.mutation.commit_id.epoch != term {
        return Err(GlobAclError::InvalidData(format!(
            "mutation epoch {} does not match current leader term {term}",
            outcome.mutation.commit_id.epoch
        )));
    }
    prepare_on_quorum(app, &outcome.mutation)?;
    apply_prepared_mutation(app, state, outcome.mutation.clone())?;
    commit_on_peers(app, &outcome.mutation);
    Ok(outcome)
}

fn commit_rule_request(
    app: &App,
    rule_request: RuleRequest,
) -> Result<globacl_core::CommitOutcome> {
    let term = ensure_write_authority(app)?;
    let mut state = lock_state(app)?;
    state.set_epoch(term);
    let outcome = state.prepare_rule_commit(rule_request)?;
    commit_prepared_outcome(app, &mut state, outcome)
}

fn apply_prepared_mutation(
    app: &App,
    state: &mut SourceOfTruth,
    mutation: Mutation,
) -> Result<ApplyStatus> {
    let shard_id = mutation.commit_id.shard_id;
    let already_at_or_past_seq = state
        .watermarks()
        .get(shard_id as usize)
        .copied()
        .unwrap_or(0)
        >= mutation.commit_id.seq;
    if !already_at_or_past_seq {
        persist_mutation(app, &mutation)?;
    }
    let status = state.apply_replicated_mutation(mutation.clone())?;
    if status == ApplyStatus::Applied {
        persist_latest_snapshot(app, &state.snapshot())?;
        persist_archived_snapshot(
            app,
            &state.snapshot(),
            &archive_name_for_mutation(&mutation),
        )?;
        maybe_compact_mutation_logs(app, state)?;
    }
    remove_pending_mutation(&app.pending_dir, &mutation)?;
    Ok(status)
}

fn ensure_write_authority(app: &App) -> Result<u64> {
    let consensus = lock_consensus(app)?;
    if consensus.role == ConsensusRole::Leader {
        return Ok(consensus.current_term);
    }
    Err(GlobAclError::InvalidData(format!(
        "node {} is not the write leader; leader is {}",
        app.replication.node_id,
        consensus.leader_id.as_deref().unwrap_or("unknown")
    )))
}

fn prepare_on_quorum(app: &App, mutation: &Mutation) -> Result<()> {
    if !app.replication.is_clustered() {
        return Ok(());
    }

    let payload = encode_mutation(mutation);
    let mut prepared = 1usize;
    let mut failures = Vec::new();
    for peer in app.replication.remote_peers() {
        match http_post(&peer.addr, "/internal/replication/prepare", &payload) {
            Ok(response) if response.status_code == 200 => prepared += 1,
            Ok(response) => {
                failures.push(format!(
                    "{}:http_status:{}",
                    peer.node_id, response.status_code
                ))
            }
            Err(err) => failures.push(format!("{}:{err}", peer.node_id)),
        }
    }

    if prepared >= app.replication.quorum {
        return Ok(());
    }

    abort_on_peers(app, mutation);
    Err(GlobAclError::InvalidData(format!(
        "commitd quorum unavailable: prepared={prepared} quorum={} failures={}",
        app.replication.quorum,
        failures.join(",")
    )))
}

fn commit_on_peers(app: &App, mutation: &Mutation) {
    if !app.replication.is_clustered() {
        return;
    }

    let payload = encode_mutation(mutation);
    for peer in app.replication.remote_peers() {
        match http_post(&peer.addr, "/internal/replication/commit", &payload) {
            Ok(response) if response.status_code == 200 => {}
            Ok(response) => eprintln!(
                "peer commit failed: peer {} returned HTTP status {}",
                peer.node_id, response.status_code
            ),
            Err(err) => eprintln!("peer commit failed: peer {} error {err}", peer.node_id),
        }
    }
}

fn abort_on_peers(app: &App, mutation: &Mutation) {
    let payload = encode_mutation(mutation);
    for peer in app.replication.remote_peers() {
        if let Err(err) = http_post(&peer.addr, "/internal/replication/abort", &payload) {
            eprintln!("peer abort failed: peer {} error {err}", peer.node_id);
        }
    }
}

fn prepare_replicated_mutation(app: &App, mutation: &Mutation) -> Result<()> {
    ensure_same_cluster(app, mutation)?;
    ensure_mutation_term(app, mutation)?;
    let state = lock_state(app)?;
    let shard_id = mutation.commit_id.shard_id;
    let current_seq = state
        .watermarks()
        .get(shard_id as usize)
        .copied()
        .ok_or_else(|| {
            GlobAclError::InvalidData(format!(
                "shard {shard_id} is outside shard_count {}",
                state.shard_count()
            ))
        })?;
    if mutation.commit_id.seq <= current_seq {
        return Ok(());
    }
    let expected_seq = current_seq + 1;
    if mutation.commit_id.seq != expected_seq {
        return Err(GlobAclError::Gap {
            shard_id,
            expected_seq,
            received_seq: mutation.commit_id.seq,
        });
    }
    write_pending_mutation(&app.pending_dir, mutation)
}

fn commit_replicated_mutation(
    app: &App,
    mutation: Mutation,
    require_pending: bool,
) -> Result<ApplyStatus> {
    ensure_same_cluster(app, &mutation)?;
    ensure_mutation_term(app, &mutation)?;
    let mut state = lock_state(app)?;
    let already_at_or_past_seq = state
        .watermarks()
        .get(mutation.commit_id.shard_id as usize)
        .copied()
        .unwrap_or(0)
        >= mutation.commit_id.seq;
    if require_pending && !already_at_or_past_seq {
        ensure_pending_mutation(&app.pending_dir, &mutation)?;
    }
    apply_prepared_mutation(app, &mut state, mutation)
}

fn ensure_same_cluster(app: &App, mutation: &Mutation) -> Result<()> {
    if mutation.commit_id.source_region == app.replication.cluster_id {
        return Ok(());
    }
    Err(GlobAclError::InvalidData(format!(
        "mutation cluster {} does not match local cluster {}",
        mutation.commit_id.source_region, app.replication.cluster_id
    )))
}

fn ensure_mutation_term(app: &App, mutation: &Mutation) -> Result<()> {
    let mut consensus = lock_consensus(app)?;
    if mutation.commit_id.epoch < consensus.current_term {
        return Err(GlobAclError::InvalidData(format!(
            "stale mutation epoch {} is older than local term {}",
            mutation.commit_id.epoch, consensus.current_term
        )));
    }
    if mutation.commit_id.epoch > consensus.current_term {
        consensus.current_term = mutation.commit_id.epoch;
        consensus.voted_for = None;
        consensus.role = ConsensusRole::Follower;
        consensus.leader_id = None;
        consensus.last_leader_contact_ms = now_unix_millis();
        consensus.election_deadline_ms = next_election_deadline_ms(
            &app.replication.node_id,
            app.replication.election_timeout_ms,
        );
        persist_consensus_state(&app.consensus_path, &consensus)?;
    }
    Ok(())
}
