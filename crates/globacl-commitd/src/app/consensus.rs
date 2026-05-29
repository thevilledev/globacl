fn is_safe_snapshot_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && name.ends_with(".gacl")
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

fn consensus_loop(app: Arc<App>) {
    if !app.replication.is_clustered() {
        return;
    }

    loop {
        let role = lock_consensus(&app)
            .map(|consensus| consensus.role)
            .unwrap_or(ConsensusRole::Follower);

        match role {
            ConsensusRole::Leader => {
                send_heartbeats(&app);
                thread::sleep(Duration::from_millis(app.replication.heartbeat_interval_ms));
            }
            ConsensusRole::Follower | ConsensusRole::Candidate => {
                let should_start_election = lock_consensus(&app)
                    .map(|consensus| now_unix_millis() >= consensus.election_deadline_ms)
                    .unwrap_or(false);
                if should_start_election {
                    if let Err(err) = start_election(&app) {
                        eprintln!("leader election failed: {err}");
                    }
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn start_election(app: &App) -> Result<()> {
    let (last_seq, log_len, watermarks) = local_log_status(app)?;
    let (term, last_seq, log_len, watermarks) = {
        let mut consensus = lock_consensus(app)?;
        consensus.current_term = consensus
            .current_term
            .checked_add(1)
            .ok_or_else(|| GlobAclError::InvalidData("consensus term overflow".to_owned()))?;
        consensus.voted_for = Some(app.replication.node_id.clone());
        consensus.role = ConsensusRole::Candidate;
        consensus.leader_id = None;
        consensus.last_leader_contact_ms = 0;
        consensus.election_deadline_ms = next_election_deadline_ms(
            &app.replication.node_id,
            app.replication.election_timeout_ms,
        );
        persist_consensus_state(&app.consensus_path, &consensus)?;
        (consensus.current_term, last_seq, log_len, watermarks)
    };

    let mut votes = 1usize;
    for peer in app.replication.remote_peers() {
        let body = json!({
            "cluster_id": app.replication.cluster_id,
            "term": term,
            "candidate_id": app.replication.node_id,
            "last_seq": last_seq,
            "log_len": log_len,
            "watermarks": watermarks
        })
        .to_string();
        let headers = peer_headers(app);
        match http_post_with_headers(
            &peer.addr,
            "/internal/raft/request_vote",
            body.as_bytes(),
            &headers,
        ) {
            Ok(response) if response.status_code == 200 => {
                let fields = parse_json_fields(&response.body)?;
                let peer_term = parse_json_u64(&fields, "term", term)?;
                if peer_term > term {
                    step_down_to_term(app, peer_term, None)?;
                    return Ok(());
                }
                if json_bool(&fields, "vote_granted") {
                    votes += 1;
                }
            }
            Ok(response) => eprintln!(
                "vote request failed: peer {} returned HTTP status {}",
                peer.node_id, response.status_code
            ),
            Err(err) => eprintln!("vote request failed: peer {} error {err}", peer.node_id),
        }
    }

    if votes >= app.replication.quorum {
        let mut consensus = lock_consensus(app)?;
        if consensus.current_term == term && consensus.role == ConsensusRole::Candidate {
            consensus.role = ConsensusRole::Leader;
            consensus.leader_id = Some(app.replication.node_id.clone());
            consensus.last_leader_contact_ms = now_unix_millis();
            persist_consensus_state(&app.consensus_path, &consensus)?;
            drop(consensus);
            if let Err(err) = recover_pending_mutations_as_leader(app) {
                eprintln!("leader pending recovery failed: {err}");
                let _ = step_down_to_term(app, term, None);
                return Ok(());
            }
            if let Err(err) = sync_acks_from_peers(app) {
                eprintln!("leader ack merge failed: {err}");
            }
            send_heartbeats(app);
        }
    }

    Ok(())
}

fn recover_pending_mutations_as_leader(app: &App) -> Result<usize> {
    let term = ensure_write_authority(app)?;
    let pending = load_pending_mutations(&app.pending_dir)?;
    let mut recovered = 0usize;
    for mut mutation in pending {
        if mutation.commit_id.source_region != app.replication.cluster_id {
            continue;
        }
        mutation.commit_id.epoch = term;
        let mut state = lock_state(app)?;
        let shard_id = mutation.commit_id.shard_id;
        let current_seq = state
            .watermarks()
            .get(shard_id as usize)
            .copied()
            .ok_or_else(|| {
                GlobAclError::InvalidData(format!(
                    "pending mutation shard {shard_id} is outside shard_count {}",
                    state.shard_count()
                ))
            })?;
        if mutation.commit_id.seq <= current_seq {
            remove_pending_mutation(&app.pending_dir, &mutation)?;
            continue;
        }
        let expected_seq = current_seq + 1;
        if mutation.commit_id.seq != expected_seq {
            return Err(GlobAclError::Gap {
                shard_id,
                expected_seq,
                received_seq: mutation.commit_id.seq,
            });
        }
        commit_prepared_outcome(
            app,
            &mut state,
            globacl_core::CommitOutcome {
                mutation,
                duplicate: false,
            },
        )?;
        recovered += 1;
    }
    Ok(recovered)
}

fn send_heartbeats(app: &App) {
    let term = match lock_consensus(app) {
        Ok(consensus) if consensus.role == ConsensusRole::Leader => consensus.current_term,
        _ => return,
    };

    let body = json!({
        "cluster_id": app.replication.cluster_id,
        "term": term,
        "leader_id": app.replication.node_id
    })
    .to_string();
    for peer in app.replication.remote_peers() {
        let headers = peer_headers(app);
        match http_post_with_headers(
            &peer.addr,
            "/internal/raft/heartbeat",
            body.as_bytes(),
            &headers,
        ) {
            Ok(response) if response.status_code == 200 => {
                if let Ok(fields) = parse_json_fields(&response.body) {
                    if let Ok(peer_term) = parse_json_u64(&fields, "term", term) {
                        if peer_term > term {
                            let _ = step_down_to_term(app, peer_term, None);
                            return;
                        }
                    }
                }
            }
            Ok(response) => eprintln!(
                "heartbeat failed: peer {} returned HTTP status {}",
                peer.node_id, response.status_code
            ),
            Err(err) => eprintln!("heartbeat failed: peer {} error {err}", peer.node_id),
        }
    }
}

fn handle_request_vote(
    app: &App,
    fields: &std::collections::HashMap<String, String>,
) -> Result<String> {
    ensure_peer_cluster(app, fields)?;
    let candidate_term = parse_json_u64(fields, "term", 0)?;
    let candidate_id = required_json_field(fields, "candidate_id")?;
    ensure_remote_peer_id(app, candidate_id, "vote candidate")?;
    let candidate_last_seq = parse_json_u64(fields, "last_seq", 0)?;
    let candidate_log_len = parse_json_u64(fields, "log_len", 0)?;
    let (local_last_seq, local_log_len, local_watermarks) = local_log_status(app)?;

    let mut consensus = lock_consensus(app)?;
    if candidate_term > consensus.current_term {
        consensus.current_term = candidate_term;
        consensus.voted_for = None;
        consensus.role = ConsensusRole::Follower;
        consensus.leader_id = None;
    }

    let up_to_date = if let Some(candidate_watermarks) = vote_watermarks(fields)? {
        candidate_watermarks.len() == local_watermarks.len()
            && candidate_watermarks
                .iter()
                .zip(local_watermarks.iter())
                .all(|(candidate, local)| candidate >= local)
    } else {
        candidate_last_seq > local_last_seq
            || (candidate_last_seq == local_last_seq && candidate_log_len >= local_log_len)
    };
    let no_conflicting_leader = consensus
        .leader_id
        .as_ref()
        .map(|leader_id| leader_id == candidate_id)
        .unwrap_or(true);
    let can_vote = candidate_term == consensus.current_term
        && up_to_date
        && no_conflicting_leader
        && consensus
            .voted_for
            .as_ref()
            .map(|voted_for| voted_for == candidate_id)
            .unwrap_or(true);

    if can_vote {
        consensus.voted_for = Some(candidate_id.to_owned());
        consensus.role = ConsensusRole::Follower;
        consensus.leader_id = None;
        consensus.last_leader_contact_ms = now_unix_millis();
        consensus.election_deadline_ms = next_election_deadline_ms(
            &app.replication.node_id,
            app.replication.election_timeout_ms,
        );
        persist_consensus_state(&app.consensus_path, &consensus)?;
    } else if candidate_term >= consensus.current_term {
        persist_consensus_state(&app.consensus_path, &consensus)?;
    }

    Ok(json!({
        "term": consensus.current_term,
        "vote_granted": can_vote
    })
    .to_string())
}

fn vote_watermarks(
    fields: &std::collections::HashMap<String, String>,
) -> Result<Option<Vec<u64>>> {
    let Some(raw) = fields.get("watermarks").filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let value = parse_json_body(raw.as_bytes())?;
    let array = value
        .as_array()
        .ok_or_else(|| GlobAclError::Parse("vote watermarks must be a JSON array".to_owned()))?;
    let mut watermarks = Vec::with_capacity(array.len());
    for value in array {
        watermarks.push(value.as_u64().ok_or_else(|| {
            GlobAclError::Parse("vote watermarks must contain unsigned integers".to_owned())
        })?);
    }
    Ok(Some(watermarks))
}

fn ensure_peer_cluster(
    app: &App,
    fields: &std::collections::HashMap<String, String>,
) -> Result<()> {
    let cluster_id = required_json_field(fields, "cluster_id")?;
    if cluster_id == app.replication.cluster_id {
        return Ok(());
    }
    Err(GlobAclError::InvalidData(format!(
        "peer cluster {cluster_id} does not match local cluster {}",
        app.replication.cluster_id
    )))
}

fn ensure_remote_peer_id(app: &App, node_id: &str, role: &str) -> Result<()> {
    if node_id == app.replication.node_id {
        return Err(GlobAclError::InvalidData(format!(
            "{role} {node_id} is this node"
        )));
    }
    if app.replication.peer_addr(node_id).is_some() {
        return Ok(());
    }
    Err(GlobAclError::InvalidData(format!(
        "unknown {role} {node_id}"
    )))
}

fn handle_heartbeat(
    app: &App,
    fields: &std::collections::HashMap<String, String>,
) -> Result<String> {
    ensure_peer_cluster(app, fields)?;
    let leader_term = parse_json_u64(fields, "term", 0)?;
    let leader_id = required_json_field(fields, "leader_id")?;
    ensure_remote_peer_id(app, leader_id, "heartbeat leader")?;
    let mut consensus = lock_consensus(app)?;
    let higher_term = leader_term > consensus.current_term;
    let same_term = leader_term == consensus.current_term;
    let conflicting_leader = same_term
        && consensus
            .leader_id
            .as_ref()
            .map(|known_leader| known_leader != leader_id)
            .unwrap_or(false);
    let accepted = higher_term || (same_term && !conflicting_leader);

    if accepted {
        consensus.current_term = leader_term;
        if higher_term {
            consensus.voted_for = None;
        }
        consensus.role = ConsensusRole::Follower;
        consensus.leader_id = Some(leader_id.to_owned());
        consensus.last_leader_contact_ms = now_unix_millis();
        consensus.election_deadline_ms = next_election_deadline_ms(
            &app.replication.node_id,
            app.replication.election_timeout_ms,
        );
        persist_consensus_state(&app.consensus_path, &consensus)?;
    }

    Ok(json!({
        "term": consensus.current_term,
        "success": accepted
    })
    .to_string())
}

fn step_down_to_term(app: &App, term: u64, leader_id: Option<String>) -> Result<()> {
    let mut consensus = lock_consensus(app)?;
    if term > consensus.current_term {
        consensus.current_term = term;
        consensus.voted_for = None;
    }
    consensus.role = ConsensusRole::Follower;
    consensus.leader_id = leader_id;
    consensus.last_leader_contact_ms = now_unix_millis();
    consensus.election_deadline_ms = next_election_deadline_ms(
        &app.replication.node_id,
        app.replication.election_timeout_ms,
    );
    persist_consensus_state(&app.consensus_path, &consensus)
}

fn control_sync_loop(app: Arc<App>, interval: Duration) {
    loop {
        if let Err(err) = sync_from_leader(&app) {
            eprintln!("commitd peer sync failed: {err}");
            if let Ok(mut status) = lock_sync_status(&app) {
                status.sync_errors += 1;
            }
        }
        thread::sleep(interval);
    }
}

fn sync_from_leader(app: &App) -> Result<()> {
    if is_write_leader(app)? {
        return Ok(());
    }
    let Some((leader_id, leader_addr)) = current_leader_peer(app)? else {
        return Ok(());
    };
    let watermarks_response = http_get(&leader_addr, "/v1/watermarks")?;
    if watermarks_response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "leader returned status {} for watermarks",
            watermarks_response.status_code
        )));
    }
    let remote_watermarks = parse_watermarks(&watermarks_response.body)?;
    let remote_compacted_watermarks = fetch_compaction_watermarks(&leader_addr)
        .unwrap_or_else(|| vec![0; remote_watermarks.len()]);
    let shard_count = {
        let state = lock_state(app)?;
        state.shard_count()
    };

    let needs_snapshot = {
        let state = lock_state(app)?;
        (0..shard_count).any(|shard_id| {
            let shard_index = shard_id as usize;
            let local_seq = state.watermarks()[shard_index];
            let remote_seq = remote_watermarks
                .get(shard_index)
                .copied()
                .unwrap_or(local_seq);
            let compacted_seq = remote_compacted_watermarks
                .get(shard_index)
                .copied()
                .unwrap_or(0);
            remote_seq > local_seq && local_seq < compacted_seq
        })
    };
    if needs_snapshot {
        install_snapshot_from_leader(app, &leader_addr)?;
    }

    for shard_id in 0..shard_count {
        let local_seq = {
            let state = lock_state(app)?;
            state.watermarks()[shard_id as usize]
        };
        let remote_seq = remote_watermarks
            .get(shard_id as usize)
            .copied()
            .unwrap_or(local_seq);
        if remote_seq <= local_seq {
            continue;
        }

        let path = format!("/v1/mutations?shard={shard_id}&from_seq={local_seq}");
        let response = http_get(&leader_addr, &path)?;
        if response.status_code == 409 || response.status_code == 410 {
            install_snapshot_from_leader(app, &leader_addr)?;
            continue;
        }
        if response.status_code != 200 {
            return Err(GlobAclError::InvalidData(format!(
                "leader returned status {} for {path}",
                response.status_code
            )));
        }
        for mutation in decode_mutation_stream(&response.body)? {
            commit_replicated_mutation_from_leader(app, mutation, false, &leader_id)?;
        }
    }

    sync_acks_from_peer(app, &leader_addr)?;

    let mut status = lock_sync_status(app)?;
    status.last_peer_sync_unix = now_unix();
    Ok(())
}

fn fetch_compaction_watermarks(leader_addr: &str) -> Option<Vec<u64>> {
    let response = http_get(leader_addr, "/v1/compaction_watermarks").ok()?;
    (response.status_code == 200).then_some(())?;
    parse_watermarks(&response.body).ok()
}

fn install_snapshot_from_leader(app: &App, leader_addr: &str) -> Result<()> {
    let shard_count = {
        let state = lock_state(app)?;
        state.shard_count()
    };

    let snapshot_response = http_get(leader_addr, "/v1/snapshot")?;
    if snapshot_response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "leader returned status {} for snapshot",
            snapshot_response.status_code
        )));
    }
    let snapshot = decode_snapshot(&snapshot_response.body)?;
    snapshot.validate()?;

    let headers = peer_headers(app);
    let idempotency_response =
        http_get_with_headers(leader_addr, "/internal/replication/idempotency", &headers)?;
    if idempotency_response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "leader returned status {} for idempotency snapshot",
            idempotency_response.status_code
        )));
    }
    let idempotency_mutations = decode_mutation_stream(&idempotency_response.body)?;

    let mut rebuilt = SourceOfTruth::from_snapshot_and_mutations(
        shard_count,
        &app.replication.cluster_id,
        snapshot,
        idempotency_mutations,
        Vec::new(),
    )?;
    let snapshot = rebuilt.snapshot();
    persist_latest_snapshot(app, &snapshot)?;
    persist_idempotency_snapshot(&app.idempotency_path, &rebuilt.idempotency_mutations())?;
    compact_logs_to_watermarks(&app.log_dir, rebuilt.shard_count(), &snapshot.watermarks)?;
    rebuilt.compact_mutation_history(&snapshot.watermarks)?;

    let mut state = lock_state(app)?;
    *state = rebuilt;
    Ok(())
}
