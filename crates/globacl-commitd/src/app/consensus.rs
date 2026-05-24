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
    let (last_seq, log_len) = local_log_status(app)?;
    let (term, last_seq, log_len) = {
        let mut consensus = lock_consensus(app)?;
        consensus.current_term += 1;
        consensus.voted_for = Some(app.replication.node_id.clone());
        consensus.role = ConsensusRole::Candidate;
        consensus.leader_id = None;
        consensus.last_leader_contact_ms = 0;
        consensus.election_deadline_ms = next_election_deadline_ms(
            &app.replication.node_id,
            app.replication.election_timeout_ms,
        );
        persist_consensus_state(&app.consensus_path, &consensus)?;
        (consensus.current_term, last_seq, log_len)
    };

    let mut votes = 1usize;
    for peer in app.replication.remote_peers() {
        let body = format!(
            "term={term}\ncandidate_id={}\nlast_seq={last_seq}\nlog_len={log_len}\n",
            app.replication.node_id
        );
        match http_post(&peer.addr, "/internal/raft/request_vote", body.as_bytes()) {
            Ok(response) if response.status_code == 200 => {
                let form = parse_form_lines(&response.body)?;
                let peer_term = parse_form_u64(&form, "term", term)?;
                if peer_term > term {
                    step_down_to_term(app, peer_term, None)?;
                    return Ok(());
                }
                if form_bool(&form, "vote_granted") {
                    votes += 1;
                }
            }
            Ok(response) => eprintln!(
                "vote request failed: peer={} status={}",
                peer.node_id, response.status_code
            ),
            Err(err) => eprintln!("vote request failed: peer={} error={err}", peer.node_id),
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
            if let Err(err) = sync_acks_from_peers(app) {
                eprintln!("leader ack merge failed: {err}");
            }
            send_heartbeats(app);
        }
    }

    Ok(())
}

fn send_heartbeats(app: &App) {
    let term = match lock_consensus(app) {
        Ok(consensus) if consensus.role == ConsensusRole::Leader => consensus.current_term,
        _ => return,
    };

    let body = format!("term={term}\nleader_id={}\n", app.replication.node_id);
    for peer in app.replication.remote_peers() {
        match http_post(&peer.addr, "/internal/raft/heartbeat", body.as_bytes()) {
            Ok(response) if response.status_code == 200 => {
                if let Ok(form) = parse_form_lines(&response.body) {
                    if let Ok(peer_term) = parse_form_u64(&form, "term", term) {
                        if peer_term > term {
                            let _ = step_down_to_term(app, peer_term, None);
                            return;
                        }
                    }
                }
            }
            Ok(response) => eprintln!(
                "heartbeat failed: peer={} status={}",
                peer.node_id, response.status_code
            ),
            Err(err) => eprintln!("heartbeat failed: peer={} error={err}", peer.node_id),
        }
    }
}

fn handle_request_vote(
    app: &App,
    form: &std::collections::HashMap<String, String>,
) -> Result<String> {
    let candidate_term = parse_form_u64(form, "term", 0)?;
    let candidate_id = required_form(form, "candidate_id")?;
    let candidate_last_seq = parse_form_u64(form, "last_seq", 0)?;
    let candidate_log_len = parse_form_u64(form, "log_len", 0)?;
    let (local_last_seq, local_log_len) = local_log_status(app)?;

    let mut consensus = lock_consensus(app)?;
    if candidate_term > consensus.current_term {
        consensus.current_term = candidate_term;
        consensus.voted_for = None;
        consensus.role = ConsensusRole::Follower;
        consensus.leader_id = None;
    }

    let up_to_date = candidate_last_seq > local_last_seq
        || (candidate_last_seq == local_last_seq && candidate_log_len >= local_log_len);
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

    Ok(format!(
        "term={}\nvote_granted={}\n",
        consensus.current_term, can_vote
    ))
}

fn handle_heartbeat(app: &App, form: &std::collections::HashMap<String, String>) -> Result<String> {
    let leader_term = parse_form_u64(form, "term", 0)?;
    let leader_id = required_form(form, "leader_id")?;
    let mut consensus = lock_consensus(app)?;
    let higher_term = leader_term > consensus.current_term;
    let same_term = leader_term == consensus.current_term;
    let conflicting_leader = same_term
        && consensus
            .leader_id
            .as_ref()
            .map(|known_leader| known_leader != leader_id)
            .unwrap_or(false);
    let conflicting_vote = same_term
        && consensus
            .voted_for
            .as_ref()
            .map(|voted_for| voted_for != leader_id)
            .unwrap_or(false);
    let accepted = higher_term || (same_term && !conflicting_leader && !conflicting_vote);

    if accepted {
        consensus.current_term = leader_term;
        if higher_term {
            consensus.voted_for = None;
        }
        consensus.role = ConsensusRole::Follower;
        consensus.leader_id = Some(leader_id.to_owned());
        if consensus.voted_for.is_none() {
            consensus.voted_for = Some(leader_id.to_owned());
        }
        consensus.last_leader_contact_ms = now_unix_millis();
        consensus.election_deadline_ms = next_election_deadline_ms(
            &app.replication.node_id,
            app.replication.election_timeout_ms,
        );
        persist_consensus_state(&app.consensus_path, &consensus)?;
    }

    Ok(format!(
        "term={}\nsuccess={}\n",
        consensus.current_term, accepted
    ))
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
    let leader_addr = current_leader_addr(app)?
        .ok_or_else(|| GlobAclError::InvalidData("leader address is not configured".to_owned()))?;
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
            commit_replicated_mutation(app, mutation, false)?;
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

    let idempotency_response = http_get(leader_addr, "/internal/replication/idempotency")?;
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

