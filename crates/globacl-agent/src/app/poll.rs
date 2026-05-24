fn poll_loop(app: Arc<App>, interval: Duration) {
    loop {
        if let Err(err) = poll_once(&app) {
            eprintln!("poll failed: {err}");
        }
        thread::sleep(interval);
    }
}

fn poll_once(app: &Arc<App>) -> Result<()> {
    let shard_count = {
        let state = current_state(app);
        state.shard_count()
    };
    let remote_watermarks = fetch_watermarks(app).ok();

    for shard_id in 0..shard_count {
        let from_seq = {
            let state = current_state(app);
            state.watermarks()[shard_id as usize]
        };
        if let Some(remote_watermarks) = &remote_watermarks {
            if remote_watermarks
                .get(shard_id as usize)
                .copied()
                .unwrap_or(from_seq)
                <= from_seq
            {
                continue;
            }
        }
        let path = format!("/v1/mutations?shard={shard_id}&from_seq={from_seq}");
        let response = http_get(&app.relay_addr, &path)?;
        if response.status_code == 409 || response.status_code == 410 {
            repair_from_snapshot(app)?;
            return Ok(());
        }
        if response.status_code != 200 {
            return Err(GlobAclError::InvalidData(format!(
                "relay returned status {} for {path}",
                response.status_code
            )));
        }
        let signature_path = format!("/v1/mutations.sig?shard={shard_id}&from_seq={from_seq}");
        verify_remote_payload_signature(
            &app.relay_addr,
            &signature_path,
            &response.body,
            &app.signature_verifier,
        )?;
        let mutations = decode_mutation_stream(&response.body)?;
        if mutations.is_empty() {
            continue;
        }

        let mut applied = 0u64;
        let (ack_seq, entries, snapshot, next_state) = {
            let current = current_state(app);
            let mut state = current.as_ref().clone();
            for mutation in &mutations {
                match state.apply_mutation(mutation) {
                    Ok(globacl_core::ApplyStatus::Applied) => applied += 1,
                    Ok(globacl_core::ApplyStatus::DuplicateOrOld) => {}
                    Err(GlobAclError::Gap {
                        shard_id,
                        expected_seq,
                        received_seq,
                    }) => {
                        drop(state);
                        repair_gap(
                            app,
                            shard_id,
                            expected_seq.saturating_sub(1),
                            received_seq.saturating_sub(1),
                        )?;
                        return Ok(());
                    }
                    Err(err) => return Err(err),
                }
            }
            if state.delta_entries_len() >= DELTA_COMPACT_THRESHOLD {
                state.compact_delta_overlay();
            }
            let ack_seq = state.watermarks()[shard_id as usize];
            let entries = state.entries_len();
            let snapshot = state.snapshot();
            (ack_seq, entries, snapshot, state)
        };
        write_snapshot_file(&app.snapshot_path, &snapshot)?;
        swap_state(app, next_state);

        let mut metrics = lock_metrics(app)?;
        metrics.last_sync_unix = now_unix();
        metrics.applied_mutations += applied;
        drop(metrics);

        send_ack(app, shard_id, ack_seq, entries)?;
    }

    check_canary(app)?;
    lock_metrics(app)?.last_successful_poll_unix = now_unix();
    Ok(())
}

fn fetch_watermarks(app: &Arc<App>) -> Result<Vec<u64>> {
    let response = http_get(&app.relay_addr, "/v1/watermarks")?;
    if response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "relay returned status {} for watermarks",
            response.status_code
        )));
    }
    parse_watermarks(&response.body)
}

fn repair_gap(app: &Arc<App>, shard_id: u16, from_seq: u64, to_seq: u64) -> Result<()> {
    if to_seq >= from_seq {
        let path = format!("/v1/delta_bundle?shard={shard_id}&from_seq={from_seq}&to_seq={to_seq}");
        let response = http_get(&app.relay_addr, &path)?;
        if response.status_code == 200 {
            let signature_path = format!(
                "/v1/delta_bundle.sig?shard={shard_id}&from_seq={from_seq}&to_seq={to_seq}"
            );
            verify_remote_payload_signature(
                &app.relay_addr,
                &signature_path,
                &response.body,
                &app.signature_verifier,
            )?;
            let mutations = decode_mutation_stream(&response.body)?;
            if !mutations.is_empty() {
                let current = current_state(app);
                let mut state = current.as_ref().clone();
                for mutation in &mutations {
                    state.apply_mutation(mutation)?;
                }
                if state.delta_entries_len() >= DELTA_COMPACT_THRESHOLD {
                    state.compact_delta_overlay();
                }
                let snapshot = state.snapshot();
                let seq = state.watermarks()[shard_id as usize];
                let entries = state.entries_len();
                write_snapshot_file(&app.snapshot_path, &snapshot)?;
                swap_state(app, state);
                send_ack(app, shard_id, seq, entries)?;
                let mut metrics = lock_metrics(app)?;
                metrics.last_sync_unix = now_unix();
                metrics.last_successful_poll_unix = metrics.last_sync_unix;
                metrics.repairs += 1;
                metrics.bundle_repairs += 1;
                return Ok(());
            }
        }
    }

    repair_from_snapshot(app)
}

fn repair_from_snapshot(app: &Arc<App>) -> Result<()> {
    let snapshot = fetch_snapshot(&app.relay_addr, &app.signature_verifier)?;
    write_snapshot_file(&app.snapshot_path, &snapshot)?;
    let mut ack_targets = Vec::new();
    let state = ActiveState::from_snapshot(snapshot)?;
    for (shard_id, seq) in state.watermarks().iter().copied().enumerate() {
        if seq > 0 {
            ack_targets.push((shard_id as u16, seq, state.entries_len()));
        }
    }
    swap_state(app, state);
    for (shard_id, seq, entries) in ack_targets {
        send_ack(app, shard_id, seq, entries)?;
    }
    let mut metrics = lock_metrics(app)?;
    metrics.last_sync_unix = now_unix();
    metrics.last_successful_poll_unix = metrics.last_sync_unix;
    metrics.repairs += 1;
    metrics.snapshot_repairs += 1;
    Ok(())
}

fn send_ack(app: &Arc<App>, shard_id: u16, seq: u64, entries: usize) -> Result<()> {
    let ack = PopAck {
        agent_id: app.agent_id.clone(),
        shard_id,
        seq,
        entries,
        applied_at_unix: now_unix(),
    };
    let response =
        globacl_core::http_post(&app.relay_addr, "/v1/ack", ack.to_json_body().as_bytes())?;
    if response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "relay returned status {} for ack",
            response.status_code
        )));
    }
    Ok(())
}

fn check_canary(app: &Arc<App>) -> Result<()> {
    let response = http_get(&app.relay_addr, "/v1/canary/latest")?;
    if response.status_code != 200 {
        return Ok(());
    }
    let form = parse_json_fields(&response.body)?;
    if form.get("status").map(String::as_str) != Some("ok") {
        return Ok(());
    }
    let Some(key) = form.get("key") else {
        return Ok(());
    };
    let canary_seq = form
        .get("seq")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let decision = {
        let state = current_state(app);
        state.lookup("globacl", "canary", key, now_unix())
    };
    if matches!(decision, Decision::Deny { .. }) {
        let mut metrics = lock_metrics(app)?;
        metrics.last_canary_key = key.clone();
        metrics.last_canary_seq = canary_seq;
        metrics.last_canary_seen_unix = now_unix();
    }
    Ok(())
}

