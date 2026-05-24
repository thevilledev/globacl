fn handle_connection(mut stream: TcpStream, app: Arc<App>) -> Result<()> {
    let request = read_http_request(&mut stream)?;
    let (route, query) = parse_query_path(&request.path);

    if requires_leader(&request.method, &route)
        && app.replication.is_clustered()
        && !is_write_leader(&app)?
    {
        proxy_write_to_leader(&mut stream, &app, &request)?;
        return Ok(());
    }

    match (request.method.as_str(), route.as_str()) {
        ("GET", "/health") => {
            let state = lock_state(&app)?;
            let consensus = lock_consensus(&app)?.clone();
            let sync_status = lock_sync_status(&app)?.clone();
            let publisher_status = lock_publisher_status(&app)?.clone();
            let central_ack_count = lock_propagation_acks(&app)?.len();
            let max_published_seq = publisher_status
                .last_published
                .iter()
                .copied()
                .max()
                .unwrap_or(0);
            let body = format!(
                "status=ok\nrole={}\nnode_id={}\ncluster_id={}\nleader_id={}\nterm={}\nvoted_for={}\nwrite_authority={}\nquorum={}\npeer_count={}\nshard_count={}\nentries={}\nmutations={}\njetstream_publisher={}\nmax_published_seq={}\ncentral_ack_count={}\nlast_publish_unix={}\npublish_errors={}\nlast_peer_sync_unix={}\nsync_errors={}\n",
                consensus.role.as_str(),
                app.replication.node_id,
                app.replication.cluster_id,
                consensus.leader_id.as_deref().unwrap_or(""),
                consensus.current_term,
                consensus.voted_for.as_deref().unwrap_or(""),
                consensus.role == ConsensusRole::Leader,
                app.replication.quorum,
                app.replication.peers.len(),
                state.shard_count(),
                state.entries_len(),
                state.mutations_len(),
                app.publisher.is_some(),
                max_published_seq,
                central_ack_count,
                publisher_status.last_publish_unix,
                publisher_status.publish_errors,
                sync_status.last_peer_sync_unix,
                sync_status.sync_errors
            );
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/propagation/status") => {
            if app.replication.is_clustered() && !is_write_leader(&app)? {
                proxy_get_to_leader(&mut stream, &app, &request)?;
                return Ok(());
            }
            let body = format_propagation_status(&app)?;
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("POST", "/v1/ack") => {
            let form = parse_form_lines(&request.body)?;
            let ack = PropagationAck::from_form(&form)?;
            record_propagation_ack(&app, ack)?;
            write_http_response(&mut stream, 200, "text/plain", b"status=ok\n")?;
        }
        ("POST", "/internal/raft/request_vote") => {
            let form = parse_form_lines(&request.body)?;
            let response = handle_request_vote(&app, &form)?;
            write_http_response(&mut stream, 200, "text/plain", response.as_bytes())?;
        }
        ("POST", "/internal/raft/heartbeat") => {
            let form = parse_form_lines(&request.body)?;
            let response = handle_heartbeat(&app, &form)?;
            write_http_response(&mut stream, 200, "text/plain", response.as_bytes())?;
        }
        ("POST", "/internal/replication/prepare") => {
            let mutation = decode_mutation(&request.body)?;
            prepare_replicated_mutation(&app, &mutation)?;
            write_http_response(&mut stream, 200, "text/plain", b"status=prepared\n")?;
        }
        ("POST", "/internal/replication/commit") => {
            let mutation = decode_mutation(&request.body)?;
            let status = commit_replicated_mutation(&app, mutation, true)?;
            let body = match status {
                ApplyStatus::Applied => "status=applied\n",
                ApplyStatus::DuplicateOrOld => "status=duplicate\n",
            };
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("POST", "/internal/replication/abort") => {
            let mutation = decode_mutation(&request.body)?;
            remove_pending_mutation(&app.pending_dir, &mutation)?;
            write_http_response(&mut stream, 200, "text/plain", b"status=aborted\n")?;
        }
        ("POST", "/internal/replication/ack") => {
            let form = parse_form_lines(&request.body)?;
            let ack = PropagationAck::from_form(&form)?;
            let applied = apply_propagation_ack(&app, ack)?;
            let body = if applied {
                "status=applied\n"
            } else {
                "status=duplicate\n"
            };
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/internal/replication/acks") => {
            let body = format_propagation_ack_log_snapshot(&app)?;
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/internal/replication/idempotency") => {
            let mutations = {
                let state = lock_state(&app)?;
                state.idempotency_mutations()
            };
            let body = encode_mutation_stream(&mutations);
            write_http_response(&mut stream, 200, "application/octet-stream", &body)?;
        }
        ("POST", "/v1/deny") | ("POST", "/v1/mutation") => {
            let principal = match require_scope(&mut stream, &app, &request, "acl:write")? {
                Some(principal) => principal,
                None => return Ok(()),
            };
            let form = parse_form_lines(&request.body)?;
            let deny_request = DenyRequest::from_form(&form)?;
            if deny_requires_blast_radius_override(&deny_request)
                && !blast_radius_override_enabled(&form)
            {
                append_audit(
                    &app,
                    "deny",
                    "rejected",
                    &format!(
                        "op_id={} reason=blast_radius_override_required namespace={} key={} actor={}",
                        deny_request.op_id,
                        deny_request.namespace,
                        deny_request.key,
                        audit_actor(&principal, &deny_request.created_by)
                    ),
                )?;
                write_http_response(
                    &mut stream,
                    400,
                    "text/plain",
                    b"status=rejected\nreason=blast_radius_override_required\n",
                )?;
                return Ok(());
            }
            let outcome = commit_request(&app, deny_request)?;
            append_audit(
                &app,
                "deny",
                "committed",
                &format!(
                    "op_id={} shard_id={} seq={} duplicate={} actor={}",
                    outcome.mutation.op_id,
                    outcome.mutation.commit_id.shard_id,
                    outcome.mutation.commit_id.seq,
                    outcome.duplicate,
                    audit_actor(&principal, &outcome.mutation.entry.created_by)
                ),
            )?;
            let body = format_commit_outcome(&outcome);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("POST", "/v1/rule") => {
            let principal = match require_scope(&mut stream, &app, &request, "acl:write")? {
                Some(principal) => principal,
                None => return Ok(()),
            };
            let form = parse_form_lines(&request.body)?;
            let rule_request = RuleRequest::from_form(&form)?;
            if rule_requires_blast_radius_override(&rule_request)
                && !blast_radius_override_enabled(&form)
            {
                append_audit(
                    &app,
                    "rule",
                    "rejected",
                    &format!(
                        "op_id={} reason=blast_radius_override_required kind={} pattern={} actor={}",
                        rule_request.op_id,
                        rule_request.kind.as_str(),
                        rule_request.pattern,
                        audit_actor(&principal, &rule_request.created_by)
                    ),
                )?;
                write_http_response(
                    &mut stream,
                    400,
                    "text/plain",
                    b"status=rejected\nreason=blast_radius_override_required\n",
                )?;
                return Ok(());
            }
            let outcome = commit_rule_request(&app, rule_request)?;
            append_audit(
                &app,
                "rule",
                "committed",
                &format!(
                    "op_id={} shard_id={} seq={} duplicate={} actor={}",
                    outcome.mutation.op_id,
                    outcome.mutation.commit_id.shard_id,
                    outcome.mutation.commit_id.seq,
                    outcome.duplicate,
                    audit_actor(
                        &principal,
                        outcome
                            .mutation
                            .rule
                            .as_ref()
                            .map(|rule| rule.created_by.as_str())
                            .unwrap_or(&outcome.mutation.entry.created_by)
                    )
                ),
            )?;
            let body = format_commit_outcome(&outcome);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("POST", "/v1/canary") => {
            let principal = match require_scope(&mut stream, &app, &request, "acl:write")? {
                Some(principal) => principal,
                None => return Ok(()),
            };
            let canary = commit_canary(&app)?;
            append_audit(
                &app,
                "canary",
                "committed",
                &format!(
                    "op_id={} shard_id={} seq={} actor={}",
                    canary.op_id,
                    canary.shard_id,
                    canary.seq,
                    audit_actor(&principal, "globacl-commitd")
                ),
            )?;
            let body = format_canary_status(&canary);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/canary/latest") => {
            let latest = lock_canary(&app)?.clone();
            let body = latest
                .as_ref()
                .map(format_canary_status)
                .unwrap_or_else(|| "status=none\n".to_owned());
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/mutations") => {
            if let Some(compacted_seq) = compacted_seq_for_query(&app, &query)? {
                let body = format!(
                    "status=compacted\nreason=history_compacted\ncompacted_seq={compacted_seq}\n"
                );
                write_http_response(&mut stream, 409, "text/plain", body.as_bytes())?;
                return Ok(());
            }
            let mutations = mutations_for_query(&app, &query)?;
            let body = encode_mutation_stream(&mutations);
            write_http_response(&mut stream, 200, "application/octet-stream", &body)?;
        }
        ("GET", "/v1/mutations.sig") => {
            if let Some(compacted_seq) = compacted_seq_for_query(&app, &query)? {
                let body = format!(
                    "status=compacted\nreason=history_compacted\ncompacted_seq={compacted_seq}\n"
                );
                write_http_response(&mut stream, 409, "text/plain", body.as_bytes())?;
                return Ok(());
            }
            let mutations = mutations_for_query(&app, &query)?;
            let payload = encode_mutation_stream(&mutations);
            let body = sign_payload(&app, &payload)?;
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/watermarks") => {
            let body = {
                let state = lock_state(&app)?;
                format_watermarks(state.watermarks())
            };
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/compaction_watermarks") => {
            let body = {
                let state = lock_state(&app)?;
                format_watermarks(state.compacted_watermarks())
            };
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/delta_bundle") => {
            if let Some(compacted_seq) = compacted_seq_for_query(&app, &query)? {
                let body = format!(
                    "status=compacted\nreason=history_compacted\ncompacted_seq={compacted_seq}\n"
                );
                write_http_response(&mut stream, 409, "text/plain", body.as_bytes())?;
                return Ok(());
            }
            let mutations = delta_bundle_for_query(&app, &query)?;
            let body = encode_mutation_stream(&mutations);
            write_http_response(&mut stream, 200, "application/octet-stream", &body)?;
        }
        ("GET", "/v1/delta_bundle.sig") => {
            if let Some(compacted_seq) = compacted_seq_for_query(&app, &query)? {
                let body = format!(
                    "status=compacted\nreason=history_compacted\ncompacted_seq={compacted_seq}\n"
                );
                write_http_response(&mut stream, 409, "text/plain", body.as_bytes())?;
                return Ok(());
            }
            let mutations = delta_bundle_for_query(&app, &query)?;
            let payload = encode_mutation_stream(&mutations);
            let body = sign_payload(&app, &payload)?;
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/snapshot") => {
            let body = match fs::read(&app.snapshot_path) {
                Ok(bytes) => bytes,
                Err(_) => {
                    let state = lock_state(&app)?;
                    encode_snapshot(&state.snapshot())
                }
            };
            write_http_response(&mut stream, 200, "application/octet-stream", &body)?;
        }
        ("GET", "/v1/snapshot.sig") => {
            let body = match fs::read(signature_path(&app.snapshot_path)) {
                Ok(body) => body,
                Err(_) => match fs::read(&app.snapshot_path) {
                    Ok(bytes) => app.signature_signer.sign_payload(&bytes)?.into_bytes(),
                    Err(_) => Vec::new(),
                },
            };
            write_http_response(&mut stream, 200, "text/plain", &body)?;
        }
        ("GET", "/v1/snapshot_manifest") => {
            ensure_latest_snapshot_manifest(&app)?;
            let body = fs::read(&app.snapshot_manifest_path)?;
            write_http_response(&mut stream, 200, "text/plain", &body)?;
        }
        ("GET", "/v1/snapshot_manifest.sig") => {
            ensure_latest_snapshot_manifest(&app)?;
            let body = fs::read(signature_path(&app.snapshot_manifest_path))?;
            write_http_response(&mut stream, 200, "text/plain", &body)?;
        }
        ("GET", "/v1/snapshot_artifact") => {
            let object = required_query(&query, "object")?;
            if !is_safe_snapshot_object_name(object) {
                write_http_response(
                    &mut stream,
                    400,
                    "text/plain",
                    b"status=rejected\nreason=invalid_snapshot_object\n",
                )?;
                return Ok(());
            }
            let body = fs::read(app.snapshot_object_dir.join(object))?;
            write_http_response(&mut stream, 200, "application/octet-stream", &body)?;
        }
        ("GET", "/v1/snapshot_artifact.sig") => {
            let object = required_query(&query, "object")?;
            if !is_safe_snapshot_object_name(object) {
                write_http_response(
                    &mut stream,
                    400,
                    "text/plain",
                    b"status=rejected\nreason=invalid_snapshot_object\n",
                )?;
                return Ok(());
            }
            let body = fs::read(signature_path(app.snapshot_object_dir.join(object)))?;
            write_http_response(&mut stream, 200, "text/plain", &body)?;
        }
        ("GET", "/v1/snapshots") => {
            let body = format_snapshot_list(&app.snapshot_dir)?;
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("POST", "/v1/snapshot") => {
            let principal = match require_scope(&mut stream, &app, &request, "snapshot:write")? {
                Some(principal) => principal,
                None => return Ok(()),
            };
            let snapshot = decode_snapshot(&request.body)?;
            snapshot.validate()?;
            let archive_name = format!("uploaded_{}", now_unix());
            persist_archived_snapshot(&app, &snapshot, &archive_name)?;
            append_audit(
                &app,
                "snapshot",
                "uploaded",
                &format!(
                    "snapshot={archive_name}.gacl actor={}",
                    audit_actor(&principal, "unknown")
                ),
            )?;
            write_http_response(&mut stream, 200, "text/plain", b"status=ok\n")?;
        }
        ("POST", "/v1/rollback") => {
            let principal = match require_scope(&mut stream, &app, &request, "admin:rollback")? {
                Some(principal) => principal,
                None => return Ok(()),
            };
            let form = parse_form_lines(&request.body)?;
            let snapshot_name = form
                .get("snapshot")
                .map(String::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| GlobAclError::Parse("missing required field snapshot".to_owned()))?;
            if !is_safe_snapshot_name(snapshot_name) {
                write_http_response(
                    &mut stream,
                    400,
                    "text/plain",
                    b"status=rejected\nreason=invalid_snapshot_name\n",
                )?;
                return Ok(());
            }
            let snapshot_path = app.snapshot_dir.join(snapshot_name);
            let snapshot = decode_snapshot(&fs::read(&snapshot_path)?)?;
            let rollback_id = format!("rollback-{}", now_unix());
            let term = ensure_write_authority(&app)?;
            let mutations = {
                let mut state = lock_state(&app)?;
                state.set_epoch(term);
                let mut planned = state.clone();
                planned.set_epoch(term);
                let mutations = planned.restore_snapshot(snapshot, &rollback_id)?;
                for mutation in mutations.iter().cloned() {
                    commit_prepared_outcome(
                        &app,
                        &mut state,
                        globacl_core::CommitOutcome {
                            mutation,
                            duplicate: false,
                        },
                    )?;
                }
                mutations
            };
            let current_snapshot = {
                let state = lock_state(&app)?;
                state.snapshot()
            };
            persist_archived_snapshot(&app, &current_snapshot, &rollback_id)?;
            append_audit(
                &app,
                "rollback",
                "committed",
                &format!(
                    "snapshot={} mutations={} actor={}",
                    snapshot_name,
                    mutations.len(),
                    audit_actor(&principal, "unknown")
                ),
            )?;
            let body = format!(
                "status=ok\nsnapshot={}\nmutations={}\n",
                snapshot_name,
                mutations.len()
            );
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/audit") => {
            if require_scope(&mut stream, &app, &request, "audit:read")?.is_none() {
                return Ok(());
            }
            let body = fs::read(&app.audit_path).unwrap_or_default();
            write_http_response(&mut stream, 200, "text/plain", &body)?;
        }
        ("GET", "/v1/lookup") => {
            let tenant_id = required_query(&query, "tenant_id")?;
            let namespace = required_query(&query, "namespace")?;
            let key = required_query(&query, "key")?;
            let decision = {
                let state = lock_state(&app)?;
                state.lookup(tenant_id, namespace, key, now_unix())
            };
            let body = format_decision(&decision);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/check") => {
            let tenant_id = required_query(&query, "tenant_id")?;
            let namespace = required_query(&query, "namespace")?;
            let value = query
                .get("value")
                .or_else(|| query.get("key"))
                .map(String::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| GlobAclError::Parse("missing query parameter value".to_owned()))?;
            let decision = {
                let state = lock_state(&app)?;
                state.check(tenant_id, namespace, value, now_unix())
            };
            let body = format_decision(&decision);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        _ => {
            write_http_response(&mut stream, 404, "text/plain", b"not found\n")?;
        }
    }

    Ok(())
}

fn format_commitd_metrics(app: &App) -> Result<String> {
    let state = lock_state(app)?;
    let entries = state.entries_len();
    let mutations = state.mutations_len();
    let shard_count = state.shard_count();
    drop(state);

    let consensus = lock_consensus(app)?.clone();
    let sync_status = lock_sync_status(app)?.clone();
    let publisher_status = lock_publisher_status(app)?.clone();
    let central_ack_count = lock_propagation_acks(app)?.len();
    let max_published_seq = publisher_status
        .last_published
        .iter()
        .copied()
        .max()
        .unwrap_or(0);

    let mut out = String::new();
    let labels = [
        ("cluster_id", app.replication.cluster_id.as_str()),
        ("node_id", app.replication.node_id.as_str()),
        ("role", consensus.role.as_str()),
    ];
    append_prometheus_metric(
        &mut out,
        "globacl_commitd_up",
        "Commitd process is serving requests.",
        "gauge",
        &labels,
        1,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_commitd_write_authority",
        "Whether this commitd node currently has write authority.",
        "gauge",
        &labels,
        prometheus_bool(consensus.role == ConsensusRole::Leader || !app.replication.is_clustered()),
    );
    append_prometheus_metric(
        &mut out,
        "globacl_commitd_current_term",
        "Current fenced-leader consensus term.",
        "gauge",
        &labels,
        consensus.current_term,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_commitd_quorum",
        "Configured commit quorum.",
        "gauge",
        &labels,
        app.replication.quorum,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_commitd_peer_count",
        "Configured commit peer count.",
        "gauge",
        &labels,
        app.replication.peers.len(),
    );
    append_prometheus_metric(
        &mut out,
        "globacl_commitd_shard_count",
        "Number of configured ACL shards.",
        "gauge",
        &labels,
        shard_count,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_commitd_entries",
        "Materialized deny entry count.",
        "gauge",
        &labels,
        entries,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_commitd_mutations",
        "Retained committed mutation count.",
        "gauge",
        &labels,
        mutations,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_commitd_jetstream_publisher_enabled",
        "Whether commitd publishes committed mutations to JetStream.",
        "gauge",
        &labels,
        prometheus_bool(app.publisher.is_some()),
    );
    append_prometheus_metric(
        &mut out,
        "globacl_commitd_max_published_seq",
        "Maximum per-shard sequence published to the configured sink.",
        "gauge",
        &labels,
        max_published_seq,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_commitd_last_publish_unix",
        "Unix timestamp of the last successful publish loop.",
        "gauge",
        &labels,
        publisher_status.last_publish_unix,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_commitd_publish_errors_total",
        "Number of publish loop errors since process start.",
        "counter",
        &labels,
        publisher_status.publish_errors,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_commitd_last_peer_sync_unix",
        "Unix timestamp of the last successful follower catch-up sync.",
        "gauge",
        &labels,
        sync_status.last_peer_sync_unix,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_commitd_sync_errors_total",
        "Number of follower catch-up sync errors since process start.",
        "counter",
        &labels,
        sync_status.sync_errors,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_commitd_central_ack_count",
        "Number of latest propagation acknowledgements stored centrally.",
        "gauge",
        &labels,
        central_ack_count,
    );
    Ok(out)
}
