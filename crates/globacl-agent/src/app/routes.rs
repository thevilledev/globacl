fn handle_connection(mut stream: TcpStream, app: Arc<App>) -> Result<()> {
    let request = read_http_request(&mut stream)?;
    let (route, query) = parse_query_path(&request.path);

    match (request.method.as_str(), route.as_str()) {
        ("GET", "/health") => {
            let state = current_state(&app);
            let metrics = lock_metrics(&app)?;
            let max_seq = state.watermarks().iter().copied().max().unwrap_or(0);
            let stats = state.stats();
            let now = now_unix();
            let poll_lag_secs = now.saturating_sub(metrics.last_successful_poll_unix);
            let state_lag_secs = now.saturating_sub(metrics.last_sync_unix);
            let stale = poll_lag_secs > app.stale_after_secs;
            let status = if stale { "stale" } else { "ok" };
            let body = format!(
                "status={status}\nrole=agent\nagent_id={}\nshard_count={}\nentries={}\nbase_entries={}\ndelta_adds={}\ndelta_removes={}\nbase_rules={}\ndelta_rule_adds={}\ndelta_rule_removes={}\nfilter_bits={}\nfilter_hashes={}\nestimated_state_bytes={}\nmax_seq={}\nlast_sync_unix={}\nlast_successful_poll_unix={}\nstate_lag_secs={}\npoll_lag_secs={}\nstale_after_secs={}\nstale={}\napplied_mutations={}\nrepairs={}\nbundle_repairs={}\nsnapshot_repairs={}\nlast_canary_key={}\nlast_canary_seq={}\nlast_canary_seen_unix={}\n",
                app.agent_id,
                state.shard_count(),
                state.entries_len(),
                stats.base_entries,
                stats.delta_adds,
                stats.delta_removes,
                stats.base_rules,
                stats.delta_rule_adds,
                stats.delta_rule_removes,
                stats.filter_bits,
                stats.filter_hashes,
                stats.estimated_bytes,
                max_seq,
                metrics.last_sync_unix,
                metrics.last_successful_poll_unix,
                state_lag_secs,
                poll_lag_secs,
                app.stale_after_secs,
                stale,
                metrics.applied_mutations,
                metrics.repairs,
                metrics.bundle_repairs,
                metrics.snapshot_repairs,
                metrics.last_canary_key,
                metrics.last_canary_seq,
                metrics.last_canary_seen_unix
            );
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/lookup") => {
            let tenant_id = required_query(&query, "tenant_id")?;
            let namespace = required_query(&query, "namespace")?;
            let key = required_query(&query, "key")?;
            let decision = {
                let state = current_state(&app);
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
                let state = current_state(&app);
                state.check(tenant_id, namespace, value, now_unix())
            };
            let body = format_decision(&decision);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/snapshot") => {
            let snapshot = {
                let state = current_state(&app);
                state.snapshot()
            };
            let body = encode_snapshot(&snapshot);
            write_http_response(&mut stream, 200, "application/octet-stream", &body)?;
        }
        _ => {
            write_http_response(&mut stream, 404, "text/plain", b"not found\n")?;
        }
    }

    Ok(())
}

fn format_agent_metrics(app: &App) -> Result<String> {
    let state = current_state(app);
    let metrics = lock_metrics(app)?;
    let max_seq = state.watermarks().iter().copied().max().unwrap_or(0);
    let stats = state.stats();
    let now = now_unix();
    let poll_lag_secs = now.saturating_sub(metrics.last_successful_poll_unix);
    let state_lag_secs = now.saturating_sub(metrics.last_sync_unix);
    let stale = poll_lag_secs > app.stale_after_secs;
    let labels = [("agent_id", app.agent_id.as_str())];

    let mut out = String::new();
    append_prometheus_metric(
        &mut out,
        "globacl_agent_up",
        "Agent process is serving requests.",
        "gauge",
        &labels,
        1,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_stale",
        "Whether the agent has exceeded its poll-lag staleness budget.",
        "gauge",
        &labels,
        if stale { 1 } else { 0 },
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_shard_count",
        "Number of configured ACL shards.",
        "gauge",
        &labels,
        state.shard_count(),
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_entries",
        "Materialized deny entry count.",
        "gauge",
        &labels,
        state.entries_len(),
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_base_entries",
        "Immutable-base deny entry count.",
        "gauge",
        &labels,
        stats.base_entries,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_delta_adds",
        "Mutable overlay deny add count.",
        "gauge",
        &labels,
        stats.delta_adds,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_delta_removes",
        "Mutable overlay deny tombstone count.",
        "gauge",
        &labels,
        stats.delta_removes,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_base_rules",
        "Immutable-base compiled rule count.",
        "gauge",
        &labels,
        stats.base_rules,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_delta_rule_adds",
        "Mutable overlay compiled rule add count.",
        "gauge",
        &labels,
        stats.delta_rule_adds,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_delta_rule_removes",
        "Mutable overlay compiled rule tombstone count.",
        "gauge",
        &labels,
        stats.delta_rule_removes,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_filter_bits",
        "Negative-filter bit count in the immutable base.",
        "gauge",
        &labels,
        stats.filter_bits,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_filter_hashes",
        "Negative-filter hash function count.",
        "gauge",
        &labels,
        stats.filter_hashes,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_estimated_state_bytes",
        "Estimated edge state memory bytes.",
        "gauge",
        &labels,
        stats.estimated_bytes,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_max_seq",
        "Maximum applied sequence across all shards.",
        "gauge",
        &labels,
        max_seq,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_last_sync_unix",
        "Unix timestamp of the last mutation application or repair.",
        "gauge",
        &labels,
        metrics.last_sync_unix,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_last_successful_poll_unix",
        "Unix timestamp of the last successful polling loop.",
        "gauge",
        &labels,
        metrics.last_successful_poll_unix,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_state_lag_secs",
        "Seconds since the last mutation application or repair.",
        "gauge",
        &labels,
        state_lag_secs,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_poll_lag_secs",
        "Seconds since the last successful polling loop.",
        "gauge",
        &labels,
        poll_lag_secs,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_stale_after_secs",
        "Configured poll-lag staleness budget in seconds.",
        "gauge",
        &labels,
        app.stale_after_secs,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_applied_mutations_total",
        "Number of applied mutations since process start.",
        "counter",
        &labels,
        metrics.applied_mutations,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_repairs_total",
        "Number of repair attempts since process start.",
        "counter",
        &labels,
        metrics.repairs,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_bundle_repairs_total",
        "Number of delta-bundle repairs since process start.",
        "counter",
        &labels,
        metrics.bundle_repairs,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_snapshot_repairs_total",
        "Number of snapshot repairs since process start.",
        "counter",
        &labels,
        metrics.snapshot_repairs,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_last_canary_seq",
        "Last observed synthetic canary sequence.",
        "gauge",
        &labels,
        metrics.last_canary_seq,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_agent_last_canary_seen_unix",
        "Unix timestamp of the last observed synthetic canary.",
        "gauge",
        &labels,
        metrics.last_canary_seen_unix,
    );
    Ok(out)
}
