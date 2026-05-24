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

