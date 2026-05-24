fn handle_connection(mut stream: TcpStream, app: Arc<App>) -> Result<()> {
    let request = read_http_request(&mut stream)?;
    let (route, _) = parse_query_path(&request.path);

    match request.method.as_str() {
        "GET" if route == "/health" => {
            let health = app.source.health()?;
            let ack_count = lock_acks(&app)?.len();
            let ack_forward_status = lock_ack_forward_status(&app)?.clone();
            let status = if health.ok { "ok" } else { "degraded" };
            let upstream = if health.ok { "ok" } else { "bad" };
            let source_details = parse_json_body(health.details.as_bytes())
                .unwrap_or_else(|_| json!({"source_parse_error": true}));
            let mut body = json!({
                "status": status,
                "role": "relay",
                "relay_id": app.relay_id.as_str(),
                "location": app.location.as_str(),
                "source": app.source.kind(),
                "upstream": upstream,
                "upstream_addr": app.source.upstream_addr(),
                "ack_count": ack_count,
                "last_ack_forward_unix": ack_forward_status.last_ack_forward_unix,
                "ack_forward_errors": ack_forward_status.ack_forward_errors
            });
            if let (Some(body), Some(source_details)) =
                (body.as_object_mut(), source_details.as_object())
            {
                for (key, value) in source_details {
                    if !body.contains_key(key)
                        && (value.is_string() || value.is_number() || value.is_boolean())
                    {
                        body.insert(key.clone(), value.clone());
                    }
                }
            }
            write_json_response(
                &mut stream,
                200,
                &body,
            )?;
        }
        "GET" if route == "/metrics" => {
            write_json_response(&mut stream, 404, &json!({"error": "not_found"}))?;
        }
        "GET" if route == "/v1/acks" => {
            let body = format_acks(&app)?;
            write_http_response(&mut stream, 200, "application/json", body.as_bytes())?;
        }
        "POST" if route == "/v1/ack" => {
            let form = parse_json_fields(&request.body)?;
            let ack = propagation_ack_from_json_fields(&app, &form)?;
            lock_acks(&app)?.insert(ack.key(), ack.clone());
            if let Err(err) = forward_ack(&app, &ack) {
                eprintln!("central ack forward failed: {err}");
                lock_ack_forward_status(&app)?.ack_forward_errors += 1;
            }
            write_json_response(&mut stream, 200, &json!({"status": "ok"}))?;
        }
        "GET" => {
            let upstream = app.source.get(&request.path)?;
            write_http_response(
                &mut stream,
                upstream.status_code,
                content_type_for(&request.path),
                &upstream.body,
            )?;
        }
        "POST" => {
            let upstream = app.source.post(&request.path, &request.body)?;
            write_http_response(&mut stream, upstream.status_code, "application/json", &upstream.body)?;
        }
        method => {
            return Err(GlobAclError::Parse(format!(
                "unsupported relay method {method}"
            )));
        }
    }

    Ok(())
}

fn format_relay_metrics(app: &App) -> Result<String> {
    let health = app.source.health().unwrap_or_else(|_| SourceHealth {
        ok: false,
        details: json!({"source_error": 1}).to_string(),
    });
    let ack_count = lock_acks(app)?.len();
    let ack_forward_status = lock_ack_forward_status(app)?.clone();
    let labels = [
        ("relay_id", app.relay_id.as_str()),
        ("location", app.location.as_str()),
        ("source", app.source.kind()),
    ];

    let mut out = String::new();
    append_prometheus_metric(
        &mut out,
        "globacl_relay_up",
        "Relay process is serving requests.",
        "gauge",
        &labels,
        1,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_relay_source_up",
        "Whether the relay source is healthy.",
        "gauge",
        &labels,
        prometheus_bool(health.ok),
    );
    append_prometheus_metric(
        &mut out,
        "globacl_relay_ack_count",
        "Number of latest local propagation acknowledgements.",
        "gauge",
        &labels,
        ack_count,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_relay_last_ack_forward_unix",
        "Unix timestamp of the last successful upstream ack forward.",
        "gauge",
        &labels,
        ack_forward_status.last_ack_forward_unix,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_relay_ack_forward_errors_total",
        "Number of upstream ack-forward errors since process start.",
        "counter",
        &labels,
        ack_forward_status.ack_forward_errors,
    );

    if let Ok(fields) = parse_json_fields(health.details.as_bytes()) {
        for key in [
            "http_status",
            "bootstrap_status",
            "shard_count",
            "max_cached_seq",
            "cached_mutations",
            "source_lag_max",
            "source_lag_sum",
            "lagging_shards",
            "consumer_num_pending",
            "consumer_num_ack_pending",
            "consumer_num_redelivered",
            "consumer_num_waiting",
            "last_pull_unix",
            "applied_messages",
            "duplicate_messages",
            "gap_repairs",
            "jetstream_errors",
            "source_error",
        ] {
            if let Some(value) = fields.get(key).and_then(|value| value.parse::<u64>().ok()) {
                let metric_name = format!("globacl_relay_source_{key}");
                append_prometheus_metric(
                    &mut out,
                    &metric_name,
                    "Relay source-specific numeric health field.",
                    "gauge",
                    &labels,
                    value,
                );
            }
        }
    }

    Ok(out)
}
