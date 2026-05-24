fn handle_connection(mut stream: TcpStream, app: Arc<App>) -> Result<()> {
    let request = read_http_request(&mut stream)?;
    let (route, query) = parse_query_path(&request.path);

    match (request.method.as_str(), route.as_str()) {
        ("GET", "/health") => {
            let body = format!("status=ok\n{}\n", app.lookup.description());
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/access") => {
            let tenant_id = required_query(&query, "tenant_id")?;
            let namespace = required_query(&query, "namespace")?;
            let key = required_query(&query, "key")?;
            write_acl_decision(
                &mut stream,
                resolve_acl_decision(&app.lookup, tenant_id, namespace, key, false)?,
            )?;
        }
        ("GET", "/check") => {
            let tenant_id = required_query(&query, "tenant_id")?;
            let namespace = required_query(&query, "namespace")?;
            let value = query
                .get("value")
                .or_else(|| query.get("key"))
                .map(String::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| GlobAclError::Parse("missing query parameter value".to_owned()))?;
            write_acl_decision(
                &mut stream,
                resolve_acl_decision(&app.lookup, tenant_id, namespace, value, true)?,
            )?;
        }
        _ => {
            write_http_response(&mut stream, 404, "text/plain", b"not found\n")?;
        }
    }

    Ok(())
}

fn format_demo_metrics(app: &App) -> Result<String> {
    let mut out = String::new();
    let lookup_mode = app.lookup.mode_name();
    let labels = [("lookup_mode", lookup_mode)];
    append_prometheus_metric(
        &mut out,
        "globacl_demo_up",
        "Demo app process is serving requests.",
        "gauge",
        &labels,
        1,
    );

    if let LookupMode::Embedded { agent } = &app.lookup {
        let health = agent.health()?;
        append_prometheus_metric(
            &mut out,
            "globacl_demo_embedded_agent_stale",
            "Whether the embedded agent has exceeded its poll-lag staleness budget.",
            "gauge",
            &labels,
            if health.stale { 1 } else { 0 },
        );
        append_prometheus_metric(
            &mut out,
            "globacl_demo_embedded_agent_max_seq",
            "Maximum applied sequence in the embedded agent.",
            "gauge",
            &labels,
            health.max_seq,
        );
        append_prometheus_metric(
            &mut out,
            "globacl_demo_embedded_agent_entries",
            "Materialized deny entry count in the embedded agent.",
            "gauge",
            &labels,
            health.entries,
        );
        append_prometheus_metric(
            &mut out,
            "globacl_demo_embedded_agent_poll_lag_secs",
            "Seconds since the embedded agent's last successful polling loop.",
            "gauge",
            &labels,
            health.poll_lag_secs,
        );
    }

    Ok(out)
}
