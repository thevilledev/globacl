fn handle_connection(mut stream: TcpStream, app: Arc<App>) -> Result<()> {
    let request = read_http_request(&mut stream)?;
    let (route, _) = parse_query_path(&request.path);

    match (request.method.as_str(), route.as_str()) {
        ("GET", "/health") => {
            let (status_code, body) = match http_get(&app.commit_addr, "/health") {
                Ok(response) if response.status_code == 200 => {
                    (200, control_health_ok(&app, &response.body))
                }
                Ok(response) => (
                    503,
                    json!({
                        "status": "degraded",
                        "role": "control",
                        "commitd": "bad",
                        "commit_addr": app.commit_addr.as_str(),
                        "commit_status": response.status_code
                    }),
                ),
                Err(err) => (
                    503,
                    json!({
                        "status": "degraded",
                        "role": "control",
                        "commitd": "unreachable",
                        "commit_addr": app.commit_addr.as_str(),
                        "error": err.to_string()
                    }),
                ),
            };
            write_json_response(&mut stream, status_code, &body)?;
        }
        ("GET", "/metrics") => {
            write_json_response(&mut stream, 404, &json!({"error": "not_found"}))?;
        }
        (_, path) if path.starts_with("/internal/") => {
            write_json_response(&mut stream, 404, &json!({"error": "not_found"}))?;
        }
        ("POST", "/v1/deny") | ("POST", "/v1/mutation") => {
            if require_scope(&mut stream, &app, &request, "acl:write")?.is_none() {
                return Ok(());
            }
            let form = parse_json_fields(&request.body)?;
            let deny_request = DenyRequest::from_json_fields(&form)?;
            if deny_requires_blast_radius_override(&deny_request)
                && !blast_radius_override_enabled(&form)
            {
                write_json_response(
                    &mut stream,
                    400,
                    &json!({
                        "status": "rejected",
                        "reason": "blast_radius_override_required"
                    }),
                )?;
                return Ok(());
            }
            proxy_post(&mut stream, &app, &request)?;
        }
        ("POST", "/v1/rule") => {
            if require_scope(&mut stream, &app, &request, "acl:write")?.is_none() {
                return Ok(());
            }
            let form = parse_json_fields(&request.body)?;
            let rule_request = RuleRequest::from_json_fields(&form)?;
            if rule_requires_blast_radius_override(&rule_request)
                && !blast_radius_override_enabled(&form)
            {
                write_json_response(
                    &mut stream,
                    400,
                    &json!({
                        "status": "rejected",
                        "reason": "blast_radius_override_required"
                    }),
                )?;
                return Ok(());
            }
            proxy_post(&mut stream, &app, &request)?;
        }
        ("POST", "/v1/canary") => {
            if require_scope(&mut stream, &app, &request, "acl:write")?.is_none() {
                return Ok(());
            }
            proxy_post(&mut stream, &app, &request)?;
        }
        ("POST", "/v1/snapshot") => {
            if require_scope(&mut stream, &app, &request, "snapshot:write")?.is_none() {
                return Ok(());
            }
            proxy_post(&mut stream, &app, &request)?;
        }
        ("POST", "/v1/rollback") => {
            if require_scope(&mut stream, &app, &request, "admin:rollback")?.is_none() {
                return Ok(());
            }
            proxy_post(&mut stream, &app, &request)?;
        }
        ("GET", "/v1/audit") => {
            if require_scope(&mut stream, &app, &request, "audit:read")?.is_none() {
                return Ok(());
            }
            proxy_get(&mut stream, &app, &request)?;
        }
        ("POST", "/v1/ack") => {
            proxy_post(&mut stream, &app, &request)?;
        }
        ("GET", _) => proxy_get(&mut stream, &app, &request)?,
        ("POST", _) => {
            write_json_response(&mut stream, 404, &json!({"error": "not_found"}))?;
        }
        (method, _) => {
            return Err(GlobAclError::Parse(format!(
                "unsupported control method {method}"
            )));
        }
    }

    Ok(())
}

fn control_health_ok(app: &App, commitd_body: &[u8]) -> JsonValue {
    let mut body = JsonMap::new();
    body.insert("status".to_owned(), json!("ok"));
    body.insert("role".to_owned(), json!("control"));
    body.insert("commitd".to_owned(), json!("ok"));
    body.insert("commit_addr".to_owned(), json!(app.commit_addr.as_str()));

    match parse_json_body(commitd_body) {
        Ok(value) => {
            if let Some(object) = value.as_object() {
                for key in [
                    "status",
                    "role",
                    "node_id",
                    "cluster_id",
                    "leader_id",
                    "term",
                    "voted_for",
                    "write_authority",
                    "quorum",
                    "peer_count",
                    "shard_count",
                    "entries",
                    "mutations",
                    "jetstream_publisher",
                    "max_published_seq",
                    "central_ack_count",
                    "last_publish_unix",
                    "publish_errors",
                    "last_peer_sync_unix",
                    "sync_errors",
                ] {
                    if let Some(value) = object.get(key) {
                        body.insert(format!("commitd_{key}"), value.clone());
                    }
                }
            } else {
                body.insert("commitd_health_parse".to_owned(), json!("non_object"));
            }
        }
        Err(err) => {
            body.insert("commitd_health_parse".to_owned(), json!(err.to_string()));
        }
    }

    JsonValue::Object(body)
}

fn format_control_metrics(app: &App) -> String {
    let commit_status = http_get(&app.commit_addr, "/health")
        .map(|response| response.status_code)
        .unwrap_or(0);
    let commit_up = commit_status == 200;
    let mut out = String::new();
    let labels = [("commit_addr", app.commit_addr.as_str())];
    append_prometheus_metric(
        &mut out,
        "globacl_control_up",
        "Control gateway process is serving requests.",
        "gauge",
        &labels,
        1,
    );
    append_prometheus_metric(
        &mut out,
        "globacl_control_commitd_up",
        "Whether the configured commitd upstream is reachable and healthy.",
        "gauge",
        &labels,
        prometheus_bool(commit_up),
    );
    append_prometheus_metric(
        &mut out,
        "globacl_control_commitd_status_code",
        "Last HTTP status code observed from commitd health.",
        "gauge",
        &labels,
        commit_status,
    );
    out
}
