
fn proxy_get(stream: &mut TcpStream, app: &App, path: &str) -> Result<()> {
    match http_get(&app.commit_addr, path) {
        Ok(response) => write_http_response(
            stream,
            response.status_code,
            content_type_for(path),
            &response.body,
        ),
        Err(err) => write_proxy_error(stream, err),
    }
}

fn proxy_post(stream: &mut TcpStream, app: &App, path: &str, body: &[u8]) -> Result<()> {
    match http_post(&app.commit_addr, path, body) {
        Ok(response) => {
            write_http_response(stream, response.status_code, "text/plain", &response.body)
        }
        Err(err) => write_proxy_error(stream, err),
    }
}

fn write_proxy_error(stream: &mut TcpStream, err: GlobAclError) -> Result<()> {
    let body = format!("status=unavailable\nreason=commitd_proxy_failed\nerror={err}\n");
    write_http_response(stream, 503, "text/plain", body.as_bytes())
}

fn content_type_for(path: &str) -> &'static str {
    let route = path.split_once('?').map_or(path, |(route, _)| route);
    if route.ends_with(".sig") || route == "/v1/snapshot_manifest" || route == "/v1/snapshots" {
        "text/plain"
    } else if matches!(
        route,
        "/v1/mutations" | "/v1/snapshot" | "/v1/snapshot_artifact" | "/v1/delta_bundle"
    ) {
        "application/octet-stream"
    } else {
        "text/plain"
    }
}

fn blast_radius_override_enabled(form: &std::collections::HashMap<String, String>) -> bool {
    form.get("override_blast_radius")
        .or_else(|| form.get("blast_radius_override"))
        .or_else(|| form.get("two_person_approved"))
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}
