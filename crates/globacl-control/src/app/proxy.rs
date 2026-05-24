
fn proxy_get(stream: &mut TcpStream, app: &App, request: &HttpRequest) -> Result<()> {
    let headers = request
        .authorization_forward_header()
        .into_iter()
        .collect::<Vec<_>>();
    match http_get_with_headers(&app.commit_addr, &request.path, &headers) {
        Ok(response) => write_http_response(
            stream,
            response.status_code,
            content_type_for(&request.path),
            &response.body,
        ),
        Err(err) => write_proxy_error(stream, err),
    }
}

fn proxy_post(stream: &mut TcpStream, app: &App, request: &HttpRequest) -> Result<()> {
    let headers = request
        .authorization_forward_header()
        .into_iter()
        .collect::<Vec<_>>();
    match http_post_with_headers(&app.commit_addr, &request.path, &request.body, &headers) {
        Ok(response) => {
            write_http_response(stream, response.status_code, "application/json", &response.body)
        }
        Err(err) => write_proxy_error(stream, err),
    }
}

fn write_proxy_error(stream: &mut TcpStream, err: GlobAclError) -> Result<()> {
    write_json_response(
        stream,
        503,
        &json!({
            "status": "unavailable",
            "reason": "commitd_proxy_failed",
            "error": err.to_string()
        }),
    )
}

fn content_type_for(path: &str) -> &'static str {
    let route = path.split_once('?').map_or(path, |(route, _)| route);
    if matches!(
        route,
        "/v1/mutations" | "/v1/snapshot" | "/v1/snapshot_artifact" | "/v1/delta_bundle"
    ) {
        "application/octet-stream"
    } else {
        "application/json"
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

fn require_scope(
    stream: &mut TcpStream,
    app: &App,
    request: &HttpRequest,
    scope: &str,
) -> Result<Option<AuthPrincipal>> {
    match app.auth.require_scope(request, scope) {
        Ok(principal) => Ok(Some(principal)),
        Err(failure) => {
            write_auth_failure_response(stream, failure, scope)?;
            Ok(None)
        }
    }
}
