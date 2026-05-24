fn handle_connection(mut stream: TcpStream, app: Arc<App>) -> Result<()> {
    let request = read_http_request(&mut stream)?;
    let (route, _) = parse_query_path(&request.path);

    match (request.method.as_str(), route.as_str()) {
        ("GET", "/health") => {
            let (status_code, body) = match http_get(&app.commit_addr, "/health") {
                Ok(response) if response.status_code == 200 => {
                    (200, format!(
                        "status=ok\nrole=control\ncommitd=ok\ncommit_addr={}\n",
                        app.commit_addr
                    ))
                }
                Ok(response) => {
                    (503, format!(
                        "status=degraded\nrole=control\ncommitd=bad\ncommit_addr={}\ncommit_status={}\n",
                        app.commit_addr, response.status_code
                    ))
                }
                Err(err) => {
                    (503, format!(
                        "status=degraded\nrole=control\ncommitd=unreachable\ncommit_addr={}\nerror={err}\n",
                        app.commit_addr
                    ))
                }
            };
            write_http_response(&mut stream, status_code, "text/plain", body.as_bytes())?;
        }
        ("POST", "/v1/deny") | ("POST", "/v1/mutation") => {
            let form = parse_form_lines(&request.body)?;
            let deny_request = DenyRequest::from_form(&form)?;
            if deny_requires_blast_radius_override(&deny_request)
                && !blast_radius_override_enabled(&form)
            {
                write_http_response(
                    &mut stream,
                    400,
                    "text/plain",
                    b"status=rejected\nreason=blast_radius_override_required\n",
                )?;
                return Ok(());
            }
            proxy_post(&mut stream, &app, &request.path, &request.body)?;
        }
        ("POST", "/v1/rule") => {
            let form = parse_form_lines(&request.body)?;
            let rule_request = RuleRequest::from_form(&form)?;
            if rule_requires_blast_radius_override(&rule_request)
                && !blast_radius_override_enabled(&form)
            {
                write_http_response(
                    &mut stream,
                    400,
                    "text/plain",
                    b"status=rejected\nreason=blast_radius_override_required\n",
                )?;
                return Ok(());
            }
            proxy_post(&mut stream, &app, &request.path, &request.body)?;
        }
        ("GET", _) => proxy_get(&mut stream, &app, &request.path)?,
        ("POST", _) => proxy_post(&mut stream, &app, &request.path, &request.body)?,
        (method, _) => {
            return Err(GlobAclError::Parse(format!(
                "unsupported control method {method}"
            )));
        }
    }

    Ok(())
}
