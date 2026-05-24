fn handle_connection(mut stream: TcpStream, app: Arc<App>) -> Result<()> {
    let request = read_http_request(&mut stream)?;
    let (route, query) = parse_query_path(&request.path);

    match (request.method.as_str(), route.as_str()) {
        ("GET", "/health") => {
            let body = format!("status=ok\nagent_addr={}\n", app.agent_addr);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/access") => {
            let tenant_id = required_query(&query, "tenant_id")?;
            let namespace = required_query(&query, "namespace")?;
            let key = required_query(&query, "key")?;
            let agent_path = format!(
                "/v1/lookup?tenant_id={}&namespace={}&key={}",
                percent_encode(tenant_id),
                percent_encode(namespace),
                percent_encode(key)
            );
            proxy_acl_decision(&mut stream, &app.agent_addr, &agent_path)?;
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
            let agent_path = format!(
                "/v1/check?tenant_id={}&namespace={}&value={}",
                percent_encode(tenant_id),
                percent_encode(namespace),
                percent_encode(value)
            );
            proxy_acl_decision(&mut stream, &app.agent_addr, &agent_path)?;
        }
        _ => {
            write_http_response(&mut stream, 404, "text/plain", b"not found\n")?;
        }
    }

    Ok(())
}

