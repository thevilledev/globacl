fn proxy_acl_decision(stream: &mut TcpStream, agent_addr: &str, agent_path: &str) -> Result<()> {
    let response = http_get(agent_addr, agent_path)?;
    if response.status_code != 200 {
        let body = format!("access=error\nagent_status={}\n", response.status_code);
        write_http_response(stream, 502, "text/plain", body.as_bytes())?;
        return Ok(());
    }

    let form = parse_form_lines(&response.body)?;
    let denied = form.get("decision").map(String::as_str) == Some("deny");
    let status = if denied { 403 } else { 200 };
    let access = if denied { "denied" } else { "allowed" };
    let mut body = format!("access={access}\n");
    body.push_str(&String::from_utf8_lossy(&response.body));
    write_http_response(stream, status, "text/plain", body.as_bytes())?;
    Ok(())
}

fn required_query<'a>(
    query: &'a std::collections::HashMap<String, String>,
    key: &str,
) -> Result<&'a str> {
    query
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| GlobAclError::Parse(format!("missing query parameter {key}")))
}

fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
