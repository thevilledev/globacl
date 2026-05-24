fn resolve_acl_decision(
    lookup: &LookupMode,
    tenant_id: &str,
    namespace: &str,
    value: &str,
    include_rules: bool,
) -> Result<Decision> {
    match lookup {
        LookupMode::Http { agent_addr } => {
            let agent_path = if include_rules {
                format!(
                    "/v1/check?tenant_id={}&namespace={}&value={}",
                    percent_encode(tenant_id),
                    percent_encode(namespace),
                    percent_encode(value)
                )
            } else {
                format!(
                    "/v1/lookup?tenant_id={}&namespace={}&key={}",
                    percent_encode(tenant_id),
                    percent_encode(namespace),
                    percent_encode(value)
                )
            };
            let response = http_get(agent_addr, &agent_path)?;
            if response.status_code != 200 {
                return Err(GlobAclError::InvalidData(format!(
                    "agent returned status {}",
                    response.status_code
                )));
            }
            decision_from_response_body(&response.body)
        }
        LookupMode::Embedded { agent } => {
            let now = now_unix();
            if include_rules {
                Ok(agent.check(tenant_id, namespace, value, now))
            } else {
                Ok(agent.lookup(tenant_id, namespace, value, now))
            }
        }
    }
}

fn write_acl_decision(stream: &mut TcpStream, decision: Decision) -> Result<()> {
    let denied = matches!(decision, Decision::Deny { .. });
    let status = if denied { 403 } else { 200 };
    let access = if denied { "denied" } else { "allowed" };
    let mut body = format!("access={access}\n");
    body.push_str(&format_decision(&decision));
    write_http_response(stream, status, "text/plain", body.as_bytes())?;
    Ok(())
}

fn decision_from_response_body(body: &[u8]) -> Result<Decision> {
    let form = parse_form_lines(body)?;
    if form.get("decision").map(String::as_str) != Some("deny") {
        return Ok(Decision::Allow);
    }
    let reason_code = form
        .get("reason_code")
        .cloned()
        .unwrap_or_else(|| "unspecified".to_owned());
    let priority = form
        .get("priority")
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let shard_id = form
        .get("shard_id")
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    let seq = form
        .get("seq")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let epoch = form
        .get("epoch")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    Ok(Decision::Deny {
        reason_code,
        priority,
        commit_id: globacl_core::CommitId {
            shard_id,
            seq,
            epoch,
            source_region: String::new(),
        },
    })
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
