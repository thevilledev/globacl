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

fn signature_signer_from_env() -> Result<SignatureSigner> {
    let key_id = env::var("GLOBACL_SIGNATURE_KEY_ID")
        .unwrap_or_else(|_| DEFAULT_SIGNATURE_KEY_ID.to_owned());
    let key_version = env::var("GLOBACL_SIGNATURE_KEY_VERSION")
        .ok()
        .map(|value| parse_env_u64(&value, "GLOBACL_SIGNATURE_KEY_VERSION"))
        .transpose()?
        .unwrap_or(DEFAULT_SIGNATURE_KEY_VERSION);
    if let Ok(command) = env::var("GLOBACL_SIGNATURE_SIGN_COMMAND")
        .or_else(|_| env::var("GLOBACL_SIGNATURE_SIGNER_COMMAND"))
    {
        if !command.trim().is_empty() {
            return SignatureSigner::external_command(key_id, key_version, command);
        }
    }

    let private_key = env_text_or_file(
        "GLOBACL_SIGNATURE_PRIVATE_KEY",
        "GLOBACL_SIGNATURE_PRIVATE_KEY_FILE",
    )?
    .unwrap_or_else(|| DEFAULT_SIGNATURE_PRIVATE_KEY.to_owned());
    SignatureSigner::ed25519_private_key(key_id, key_version, private_key.trim().to_owned())
}

fn env_text_or_file(value_env: &str, file_env: &str) -> Result<Option<String>> {
    if let Ok(value) = env::var(value_env) {
        if !value.trim().is_empty() {
            return Ok(Some(value));
        }
    }
    if let Ok(path) = env::var(file_env) {
        if !path.trim().is_empty() {
            return Ok(Some(fs::read_to_string(path.trim())?));
        }
    }
    Ok(None)
}

fn lock_acks(app: &App) -> Result<std::sync::MutexGuard<'_, HashMap<String, PropagationAck>>> {
    app.acks
        .lock()
        .map_err(|_| GlobAclError::InvalidData("ack lock poisoned".to_owned()))
}

fn lock_ack_forward_status(app: &App) -> Result<std::sync::MutexGuard<'_, AckForwardStatus>> {
    app.ack_forward_status
        .lock()
        .map_err(|_| GlobAclError::InvalidData("ack forward status lock poisoned".to_owned()))
}

fn lock_cache(source: &JetStreamSource) -> Result<std::sync::MutexGuard<'_, RelayCache>> {
    source
        .cache
        .lock()
        .map_err(|_| GlobAclError::InvalidData("relay cache lock poisoned".to_owned()))
}

fn lock_jetstream_status(
    source: &JetStreamSource,
) -> Result<std::sync::MutexGuard<'_, JetStreamStatus>> {
    source
        .status
        .lock()
        .map_err(|_| GlobAclError::InvalidData("JetStream status lock poisoned".to_owned()))
}

fn format_acks(app: &App) -> Result<String> {
    let now = now_unix();
    let mut acks = lock_acks(app)?.values().cloned().collect::<Vec<_>>();
    acks.sort_by(|left, right| {
        left.agent_id
            .cmp(&right.agent_id)
            .then(left.shard_id.cmp(&right.shard_id))
    });

    let mut items = Vec::new();
    for ack in acks {
        let lag_secs = now.saturating_sub(ack.applied_at_unix);
        items.push(json!({
            "relay_id": ack.relay_id.as_str(),
            "location": ack.location.as_str(),
            "agent_id": ack.agent_id.as_str(),
            "shard_id": ack.shard_id,
            "seq": ack.seq,
            "entries": ack.entries,
            "applied_at_unix": ack.applied_at_unix,
            "relay_received_at_unix": ack.relay_received_at_unix,
            "lag_secs": lag_secs
        }));
    }
    Ok(json!({
        "relay_id": app.relay_id.as_str(),
        "location": app.location.as_str(),
        "ack_count": items.len(),
        "acks": items
    })
    .to_string())
}

fn required_query_u16(query: &HashMap<String, String>, key: &str) -> Result<u16> {
    query
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| GlobAclError::Parse(format!("missing query parameter {key}")))?
        .parse::<u16>()
        .map_err(|err| GlobAclError::Parse(format!("invalid {key}: {err}")))
}

fn parse_query_u64(value: &str, field: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|err| GlobAclError::Parse(format!("invalid {field}: {err}")))
}

fn parse_env_usize(value: &str, field: &str) -> Result<usize> {
    value
        .parse::<usize>()
        .map_err(|err| GlobAclError::Parse(format!("invalid {field}: {err}")))
}

fn parse_env_u64(value: &str, field: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|err| GlobAclError::Parse(format!("invalid {field}: {err}")))
}

fn parse_env_u16(value: &str, field: &str) -> Result<u16> {
    value
        .parse::<u16>()
        .map_err(|err| GlobAclError::Parse(format!("invalid {field}: {err}")))
}

fn env_bool(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

fn sanitize_nats_name(value: &str) -> String {
    let mut out = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if out.is_empty() {
        out = "relay".to_owned();
    }
    out
}
