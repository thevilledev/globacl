fn canary_loop(app: Arc<App>, interval: Duration) {
    loop {
        if let Err(err) = commit_canary(&app) {
            eprintln!("canary commit failed: {err}");
        }
        thread::sleep(interval);
    }
}

fn commit_canary(app: &App) -> Result<CanaryStatus> {
    let now = now_unix();
    let op_id = format!("canary-{now}");
    let key = format!("sentinel-{now}");
    let request = DenyRequest {
        op_id: op_id.clone(),
        tenant_id: "globacl".to_owned(),
        namespace: "canary".to_owned(),
        key: key.clone(),
        action: Action::Deny,
        priority: 0,
        reason_code: "synthetic_canary".to_owned(),
        expires_at: now + 120,
        created_by: "globacl-commitd".to_owned(),
        delivery_priority: DeliveryPriority::P0,
    };
    let outcome = commit_request(app, request)?;
    let status = CanaryStatus {
        op_id,
        key,
        shard_id: outcome.mutation.commit_id.shard_id,
        seq: outcome.mutation.commit_id.seq,
        created_at_unix: now,
        expires_at: now + 120,
    };
    *lock_canary(app)? = Some(status.clone());
    Ok(status)
}

fn format_canary_status(status: &CanaryStatus) -> String {
    json!({
        "status": "ok",
        "op_id": status.op_id.as_str(),
        "tenant_id": "globacl",
        "namespace": "canary",
        "key": status.key.as_str(),
        "shard_id": status.shard_id,
        "seq": status.seq,
        "created_at_unix": status.created_at_unix,
        "expires_at": status.expires_at,
        "delivery_priority": "p0"
    })
    .to_string()
}

fn lock_state(app: &App) -> Result<std::sync::MutexGuard<'_, SourceOfTruth>> {
    app.state
        .lock()
        .map_err(|_| GlobAclError::InvalidData("source-of-truth lock poisoned".to_owned()))
}

fn lock_canary(app: &App) -> Result<std::sync::MutexGuard<'_, Option<CanaryStatus>>> {
    app.latest_canary
        .lock()
        .map_err(|_| GlobAclError::InvalidData("canary lock poisoned".to_owned()))
}

fn lock_consensus(app: &App) -> Result<std::sync::MutexGuard<'_, ConsensusState>> {
    app.consensus
        .lock()
        .map_err(|_| GlobAclError::InvalidData("consensus lock poisoned".to_owned()))
}

fn lock_sync_status(app: &App) -> Result<std::sync::MutexGuard<'_, SyncStatus>> {
    app.sync_status
        .lock()
        .map_err(|_| GlobAclError::InvalidData("sync status lock poisoned".to_owned()))
}

fn lock_publisher_status(app: &App) -> Result<std::sync::MutexGuard<'_, PublisherStatus>> {
    app.publisher_status
        .lock()
        .map_err(|_| GlobAclError::InvalidData("publisher status lock poisoned".to_owned()))
}

fn lock_propagation_acks(
    app: &App,
) -> Result<std::sync::MutexGuard<'_, HashMap<String, PropagationAck>>> {
    app.propagation_acks
        .lock()
        .map_err(|_| GlobAclError::InvalidData("propagation ack lock poisoned".to_owned()))
}

fn requires_leader(method: &str, route: &str) -> bool {
    method == "POST"
        && matches!(
            route,
            "/v1/deny"
                | "/v1/mutation"
                | "/v1/rule"
                | "/v1/canary"
                | "/v1/snapshot"
                | "/v1/rollback"
                | "/v1/ack"
        )
}

fn is_internal_route(route: &str) -> bool {
    route.starts_with("/internal/raft/") || route.starts_with("/internal/replication/")
}

fn require_peer_token(stream: &mut TcpStream, app: &App, request: &HttpRequest) -> Result<bool> {
    let Some(expected) = app.peer_token.as_deref() else {
        return Ok(true);
    };
    let provided = request.header(PEER_TOKEN_HEADER).unwrap_or("");
    if constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
        return Ok(true);
    }
    write_json_response(
        stream,
        401,
        &json!({
            "status": "rejected",
            "reason": "invalid_peer_token"
        }),
    )?;
    Ok(false)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
}

fn peer_headers(app: &App) -> Vec<(&'static str, &str)> {
    app.peer_token
        .as_deref()
        .map(|token| vec![(PEER_TOKEN_HEADER, token)])
        .unwrap_or_default()
}

fn replication_headers(app: &App) -> Vec<(&'static str, &str)> {
    let mut headers = peer_headers(app);
    headers.push((LEADER_ID_HEADER, app.replication.node_id.as_str()));
    headers
}

fn proxy_get_to_leader(stream: &mut TcpStream, app: &App, request: &HttpRequest) -> Result<()> {
    let Some(leader_addr) = current_leader_addr(app)? else {
        write_json_response(
            stream,
            503,
            &json!({
                "status": "unavailable",
                "reason": "leader_not_configured"
            }),
        )?;
        return Ok(());
    };
    let headers = request
        .authorization_forward_header()
        .into_iter()
        .collect::<Vec<_>>();
    match globacl_core::http_get_with_headers(&leader_addr, &request.path, &headers) {
        Ok(response) => write_http_response(
            stream,
            response.status_code,
            "application/json",
            &response.body,
        ),
        Err(err) => {
            write_json_response(
                stream,
                503,
                &json!({
                    "status": "unavailable",
                    "reason": "leader_proxy_failed",
                    "error": err.to_string()
                }),
            )
        }
    }
}

fn proxy_write_to_leader(stream: &mut TcpStream, app: &App, request: &HttpRequest) -> Result<()> {
    let Some(leader_addr) = current_leader_addr(app)? else {
        write_json_response(
            stream,
            503,
            &json!({
                "status": "unavailable",
                "reason": "leader_not_configured"
            }),
        )?;
        return Ok(());
    };
    let headers = request
        .authorization_forward_header()
        .into_iter()
        .collect::<Vec<_>>();
    match http_post_with_headers(&leader_addr, &request.path, &request.body, &headers) {
        Ok(response) => {
            write_http_response(
                stream,
                response.status_code,
                "application/json",
                &response.body,
            )?;
        }
        Err(err) => {
            write_json_response(
                stream,
                503,
                &json!({
                    "status": "unavailable",
                    "reason": "leader_proxy_failed",
                    "error": err.to_string()
                }),
            )?;
        }
    }
    Ok(())
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

fn audit_actor(principal: &AuthPrincipal, fallback: &str) -> String {
    if principal.authenticated {
        sanitize_audit_value(&principal.identity)
    } else {
        sanitize_audit_value(fallback)
    }
}

fn is_write_leader(app: &App) -> Result<bool> {
    if !app.replication.is_clustered() {
        return Ok(true);
    }
    Ok(lock_consensus(app)?.role == ConsensusRole::Leader)
}

fn current_leader_addr(app: &App) -> Result<Option<String>> {
    Ok(current_leader_peer(app)?.map(|(_, addr)| addr))
}

fn current_leader_peer(app: &App) -> Result<Option<(String, String)>> {
    let leader_id = lock_consensus(app)?.leader_id.clone();
    Ok(leader_id.and_then(|node_id| {
        app.replication
            .peer_addr(&node_id)
            .map(|addr| (node_id, addr.to_owned()))
    }))
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

fn publisher_config() -> Result<Option<PublisherConfig>> {
    let mode = env::var("GLOBACL_COMMITD_PUBLISHER")
        .or_else(|_| env::var("GLOBACL_PUBLISHER"))
        .unwrap_or_else(|_| {
            if env::var("GLOBACL_NATS_ADDR")
                .or_else(|_| env::var("GLOBACL_NATS_URL"))
                .is_ok()
            {
                "jetstream".to_owned()
            } else {
                "none".to_owned()
            }
        });
    match mode.trim().to_ascii_lowercase().as_str() {
        "" | "none" | "off" | "disabled" => Ok(None),
        "jetstream" | "nats" | "nats_jetstream" => {
            let nats_addr = env::var("GLOBACL_NATS_ADDR")
                .or_else(|_| env::var("GLOBACL_NATS_URL"))
                .unwrap_or_else(|_| "127.0.0.1:4222".to_owned());
            let stream = env::var("GLOBACL_NATS_STREAM").unwrap_or_else(|_| "GLOBACL".to_owned());
            let subject_prefix =
                env::var("GLOBACL_NATS_SUBJECT_PREFIX").unwrap_or_else(|_| "globacl".to_owned());
            let publish_interval_ms = env::var("GLOBACL_NATS_PUBLISH_MS")
                .ok()
                .map(|value| parse_env_u64(&value, "GLOBACL_NATS_PUBLISH_MS"))
                .transpose()?
                .unwrap_or(250);
            let autocreate_stream = env_bool("GLOBACL_NATS_AUTOCREATE", true);
            Ok(Some(PublisherConfig {
                nats_addr,
                stream,
                subject_prefix,
                publish_interval_ms,
                autocreate_stream,
            }))
        }
        other => Err(GlobAclError::Parse(format!(
            "unknown GLOBACL_COMMITD_PUBLISHER mode {other:?}"
        ))),
    }
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

fn required_query_u16(query: &std::collections::HashMap<String, String>, key: &str) -> Result<u16> {
    parse_arg_u16(required_query(query, key)?, key)
}

fn parse_query_u64(value: &str, field: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|err| GlobAclError::Parse(format!("invalid {field}: {err}")))
}

fn parse_arg_u16(value: &str, field: &str) -> Result<u16> {
    value
        .parse::<u16>()
        .map_err(|err| GlobAclError::Parse(format!("invalid {field}: {err}")))
}

fn replication_config(bind_addr: &str) -> Result<ReplicationConfig> {
    let node_id = commitd_env("NODE_ID")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "commitd-local".to_owned());
    let cluster_id = commitd_env("CLUSTER_ID").unwrap_or_else(|_| "local".to_owned());
    let initial_leader_id = commitd_env("INITIAL_LEADER_ID")
        .or_else(|_| commitd_env("LEADER_ID"))
        .ok()
        .filter(|value| !value.trim().is_empty());
    let mut peers = parse_peers(commitd_env("PEERS").unwrap_or_default().as_str())?;
    if peers.is_empty() {
        peers.push(ControlPeer {
            node_id: node_id.clone(),
            addr: bind_addr.to_owned(),
        });
    }
    if !peers.iter().any(|peer| peer.node_id == node_id) {
        peers.push(ControlPeer {
            node_id: node_id.clone(),
            addr: bind_addr.to_owned(),
        });
    }
    if let Some(leader_id) = &initial_leader_id {
        if !peers.iter().any(|peer| &peer.node_id == leader_id) {
            return Err(GlobAclError::InvalidData(format!(
                "initial leader {leader_id} is not present in GLOBACL_COMMITD_PEERS"
            )));
        }
    }
    let quorum = commitd_env("QUORUM")
        .ok()
        .map(|value| parse_env_usize(&value, "GLOBACL_COMMITD_QUORUM"))
        .transpose()?
        .unwrap_or_else(|| (peers.len() / 2) + 1);
    if quorum == 0 || quorum > peers.len() {
        return Err(GlobAclError::InvalidData(format!(
            "invalid quorum {quorum} for {} peers",
            peers.len()
        )));
    }
    if peers.len() > 1 && quorum <= peers.len() / 2 {
        return Err(GlobAclError::InvalidData(format!(
            "clustered commitd quorum must be a majority: quorum={quorum} peers={}",
            peers.len()
        )));
    }
    let heartbeat_interval_ms = commitd_env("HEARTBEAT_MS")
        .ok()
        .map(|value| parse_env_u64(&value, "GLOBACL_COMMITD_HEARTBEAT_MS"))
        .transpose()?
        .unwrap_or(250);
    let election_timeout_ms = commitd_env("ELECTION_MS")
        .ok()
        .map(|value| parse_env_u64(&value, "GLOBACL_COMMITD_ELECTION_MS"))
        .transpose()?
        .unwrap_or(1200);
    let sync_interval_ms = commitd_env("SYNC_MS")
        .ok()
        .map(|value| parse_env_u64(&value, "GLOBACL_COMMITD_SYNC_MS"))
        .transpose()?
        .unwrap_or(1000);
    if heartbeat_interval_ms == 0 {
        return Err(GlobAclError::InvalidData(
            "GLOBACL_COMMITD_HEARTBEAT_MS must be greater than zero".to_owned(),
        ));
    }
    if election_timeout_ms < heartbeat_interval_ms.saturating_mul(3) {
        return Err(GlobAclError::InvalidData(format!(
            "GLOBACL_COMMITD_ELECTION_MS must be at least 3x heartbeat: election={election_timeout_ms} heartbeat={heartbeat_interval_ms}"
        )));
    }
    if sync_interval_ms == 0 {
        return Err(GlobAclError::InvalidData(
            "GLOBACL_COMMITD_SYNC_MS must be greater than zero".to_owned(),
        ));
    }

    Ok(ReplicationConfig {
        cluster_id,
        node_id,
        initial_leader_id,
        peers,
        quorum,
        heartbeat_interval_ms,
        election_timeout_ms,
        sync_interval_ms,
    })
}

fn peer_token_config(replication: &ReplicationConfig) -> Result<Option<String>> {
    let token = commitd_env("PEER_TOKEN")
        .or_else(|_| env::var("GLOBACL_PEER_TOKEN"))
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if replication.is_clustered() && token.is_none() {
        return Err(GlobAclError::InvalidData(
            "GLOBACL_COMMITD_PEER_TOKEN is required when commitd is clustered".to_owned(),
        ));
    }
    Ok(token)
}

fn commitd_env(suffix: &str) -> std::result::Result<String, env::VarError> {
    env::var(format!("GLOBACL_COMMITD_{suffix}"))
        .or_else(|_| env::var(format!("GLOBACL_CONTROL_{suffix}")))
}

fn parse_peers(value: &str) -> Result<Vec<ControlPeer>> {
    let mut peers = Vec::new();
    for part in value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let (node_id, addr) = part.split_once('=').ok_or_else(|| {
            GlobAclError::Parse(format!("invalid peer {part:?}; expected node_id=host:port"))
        })?;
        if node_id.trim().is_empty() || addr.trim().is_empty() {
            return Err(GlobAclError::Parse(format!(
                "invalid peer {part:?}; node_id and address are required"
            )));
        }
        if peers
            .iter()
            .any(|peer: &ControlPeer| peer.node_id == node_id.trim())
        {
            return Err(GlobAclError::Parse(format!(
                "duplicate peer node id {:?}",
                node_id.trim()
            )));
        }
        if peers.iter().any(|peer| peer.addr == addr.trim()) {
            return Err(GlobAclError::Parse(format!(
                "duplicate peer address {:?}",
                addr.trim()
            )));
        }
        peers.push(ControlPeer {
            node_id: node_id.trim().to_owned(),
            addr: addr.trim().to_owned(),
        });
    }
    Ok(peers)
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

fn env_bool(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .map(|value| env_bool_value(&value))
        .unwrap_or(default)
}

fn env_bool_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn load_consensus_state(path: &Path, replication: &ReplicationConfig) -> Result<ConsensusState> {
    let mut current_term = 0u64;
    let mut voted_for = None;
    if path.exists() {
        let fields = parse_json_fields(&fs::read(path)?)?;
        current_term = parse_json_u64(&fields, "current_term", 0)?;
        voted_for = fields
            .get("voted_for")
            .map(String::to_owned)
            .filter(|value| !value.is_empty());
    }

    let role = if replication.peers.len() == 1 {
        ConsensusRole::Leader
    } else {
        ConsensusRole::Follower
    };
    let leader_id = if role == ConsensusRole::Leader {
        Some(replication.node_id.clone())
    } else {
        replication.initial_leader_id.clone()
    };

    Ok(ConsensusState {
        current_term: current_term.max(1),
        voted_for,
        role,
        leader_id,
        last_leader_contact_ms: now_unix_millis(),
        election_deadline_ms: next_election_deadline_ms(
            &replication.node_id,
            replication.election_timeout_ms,
        ),
    })
}

fn persist_consensus_state(path: &Path, consensus: &ConsensusState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(
            json!({
                "current_term": consensus.current_term,
                "voted_for": consensus.voted_for.as_deref().unwrap_or("")
            })
            .to_string()
            .as_bytes(),
        )?;
        file.sync_all()?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

fn local_log_status(app: &App) -> Result<(u64, u64, Vec<u64>)> {
    let (mut watermarks, mut log_len) = {
        let state = lock_state(app)?;
        (state.watermarks().to_vec(), state.mutations_len() as u64)
    };
    for mutation in load_pending_mutations(&app.pending_dir)? {
        if mutation.commit_id.source_region != app.replication.cluster_id {
            continue;
        }
        if let Some(watermark) = watermarks.get_mut(mutation.commit_id.shard_id as usize) {
            if mutation.commit_id.seq > *watermark {
                *watermark = mutation.commit_id.seq;
                log_len += 1;
            }
        }
    }
    let last_seq = watermarks.iter().copied().max().unwrap_or(0);
    Ok((last_seq, log_len, watermarks))
}

fn next_election_deadline_ms(node_id: &str, election_timeout_ms: u64) -> u64 {
    now_unix_millis()
        + election_timeout_ms
        + (stable_node_jitter(node_id) % election_timeout_ms.max(1))
}

fn stable_node_jitter(node_id: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in node_id.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

fn required_json_field<'a>(
    form: &'a std::collections::HashMap<String, String>,
    key: &str,
) -> Result<&'a str> {
    form.get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| GlobAclError::Parse(format!("missing required field {key}")))
}

fn parse_json_u64(
    form: &std::collections::HashMap<String, String>,
    key: &str,
    default: u64,
) -> Result<u64> {
    form.get(key)
        .map(|value| parse_query_u64(value, key))
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn json_bool(form: &std::collections::HashMap<String, String>, key: &str) -> bool {
    form.get(key)
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}
