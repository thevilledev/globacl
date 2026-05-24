use globacl_core::{
    decode_mutation_stream, decode_snapshot, decode_snapshot_manifest, encode_snapshot,
    format_decision, http_get, now_unix, parse_form_lines, parse_query_path,
    parse_signature_public_keys, parse_watermarks, read_http_request, read_snapshot_file,
    verify_payload_signature_with_verifier, write_http_response, write_snapshot_file, ActiveState,
    ActiveStateHandle, Decision, GlobAclError, PopAck, Result, SignatureVerificationKey,
    SignatureVerifier, DEFAULT_SIGNATURE_KEY_ID, DEFAULT_SIGNATURE_KEY_VERSION,
    DEFAULT_SIGNATURE_PUBLIC_KEY,
};
use std::env;
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const DELTA_COMPACT_THRESHOLD: usize = 1024;

struct App {
    agent_id: String,
    relay_addr: String,
    snapshot_path: PathBuf,
    stale_after_secs: u64,
    signature_verifier: SignatureVerifier,
    state: ActiveStateHandle,
    metrics: Mutex<AgentMetrics>,
}

#[derive(Default)]
struct AgentMetrics {
    last_sync_unix: u64,
    last_successful_poll_unix: u64,
    applied_mutations: u64,
    repairs: u64,
    bundle_repairs: u64,
    snapshot_repairs: u64,
    last_canary_key: String,
    last_canary_seq: u64,
    last_canary_seen_unix: u64,
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let relay_addr = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:7001".to_owned());
    let bind_addr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:7002");
    let snapshot_path = PathBuf::from(
        args.get(3)
            .map(String::as_str)
            .unwrap_or("data/agent/latest.gacl"),
    );
    let poll_ms = args
        .get(4)
        .map(|value| parse_arg_u64(value, "poll_ms"))
        .transpose()?
        .unwrap_or(1000);
    let agent_id = args.get(5).cloned().unwrap_or_else(|| {
        format!(
            "agent-{}",
            bind_addr
                .replace(":", "-")
                .replace(".", "-")
                .replace("[", "")
                .replace("]", "")
        )
    });
    let stale_after_secs = args
        .get(6)
        .map(|value| parse_arg_u64(value, "stale_after_secs"))
        .transpose()?
        .unwrap_or(60);
    let signature_verifier = signature_verifier_from_env()?;

    let snapshot = load_or_fetch_snapshot(&relay_addr, &snapshot_path, &signature_verifier)?;
    let started_at = now_unix();
    let app = Arc::new(App {
        agent_id,
        relay_addr,
        snapshot_path,
        stale_after_secs,
        signature_verifier,
        state: ActiveStateHandle::from_snapshot(snapshot)?,
        metrics: Mutex::new(AgentMetrics {
            last_sync_unix: started_at,
            last_successful_poll_unix: started_at,
            ..AgentMetrics::default()
        }),
    });

    {
        let app = Arc::clone(&app);
        thread::spawn(move || poll_loop(app, Duration::from_millis(poll_ms)));
    }

    let listener = TcpListener::bind(bind_addr)?;
    eprintln!(
        "globacl-agent listening on {bind_addr}; agent_id={}; relay_addr={}",
        app.agent_id, app.relay_addr
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let app = Arc::clone(&app);
                thread::spawn(move || {
                    if let Err(err) = handle_connection(stream, app) {
                        eprintln!("request failed: {err}");
                    }
                });
            }
            Err(err) => eprintln!("accept failed: {err}"),
        }
    }

    Ok(())
}

fn handle_connection(mut stream: TcpStream, app: Arc<App>) -> Result<()> {
    let request = read_http_request(&mut stream)?;
    let (route, query) = parse_query_path(&request.path);

    match (request.method.as_str(), route.as_str()) {
        ("GET", "/health") => {
            let state = current_state(&app);
            let metrics = lock_metrics(&app)?;
            let max_seq = state.watermarks().iter().copied().max().unwrap_or(0);
            let stats = state.stats();
            let now = now_unix();
            let poll_lag_secs = now.saturating_sub(metrics.last_successful_poll_unix);
            let state_lag_secs = now.saturating_sub(metrics.last_sync_unix);
            let stale = poll_lag_secs > app.stale_after_secs;
            let status = if stale { "stale" } else { "ok" };
            let body = format!(
                "status={status}\nrole=agent\nagent_id={}\nshard_count={}\nentries={}\nbase_entries={}\ndelta_adds={}\ndelta_removes={}\nbase_rules={}\ndelta_rule_adds={}\ndelta_rule_removes={}\nfilter_bits={}\nfilter_hashes={}\nestimated_state_bytes={}\nmax_seq={}\nlast_sync_unix={}\nlast_successful_poll_unix={}\nstate_lag_secs={}\npoll_lag_secs={}\nstale_after_secs={}\nstale={}\napplied_mutations={}\nrepairs={}\nbundle_repairs={}\nsnapshot_repairs={}\nlast_canary_key={}\nlast_canary_seq={}\nlast_canary_seen_unix={}\n",
                app.agent_id,
                state.shard_count(),
                state.entries_len(),
                stats.base_entries,
                stats.delta_adds,
                stats.delta_removes,
                stats.base_rules,
                stats.delta_rule_adds,
                stats.delta_rule_removes,
                stats.filter_bits,
                stats.filter_hashes,
                stats.estimated_bytes,
                max_seq,
                metrics.last_sync_unix,
                metrics.last_successful_poll_unix,
                state_lag_secs,
                poll_lag_secs,
                app.stale_after_secs,
                stale,
                metrics.applied_mutations,
                metrics.repairs,
                metrics.bundle_repairs,
                metrics.snapshot_repairs,
                metrics.last_canary_key,
                metrics.last_canary_seq,
                metrics.last_canary_seen_unix
            );
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/lookup") => {
            let tenant_id = required_query(&query, "tenant_id")?;
            let namespace = required_query(&query, "namespace")?;
            let key = required_query(&query, "key")?;
            let decision = {
                let state = current_state(&app);
                state.lookup(tenant_id, namespace, key, now_unix())
            };
            let body = format_decision(&decision);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/check") => {
            let tenant_id = required_query(&query, "tenant_id")?;
            let namespace = required_query(&query, "namespace")?;
            let value = query
                .get("value")
                .or_else(|| query.get("key"))
                .map(String::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| GlobAclError::Parse("missing query parameter value".to_owned()))?;
            let decision = {
                let state = current_state(&app);
                state.check(tenant_id, namespace, value, now_unix())
            };
            let body = format_decision(&decision);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/snapshot") => {
            let snapshot = {
                let state = current_state(&app);
                state.snapshot()
            };
            let body = encode_snapshot(&snapshot);
            write_http_response(&mut stream, 200, "application/octet-stream", &body)?;
        }
        _ => {
            write_http_response(&mut stream, 404, "text/plain", b"not found\n")?;
        }
    }

    Ok(())
}

fn poll_loop(app: Arc<App>, interval: Duration) {
    loop {
        if let Err(err) = poll_once(&app) {
            eprintln!("poll failed: {err}");
        }
        thread::sleep(interval);
    }
}

fn poll_once(app: &Arc<App>) -> Result<()> {
    let shard_count = {
        let state = current_state(app);
        state.shard_count()
    };
    let remote_watermarks = fetch_watermarks(app).ok();

    for shard_id in 0..shard_count {
        let from_seq = {
            let state = current_state(app);
            state.watermarks()[shard_id as usize]
        };
        if let Some(remote_watermarks) = &remote_watermarks {
            if remote_watermarks
                .get(shard_id as usize)
                .copied()
                .unwrap_or(from_seq)
                <= from_seq
            {
                continue;
            }
        }
        let path = format!("/v1/mutations?shard={shard_id}&from_seq={from_seq}");
        let response = http_get(&app.relay_addr, &path)?;
        if response.status_code == 409 || response.status_code == 410 {
            repair_from_snapshot(app)?;
            return Ok(());
        }
        if response.status_code != 200 {
            return Err(GlobAclError::InvalidData(format!(
                "relay returned status {} for {path}",
                response.status_code
            )));
        }
        let signature_path = format!("/v1/mutations.sig?shard={shard_id}&from_seq={from_seq}");
        verify_remote_payload_signature(
            &app.relay_addr,
            &signature_path,
            &response.body,
            &app.signature_verifier,
        )?;
        let mutations = decode_mutation_stream(&response.body)?;
        if mutations.is_empty() {
            continue;
        }

        let mut applied = 0u64;
        let (ack_seq, entries, snapshot, next_state) = {
            let current = current_state(app);
            let mut state = current.as_ref().clone();
            for mutation in &mutations {
                match state.apply_mutation(mutation) {
                    Ok(globacl_core::ApplyStatus::Applied) => applied += 1,
                    Ok(globacl_core::ApplyStatus::DuplicateOrOld) => {}
                    Err(GlobAclError::Gap {
                        shard_id,
                        expected_seq,
                        received_seq,
                    }) => {
                        drop(state);
                        repair_gap(
                            app,
                            shard_id,
                            expected_seq.saturating_sub(1),
                            received_seq.saturating_sub(1),
                        )?;
                        return Ok(());
                    }
                    Err(err) => return Err(err),
                }
            }
            if state.delta_entries_len() >= DELTA_COMPACT_THRESHOLD {
                state.compact_delta_overlay();
            }
            let ack_seq = state.watermarks()[shard_id as usize];
            let entries = state.entries_len();
            let snapshot = state.snapshot();
            (ack_seq, entries, snapshot, state)
        };
        write_snapshot_file(&app.snapshot_path, &snapshot)?;
        swap_state(app, next_state);

        let mut metrics = lock_metrics(app)?;
        metrics.last_sync_unix = now_unix();
        metrics.applied_mutations += applied;
        drop(metrics);

        send_ack(app, shard_id, ack_seq, entries)?;
    }

    check_canary(app)?;
    lock_metrics(app)?.last_successful_poll_unix = now_unix();
    Ok(())
}

fn fetch_watermarks(app: &Arc<App>) -> Result<Vec<u64>> {
    let response = http_get(&app.relay_addr, "/v1/watermarks")?;
    if response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "relay returned status {} for watermarks",
            response.status_code
        )));
    }
    parse_watermarks(&response.body)
}

fn repair_gap(app: &Arc<App>, shard_id: u16, from_seq: u64, to_seq: u64) -> Result<()> {
    if to_seq >= from_seq {
        let path = format!("/v1/delta_bundle?shard={shard_id}&from_seq={from_seq}&to_seq={to_seq}");
        let response = http_get(&app.relay_addr, &path)?;
        if response.status_code == 200 {
            let signature_path = format!(
                "/v1/delta_bundle.sig?shard={shard_id}&from_seq={from_seq}&to_seq={to_seq}"
            );
            verify_remote_payload_signature(
                &app.relay_addr,
                &signature_path,
                &response.body,
                &app.signature_verifier,
            )?;
            let mutations = decode_mutation_stream(&response.body)?;
            if !mutations.is_empty() {
                let current = current_state(app);
                let mut state = current.as_ref().clone();
                for mutation in &mutations {
                    state.apply_mutation(mutation)?;
                }
                if state.delta_entries_len() >= DELTA_COMPACT_THRESHOLD {
                    state.compact_delta_overlay();
                }
                let snapshot = state.snapshot();
                let seq = state.watermarks()[shard_id as usize];
                let entries = state.entries_len();
                write_snapshot_file(&app.snapshot_path, &snapshot)?;
                swap_state(app, state);
                send_ack(app, shard_id, seq, entries)?;
                let mut metrics = lock_metrics(app)?;
                metrics.last_sync_unix = now_unix();
                metrics.last_successful_poll_unix = metrics.last_sync_unix;
                metrics.repairs += 1;
                metrics.bundle_repairs += 1;
                return Ok(());
            }
        }
    }

    repair_from_snapshot(app)
}

fn repair_from_snapshot(app: &Arc<App>) -> Result<()> {
    let snapshot = fetch_snapshot(&app.relay_addr, &app.signature_verifier)?;
    write_snapshot_file(&app.snapshot_path, &snapshot)?;
    let mut ack_targets = Vec::new();
    let state = ActiveState::from_snapshot(snapshot)?;
    for (shard_id, seq) in state.watermarks().iter().copied().enumerate() {
        if seq > 0 {
            ack_targets.push((shard_id as u16, seq, state.entries_len()));
        }
    }
    swap_state(app, state);
    for (shard_id, seq, entries) in ack_targets {
        send_ack(app, shard_id, seq, entries)?;
    }
    let mut metrics = lock_metrics(app)?;
    metrics.last_sync_unix = now_unix();
    metrics.last_successful_poll_unix = metrics.last_sync_unix;
    metrics.repairs += 1;
    metrics.snapshot_repairs += 1;
    Ok(())
}

fn send_ack(app: &Arc<App>, shard_id: u16, seq: u64, entries: usize) -> Result<()> {
    let ack = PopAck {
        agent_id: app.agent_id.clone(),
        shard_id,
        seq,
        entries,
        applied_at_unix: now_unix(),
    };
    let response =
        globacl_core::http_post(&app.relay_addr, "/v1/ack", ack.to_form_body().as_bytes())?;
    if response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "relay returned status {} for ack",
            response.status_code
        )));
    }
    Ok(())
}

fn check_canary(app: &Arc<App>) -> Result<()> {
    let response = http_get(&app.relay_addr, "/v1/canary/latest")?;
    if response.status_code != 200 {
        return Ok(());
    }
    let form = parse_form_lines(&response.body)?;
    if form.get("status").map(String::as_str) != Some("ok") {
        return Ok(());
    }
    let Some(key) = form.get("key") else {
        return Ok(());
    };
    let canary_seq = form
        .get("seq")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let decision = {
        let state = current_state(app);
        state.lookup("globacl", "canary", key, now_unix())
    };
    if matches!(decision, Decision::Deny { .. }) {
        let mut metrics = lock_metrics(app)?;
        metrics.last_canary_key = key.clone();
        metrics.last_canary_seq = canary_seq;
        metrics.last_canary_seen_unix = now_unix();
    }
    Ok(())
}

fn load_or_fetch_snapshot(
    relay_addr: &str,
    snapshot_path: &Path,
    signature_verifier: &SignatureVerifier,
) -> Result<globacl_core::Snapshot> {
    if snapshot_path.exists() {
        verify_local_snapshot(snapshot_path, signature_verifier)?;
        return read_snapshot_file(snapshot_path);
    }
    let snapshot = fetch_snapshot(relay_addr, signature_verifier)?;
    write_snapshot_file(snapshot_path, &snapshot)?;
    Ok(snapshot)
}

fn fetch_snapshot(
    relay_addr: &str,
    signature_verifier: &SignatureVerifier,
) -> Result<globacl_core::Snapshot> {
    match fetch_snapshot_from_manifest(relay_addr, signature_verifier) {
        Ok(snapshot) => return Ok(snapshot),
        Err(err) => {
            eprintln!("snapshot manifest fetch failed, falling back to legacy snapshot: {err}")
        }
    }

    let response = http_get(relay_addr, "/v1/snapshot")?;
    if response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "relay returned status {} for snapshot",
            response.status_code
        )));
    }
    verify_remote_payload_signature(
        relay_addr,
        "/v1/snapshot.sig",
        &response.body,
        signature_verifier,
    )?;
    decode_snapshot(&response.body)
}

fn fetch_snapshot_from_manifest(
    relay_addr: &str,
    signature_verifier: &SignatureVerifier,
) -> Result<globacl_core::Snapshot> {
    let manifest_response = http_get(relay_addr, "/v1/snapshot_manifest")?;
    if manifest_response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "relay returned status {} for snapshot manifest",
            manifest_response.status_code
        )));
    }
    verify_required_remote_payload_signature(
        relay_addr,
        "/v1/snapshot_manifest.sig",
        &manifest_response.body,
        signature_verifier,
    )?;
    let manifest = decode_snapshot_manifest(&manifest_response.body)?;

    let artifact_path = format!("/v1/snapshot_artifact?object={}", manifest.artifact_object);
    let artifact_response = http_get(relay_addr, &artifact_path)?;
    if artifact_response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "relay returned status {} for snapshot artifact {}",
            artifact_response.status_code, manifest.artifact_object
        )));
    }
    let artifact_signature_path = format!(
        "/v1/snapshot_artifact.sig?object={}",
        manifest.artifact_object
    );
    verify_required_remote_payload_signature(
        relay_addr,
        &artifact_signature_path,
        &artifact_response.body,
        signature_verifier,
    )?;
    manifest.validate_artifact(&artifact_response.body)?;
    let snapshot = decode_snapshot(&artifact_response.body)?;
    manifest.validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn verify_local_snapshot(path: &Path, signature_verifier: &SignatureVerifier) -> Result<()> {
    let sig_path = signature_path(path);
    if !sig_path.exists() {
        return Ok(());
    }
    let payload = fs::read(path)?;
    let signature = fs::read(sig_path)?;
    verify_snapshot_signature(&payload, &signature, signature_verifier)
}

fn verify_remote_payload_signature(
    relay_addr: &str,
    signature_path: &str,
    payload: &[u8],
    signature_verifier: &SignatureVerifier,
) -> Result<()> {
    let response = http_get(relay_addr, signature_path)?;
    if response.status_code != 200 || response.body.is_empty() {
        return Ok(());
    }
    verify_snapshot_signature(payload, &response.body, signature_verifier)
}

fn verify_required_remote_payload_signature(
    relay_addr: &str,
    signature_path: &str,
    payload: &[u8],
    signature_verifier: &SignatureVerifier,
) -> Result<()> {
    let response = http_get(relay_addr, signature_path)?;
    if response.status_code != 200 || response.body.is_empty() {
        return Err(GlobAclError::InvalidData(format!(
            "required signature missing at {signature_path}"
        )));
    }
    verify_snapshot_signature(payload, &response.body, signature_verifier)
}

fn verify_snapshot_signature(
    payload: &[u8],
    signature_body: &[u8],
    signature_verifier: &SignatureVerifier,
) -> Result<()> {
    verify_payload_signature_with_verifier(signature_verifier, payload, signature_body)
}

fn signature_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sig", path.display()))
}

fn signature_verifier_from_env() -> Result<SignatureVerifier> {
    let min_key_version = env::var("GLOBACL_SIGNATURE_MIN_KEY_VERSION")
        .ok()
        .map(|value| parse_arg_u64(&value, "GLOBACL_SIGNATURE_MIN_KEY_VERSION"))
        .transpose()?
        .unwrap_or(0);

    let mut keys = Vec::new();
    if let Some(public_keys) = env_text_or_file(
        "GLOBACL_SIGNATURE_PUBLIC_KEYS",
        "GLOBACL_SIGNATURE_PUBLIC_KEYS_FILE",
    )? {
        keys.extend(parse_signature_public_keys(&public_keys)?);
    }

    let explicit_public_key = env_text_or_file(
        "GLOBACL_SIGNATURE_PUBLIC_KEY",
        "GLOBACL_SIGNATURE_PUBLIC_KEY_FILE",
    )?;
    if keys.is_empty() || explicit_public_key.is_some() {
        let key_id = env::var("GLOBACL_SIGNATURE_KEY_ID")
            .unwrap_or_else(|_| DEFAULT_SIGNATURE_KEY_ID.to_owned());
        let key_version = env::var("GLOBACL_SIGNATURE_KEY_VERSION")
            .ok()
            .map(|value| parse_arg_u64(&value, "GLOBACL_SIGNATURE_KEY_VERSION"))
            .transpose()?
            .unwrap_or(DEFAULT_SIGNATURE_KEY_VERSION);
        let public_key =
            explicit_public_key.unwrap_or_else(|| DEFAULT_SIGNATURE_PUBLIC_KEY.to_owned());
        if keys.iter().any(|key| key.key_id == key_id) {
            return Err(GlobAclError::InvalidData(format!(
                "duplicate signature key_id {key_id:?} in keyring and single-key configuration"
            )));
        }
        keys.push(SignatureVerificationKey::new(
            key_id,
            key_version,
            public_key.trim().to_owned(),
        ));
    }

    SignatureVerifier::new(keys, min_key_version)
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

fn current_state(app: &App) -> Arc<ActiveState> {
    app.state.load()
}

fn swap_state(app: &App, next: ActiveState) {
    app.state.store(next);
}

fn lock_metrics(app: &App) -> Result<std::sync::MutexGuard<'_, AgentMetrics>> {
    app.metrics
        .lock()
        .map_err(|_| GlobAclError::InvalidData("agent metrics lock poisoned".to_owned()))
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

fn parse_arg_u64(value: &str, field: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|err| GlobAclError::Parse(format!("invalid {field}: {err}")))
}
