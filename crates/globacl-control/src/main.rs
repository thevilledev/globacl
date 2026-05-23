use globacl_core::{
    append_mutation_to_log, decode_snapshot, deny_requires_blast_radius_override,
    encode_mutation_stream, encode_snapshot, format_commit_outcome, format_decision,
    format_payload_signature, format_watermarks, load_all_logs, now_unix, parse_form_lines,
    parse_query_path, read_http_request, rule_requires_blast_radius_override,
    write_delta_bundle_file, write_http_response, write_snapshot_file, Action, DeliveryPriority,
    DenyRequest, GlobAclError, Mutation, Result, RuleRequest, Snapshot, SourceOfTruth,
    DEFAULT_SHARD_COUNT, DEFAULT_SIGNATURE_KEY_ID, DEFAULT_SIGNATURE_SECRET,
};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

struct App {
    state: Mutex<SourceOfTruth>,
    log_dir: PathBuf,
    bundle_dir: PathBuf,
    snapshot_dir: PathBuf,
    snapshot_path: PathBuf,
    audit_path: PathBuf,
    signature_key_id: String,
    signature_secret: String,
    latest_canary: Mutex<Option<CanaryStatus>>,
}

#[derive(Clone, Debug)]
struct CanaryStatus {
    op_id: String,
    key: String,
    shard_id: u16,
    seq: u64,
    created_at_unix: u64,
    expires_at: u64,
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let data_dir = PathBuf::from(args.get(1).map(String::as_str).unwrap_or("data/control"));
    let bind_addr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:7000");
    let shard_count = args
        .get(3)
        .map(|value| parse_arg_u16(value, "shard_count"))
        .transpose()?
        .unwrap_or(DEFAULT_SHARD_COUNT);
    let canary_interval_secs = args
        .get(4)
        .map(|value| parse_query_u64(value, "canary_interval_secs"))
        .transpose()?
        .unwrap_or(0);

    let log_dir = data_dir.join("logs");
    let bundle_dir = data_dir.join("bundles");
    let snapshot_dir = data_dir.join("snapshots");
    let snapshot_path = snapshot_dir.join("latest.gacl");
    let audit_path = data_dir.join("audit.log");
    let signature_key_id = env::var("GLOBACL_SIGNATURE_KEY_ID")
        .unwrap_or_else(|_| DEFAULT_SIGNATURE_KEY_ID.to_owned());
    let signature_secret = env::var("GLOBACL_SIGNATURE_SECRET")
        .unwrap_or_else(|_| DEFAULT_SIGNATURE_SECRET.to_owned());
    let mutations = load_all_logs(&log_dir, shard_count)?;
    let state = SourceOfTruth::from_mutations(shard_count, "local", mutations)?;
    write_signed_snapshot_file(
        &snapshot_path,
        &state.snapshot(),
        &signature_key_id,
        &signature_secret,
    )?;

    let app = Arc::new(App {
        state: Mutex::new(state),
        log_dir,
        bundle_dir,
        snapshot_dir,
        snapshot_path,
        audit_path,
        signature_key_id,
        signature_secret,
        latest_canary: Mutex::new(None),
    });

    if canary_interval_secs > 0 {
        let app = Arc::clone(&app);
        thread::spawn(move || canary_loop(app, Duration::from_secs(canary_interval_secs)));
    }

    let listener = TcpListener::bind(bind_addr)?;
    eprintln!(
        "globacl-control listening on {bind_addr}; data_dir={}",
        data_dir.display()
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
            let state = lock_state(&app)?;
            let body = format!(
                "status=ok\nshard_count={}\nentries={}\nmutations={}\n",
                state.shard_count(),
                state.entries_len(),
                state.mutations_len()
            );
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("POST", "/v1/deny") | ("POST", "/v1/mutation") => {
            let form = parse_form_lines(&request.body)?;
            let deny_request = DenyRequest::from_form(&form)?;
            if deny_requires_blast_radius_override(&deny_request)
                && !blast_radius_override_enabled(&form)
            {
                append_audit(
                    &app,
                    "deny",
                    "rejected",
                    &format!(
                        "op_id={} reason=blast_radius_override_required namespace={} key={}",
                        deny_request.op_id, deny_request.namespace, deny_request.key
                    ),
                )?;
                write_http_response(
                    &mut stream,
                    400,
                    "text/plain",
                    b"status=rejected\nreason=blast_radius_override_required\n",
                )?;
                return Ok(());
            }
            let outcome = commit_request(&app, deny_request)?;
            append_audit(
                &app,
                "deny",
                "committed",
                &format!(
                    "op_id={} shard_id={} seq={} duplicate={}",
                    outcome.mutation.op_id,
                    outcome.mutation.commit_id.shard_id,
                    outcome.mutation.commit_id.seq,
                    outcome.duplicate
                ),
            )?;
            let body = format_commit_outcome(&outcome);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("POST", "/v1/rule") => {
            let form = parse_form_lines(&request.body)?;
            let rule_request = RuleRequest::from_form(&form)?;
            if rule_requires_blast_radius_override(&rule_request)
                && !blast_radius_override_enabled(&form)
            {
                append_audit(
                    &app,
                    "rule",
                    "rejected",
                    &format!(
                        "op_id={} reason=blast_radius_override_required kind={} pattern={}",
                        rule_request.op_id,
                        rule_request.kind.as_str(),
                        rule_request.pattern
                    ),
                )?;
                write_http_response(
                    &mut stream,
                    400,
                    "text/plain",
                    b"status=rejected\nreason=blast_radius_override_required\n",
                )?;
                return Ok(());
            }
            let outcome = commit_rule_request(&app, rule_request)?;
            append_audit(
                &app,
                "rule",
                "committed",
                &format!(
                    "op_id={} shard_id={} seq={} duplicate={}",
                    outcome.mutation.op_id,
                    outcome.mutation.commit_id.shard_id,
                    outcome.mutation.commit_id.seq,
                    outcome.duplicate
                ),
            )?;
            let body = format_commit_outcome(&outcome);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("POST", "/v1/canary") => {
            let canary = commit_canary(&app)?;
            append_audit(
                &app,
                "canary",
                "committed",
                &format!(
                    "op_id={} shard_id={} seq={}",
                    canary.op_id, canary.shard_id, canary.seq
                ),
            )?;
            let body = format_canary_status(&canary);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/canary/latest") => {
            let latest = lock_canary(&app)?.clone();
            let body = latest
                .as_ref()
                .map(format_canary_status)
                .unwrap_or_else(|| "status=none\n".to_owned());
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/mutations") => {
            let mutations = mutations_for_query(&app, &query)?;
            let body = encode_mutation_stream(&mutations);
            write_http_response(&mut stream, 200, "application/octet-stream", &body)?;
        }
        ("GET", "/v1/mutations.sig") => {
            let mutations = mutations_for_query(&app, &query)?;
            let payload = encode_mutation_stream(&mutations);
            let body = sign_payload(&app, &payload);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/watermarks") => {
            let body = {
                let state = lock_state(&app)?;
                format_watermarks(state.watermarks())
            };
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/delta_bundle") => {
            let mutations = delta_bundle_for_query(&app, &query)?;
            let body = encode_mutation_stream(&mutations);
            write_http_response(&mut stream, 200, "application/octet-stream", &body)?;
        }
        ("GET", "/v1/delta_bundle.sig") => {
            let mutations = delta_bundle_for_query(&app, &query)?;
            let payload = encode_mutation_stream(&mutations);
            let body = sign_payload(&app, &payload);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/snapshot") => {
            let body = match fs::read(&app.snapshot_path) {
                Ok(bytes) => bytes,
                Err(_) => {
                    let state = lock_state(&app)?;
                    encode_snapshot(&state.snapshot())
                }
            };
            write_http_response(&mut stream, 200, "application/octet-stream", &body)?;
        }
        ("GET", "/v1/snapshot.sig") => {
            let body = fs::read(signature_path(&app.snapshot_path)).unwrap_or_else(|_| {
                match fs::read(&app.snapshot_path) {
                    Ok(bytes) => format_payload_signature(
                        &app.signature_key_id,
                        &app.signature_secret,
                        &bytes,
                    )
                    .into_bytes(),
                    Err(_) => Vec::new(),
                }
            });
            write_http_response(&mut stream, 200, "text/plain", &body)?;
        }
        ("GET", "/v1/snapshots") => {
            let body = format_snapshot_list(&app.snapshot_dir)?;
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("POST", "/v1/snapshot") => {
            let snapshot = decode_snapshot(&request.body)?;
            snapshot.validate()?;
            let archive_name = format!("uploaded_{}", now_unix());
            persist_archived_snapshot(&app, &snapshot, &archive_name)?;
            append_audit(
                &app,
                "snapshot",
                "uploaded",
                &format!("snapshot={archive_name}.gacl"),
            )?;
            write_http_response(&mut stream, 200, "text/plain", b"status=ok\n")?;
        }
        ("POST", "/v1/rollback") => {
            let form = parse_form_lines(&request.body)?;
            let snapshot_name = form
                .get("snapshot")
                .map(String::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| GlobAclError::Parse("missing required field snapshot".to_owned()))?;
            if !is_safe_snapshot_name(snapshot_name) {
                write_http_response(
                    &mut stream,
                    400,
                    "text/plain",
                    b"status=rejected\nreason=invalid_snapshot_name\n",
                )?;
                return Ok(());
            }
            let snapshot_path = app.snapshot_dir.join(snapshot_name);
            let snapshot = decode_snapshot(&fs::read(&snapshot_path)?)?;
            let rollback_id = format!("rollback-{}", now_unix());
            let (mutations, current_snapshot) = {
                let mut state = lock_state(&app)?;
                let mutations = state.restore_snapshot(snapshot, &rollback_id)?;
                let current_snapshot = state.snapshot();
                (mutations, current_snapshot)
            };
            persist_mutations(&app, &mutations)?;
            persist_latest_snapshot(&app, &current_snapshot)?;
            persist_archived_snapshot(&app, &current_snapshot, &rollback_id)?;
            append_audit(
                &app,
                "rollback",
                "committed",
                &format!("snapshot={} mutations={}", snapshot_name, mutations.len()),
            )?;
            let body = format!(
                "status=ok\nsnapshot={}\nmutations={}\n",
                snapshot_name,
                mutations.len()
            );
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/audit") => {
            let body = fs::read(&app.audit_path).unwrap_or_default();
            write_http_response(&mut stream, 200, "text/plain", &body)?;
        }
        ("GET", "/v1/lookup") => {
            let tenant_id = required_query(&query, "tenant_id")?;
            let namespace = required_query(&query, "namespace")?;
            let key = required_query(&query, "key")?;
            let decision = {
                let state = lock_state(&app)?;
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
                let state = lock_state(&app)?;
                state.check(tenant_id, namespace, value, now_unix())
            };
            let body = format_decision(&decision);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        _ => {
            write_http_response(&mut stream, 404, "text/plain", b"not found\n")?;
        }
    }

    Ok(())
}

fn mutations_for_query(
    app: &App,
    query: &std::collections::HashMap<String, String>,
) -> Result<Vec<Mutation>> {
    let shard_id = required_query_u16(query, "shard")?;
    let from_seq = query
        .get("from_seq")
        .or_else(|| query.get("from"))
        .map(|value| parse_query_u64(value, "from_seq"))
        .transpose()?
        .unwrap_or(0);
    let priority_filter = query
        .get("delivery_priority")
        .or_else(|| query.get("channel"))
        .map(|value| DeliveryPriority::from_name(value))
        .transpose()?;
    let state = lock_state(app)?;
    let mutations = state.mutations_for_shard(shard_id, from_seq);
    Ok(if let Some(priority) = priority_filter {
        mutations
            .into_iter()
            .filter(|mutation| mutation.delivery_priority == priority)
            .collect()
    } else {
        mutations
    })
}

fn delta_bundle_for_query(
    app: &App,
    query: &std::collections::HashMap<String, String>,
) -> Result<Vec<Mutation>> {
    let shard_id = required_query_u16(query, "shard")?;
    let from_seq = query
        .get("from_seq")
        .or_else(|| query.get("from"))
        .map(|value| parse_query_u64(value, "from_seq"))
        .transpose()?
        .unwrap_or(0);
    let to_seq = query
        .get("to_seq")
        .or_else(|| query.get("to"))
        .map(|value| parse_query_u64(value, "to_seq"))
        .transpose()?
        .unwrap_or(u64::MAX);
    let state = lock_state(app)?;
    Ok(state
        .mutations_for_shard(shard_id, from_seq)
        .into_iter()
        .filter(|mutation| mutation.commit_id.seq <= to_seq)
        .collect::<Vec<_>>())
}

fn sign_payload(app: &App, payload: &[u8]) -> String {
    format_payload_signature(&app.signature_key_id, &app.signature_secret, payload)
}

fn commit_request(app: &App, deny_request: DenyRequest) -> Result<globacl_core::CommitOutcome> {
    let mut state = lock_state(app)?;
    let outcome = state.commit(deny_request)?;
    if !outcome.duplicate {
        persist_mutation(app, &outcome.mutation)?;
        persist_latest_snapshot(app, &state.snapshot())?;
        persist_archived_snapshot(
            app,
            &state.snapshot(),
            &archive_name_for_mutation(&outcome.mutation),
        )?;
    }
    Ok(outcome)
}

fn commit_rule_request(
    app: &App,
    rule_request: RuleRequest,
) -> Result<globacl_core::CommitOutcome> {
    let mut state = lock_state(app)?;
    let outcome = state.commit_rule(rule_request)?;
    if !outcome.duplicate {
        persist_mutation(app, &outcome.mutation)?;
        persist_latest_snapshot(app, &state.snapshot())?;
        persist_archived_snapshot(
            app,
            &state.snapshot(),
            &archive_name_for_mutation(&outcome.mutation),
        )?;
    }
    Ok(outcome)
}

fn persist_mutations(app: &App, mutations: &[Mutation]) -> Result<()> {
    for mutation in mutations {
        persist_mutation(app, mutation)?;
    }
    Ok(())
}

fn persist_mutation(app: &App, mutation: &Mutation) -> Result<()> {
    append_mutation_to_log(&app.log_dir, mutation)?;
    write_delta_bundle_file(
        &app.bundle_dir,
        mutation.commit_id.shard_id,
        mutation.commit_id.seq,
        mutation.commit_id.seq,
        std::slice::from_ref(mutation),
    )?;
    Ok(())
}

fn persist_latest_snapshot(app: &App, snapshot: &Snapshot) -> Result<()> {
    write_signed_snapshot_file(
        &app.snapshot_path,
        snapshot,
        &app.signature_key_id,
        &app.signature_secret,
    )
}

fn persist_archived_snapshot(app: &App, snapshot: &Snapshot, name: &str) -> Result<()> {
    let path = app.snapshot_dir.join(format!("{name}.gacl"));
    write_signed_snapshot_file(path, snapshot, &app.signature_key_id, &app.signature_secret)
}

fn write_signed_snapshot_file(
    path: impl AsRef<Path>,
    snapshot: &Snapshot,
    key_id: &str,
    secret: &str,
) -> Result<()> {
    write_snapshot_file(&path, snapshot)?;
    let payload = fs::read(path.as_ref())?;
    let signature = format_payload_signature(key_id, secret, &payload);
    let sig_path = signature_path(path.as_ref());
    if let Some(parent) = sig_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(sig_path, signature)?;
    Ok(())
}

fn signature_path(path: impl AsRef<Path>) -> PathBuf {
    PathBuf::from(format!("{}.sig", path.as_ref().display()))
}

fn archive_name_for_mutation(mutation: &Mutation) -> String {
    format!(
        "epoch_{:020}_shard_{:04}_seq_{:020}",
        mutation.committed_at_unix, mutation.commit_id.shard_id, mutation.commit_id.seq
    )
}

fn format_snapshot_list(snapshot_dir: &Path) -> Result<String> {
    let mut names = Vec::new();
    if snapshot_dir.exists() {
        for entry in fs::read_dir(snapshot_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".gacl") {
                names.push(name);
            }
        }
    }
    names.sort();
    let mut body = format!("snapshot_count={}\n", names.len());
    for name in names {
        body.push_str(&format!("snapshot={name}\n"));
    }
    Ok(body)
}

fn append_audit(app: &App, event: &str, result: &str, detail: &str) -> Result<()> {
    if let Some(parent) = app.audit_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&app.audit_path)?;
    writeln!(
        file,
        "ts={} event={} result={} {}",
        now_unix(),
        event,
        result,
        detail
    )?;
    file.sync_data()?;
    Ok(())
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

fn is_safe_snapshot_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && name.ends_with(".gacl")
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

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
        created_by: "globacl-control".to_owned(),
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
    format!(
        "status=ok\nop_id={}\ntenant_id=globacl\nnamespace=canary\nkey={}\nshard_id={}\nseq={}\ncreated_at_unix={}\nexpires_at={}\ndelivery_priority=p0\n",
        status.op_id,
        status.key,
        status.shard_id,
        status.seq,
        status.created_at_unix,
        status.expires_at
    )
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
