use globacl_core::{
    append_mutation_to_log, decode_snapshot, encode_mutation_stream, encode_snapshot,
    format_commit_outcome, format_decision, format_watermarks, load_all_logs, now_unix,
    parse_form_lines, parse_query_path, read_http_request, write_delta_bundle_file,
    write_http_response, write_snapshot_file, Action, DeliveryPriority, DenyRequest, GlobAclError,
    Result, SourceOfTruth, DEFAULT_SHARD_COUNT,
};
use std::env;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

struct App {
    state: Mutex<SourceOfTruth>,
    log_dir: PathBuf,
    bundle_dir: PathBuf,
    snapshot_path: PathBuf,
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
    let snapshot_path = data_dir.join("snapshots").join("latest.gacl");
    let mutations = load_all_logs(&log_dir, shard_count)?;
    let state = SourceOfTruth::from_mutations(shard_count, "local", mutations)?;
    write_snapshot_file(&snapshot_path, &state.snapshot())?;

    let app = Arc::new(App {
        state: Mutex::new(state),
        log_dir,
        bundle_dir,
        snapshot_path,
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
            let outcome = commit_request(&app, deny_request)?;
            let body = format_commit_outcome(&outcome);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("POST", "/v1/canary") => {
            let canary = commit_canary(&app)?;
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
            let shard_id = required_query_u16(&query, "shard")?;
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
            let mutations = {
                let state = lock_state(&app)?;
                let mutations = state.mutations_for_shard(shard_id, from_seq);
                if let Some(priority) = priority_filter {
                    mutations
                        .into_iter()
                        .filter(|mutation| mutation.delivery_priority == priority)
                        .collect()
                } else {
                    mutations
                }
            };
            let body = encode_mutation_stream(&mutations);
            write_http_response(&mut stream, 200, "application/octet-stream", &body)?;
        }
        ("GET", "/v1/watermarks") => {
            let body = {
                let state = lock_state(&app)?;
                format_watermarks(state.watermarks())
            };
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/delta_bundle") => {
            let shard_id = required_query_u16(&query, "shard")?;
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
            let mutations = {
                let state = lock_state(&app)?;
                state
                    .mutations_for_shard(shard_id, from_seq)
                    .into_iter()
                    .filter(|mutation| mutation.commit_id.seq <= to_seq)
                    .collect::<Vec<_>>()
            };
            let body = encode_mutation_stream(&mutations);
            write_http_response(&mut stream, 200, "application/octet-stream", &body)?;
        }
        ("GET", "/v1/snapshot") => {
            let snapshot = {
                let state = lock_state(&app)?;
                state.snapshot()
            };
            let body = encode_snapshot(&snapshot);
            write_http_response(&mut stream, 200, "application/octet-stream", &body)?;
        }
        ("POST", "/v1/snapshot") => {
            let snapshot = decode_snapshot(&request.body)?;
            write_snapshot_file(&app.snapshot_path, &snapshot)?;
            write_http_response(&mut stream, 200, "text/plain", b"status=ok\n")?;
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
        _ => {
            write_http_response(&mut stream, 404, "text/plain", b"not found\n")?;
        }
    }

    Ok(())
}

fn commit_request(app: &App, deny_request: DenyRequest) -> Result<globacl_core::CommitOutcome> {
    let mut state = lock_state(app)?;
    let outcome = state.commit(deny_request)?;
    if !outcome.duplicate {
        append_mutation_to_log(&app.log_dir, &outcome.mutation)?;
        write_delta_bundle_file(
            &app.bundle_dir,
            outcome.mutation.commit_id.shard_id,
            outcome.mutation.commit_id.seq,
            outcome.mutation.commit_id.seq,
            std::slice::from_ref(&outcome.mutation),
        )?;
        write_snapshot_file(&app.snapshot_path, &state.snapshot())?;
    }
    Ok(outcome)
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
