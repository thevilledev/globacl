use globacl_core::{
    append_mutation_to_log, decode_snapshot, encode_mutation_stream, encode_snapshot,
    format_commit_outcome, format_decision, load_all_logs, now_unix, parse_form_lines,
    parse_query_path, read_http_request, write_http_response, write_snapshot_file, DenyRequest,
    GlobAclError, Result, SourceOfTruth, DEFAULT_SHARD_COUNT,
};
use std::env;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

struct App {
    state: Mutex<SourceOfTruth>,
    log_dir: PathBuf,
    snapshot_path: PathBuf,
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

    let log_dir = data_dir.join("logs");
    let snapshot_path = data_dir.join("snapshots").join("latest.gacl");
    let mutations = load_all_logs(&log_dir, shard_count)?;
    let state = SourceOfTruth::from_mutations(shard_count, "local", mutations)?;
    write_snapshot_file(&snapshot_path, &state.snapshot())?;

    let app = Arc::new(App {
        state: Mutex::new(state),
        log_dir,
        snapshot_path,
    });

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
            let outcome = {
                let mut state = lock_state(&app)?;
                let outcome = state.commit(deny_request)?;
                if !outcome.duplicate {
                    append_mutation_to_log(&app.log_dir, &outcome.mutation)?;
                    write_snapshot_file(&app.snapshot_path, &state.snapshot())?;
                }
                outcome
            };
            let body = format_commit_outcome(&outcome);
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
            let mutations = {
                let state = lock_state(&app)?;
                state.mutations_for_shard(shard_id, from_seq)
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

fn lock_state(app: &App) -> Result<std::sync::MutexGuard<'_, SourceOfTruth>> {
    app.state
        .lock()
        .map_err(|_| GlobAclError::InvalidData("source-of-truth lock poisoned".to_owned()))
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
