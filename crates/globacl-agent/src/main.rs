use globacl_core::{
    decode_mutation_stream, decode_snapshot, encode_snapshot, format_decision, http_get, now_unix,
    parse_query_path, read_http_request, read_snapshot_file, write_http_response,
    write_snapshot_file, ActiveState, GlobAclError, Result,
};
use std::env;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

struct App {
    relay_addr: String,
    snapshot_path: PathBuf,
    state: RwLock<ActiveState>,
    metrics: Mutex<AgentMetrics>,
}

#[derive(Default)]
struct AgentMetrics {
    last_sync_unix: u64,
    applied_mutations: u64,
    repairs: u64,
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

    let snapshot = load_or_fetch_snapshot(&relay_addr, &snapshot_path)?;
    let app = Arc::new(App {
        relay_addr,
        snapshot_path,
        state: RwLock::new(ActiveState::from_snapshot(snapshot)?),
        metrics: Mutex::new(AgentMetrics {
            last_sync_unix: now_unix(),
            ..AgentMetrics::default()
        }),
    });

    {
        let app = Arc::clone(&app);
        thread::spawn(move || poll_loop(app, Duration::from_millis(poll_ms)));
    }

    let listener = TcpListener::bind(bind_addr)?;
    eprintln!(
        "globacl-agent listening on {bind_addr}; relay_addr={}",
        app.relay_addr
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
            let state = read_state(&app)?;
            let metrics = lock_metrics(&app)?;
            let max_seq = state.watermarks().iter().copied().max().unwrap_or(0);
            let body = format!(
                "status=ok\nrole=agent\nshard_count={}\nentries={}\nmax_seq={}\nlast_sync_unix={}\napplied_mutations={}\nrepairs={}\n",
                state.shard_count(),
                state.entries_len(),
                max_seq,
                metrics.last_sync_unix,
                metrics.applied_mutations,
                metrics.repairs
            );
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/lookup") => {
            let tenant_id = required_query(&query, "tenant_id")?;
            let namespace = required_query(&query, "namespace")?;
            let key = required_query(&query, "key")?;
            let decision = {
                let state = read_state(&app)?;
                state.lookup(tenant_id, namespace, key, now_unix())
            };
            let body = format_decision(&decision);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/snapshot") => {
            let snapshot = {
                let state = read_state(&app)?;
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
        let state = read_state(app)?;
        state.shard_count()
    };

    for shard_id in 0..shard_count {
        let from_seq = {
            let state = read_state(app)?;
            state.watermarks()[shard_id as usize]
        };
        let path = format!("/v1/mutations?shard={shard_id}&from_seq={from_seq}");
        let response = http_get(&app.relay_addr, &path)?;
        if response.status_code != 200 {
            return Err(GlobAclError::InvalidData(format!(
                "relay returned status {} for {path}",
                response.status_code
            )));
        }
        let mutations = decode_mutation_stream(&response.body)?;
        if mutations.is_empty() {
            continue;
        }

        let mut applied = 0u64;
        {
            let mut state = write_state(app)?;
            for mutation in &mutations {
                match state.apply_mutation(mutation) {
                    Ok(globacl_core::ApplyStatus::Applied) => applied += 1,
                    Ok(globacl_core::ApplyStatus::DuplicateOrOld) => {}
                    Err(GlobAclError::Gap { .. }) => {
                        drop(state);
                        repair_from_snapshot(app)?;
                        return Ok(());
                    }
                    Err(err) => return Err(err),
                }
            }
            write_snapshot_file(&app.snapshot_path, &state.snapshot())?;
        }

        let mut metrics = lock_metrics(app)?;
        metrics.last_sync_unix = now_unix();
        metrics.applied_mutations += applied;
    }

    Ok(())
}

fn repair_from_snapshot(app: &Arc<App>) -> Result<()> {
    let snapshot = fetch_snapshot(&app.relay_addr)?;
    write_snapshot_file(&app.snapshot_path, &snapshot)?;
    {
        let mut state = write_state(app)?;
        *state = ActiveState::from_snapshot(snapshot)?;
    }
    let mut metrics = lock_metrics(app)?;
    metrics.last_sync_unix = now_unix();
    metrics.repairs += 1;
    Ok(())
}

fn load_or_fetch_snapshot(
    relay_addr: &str,
    snapshot_path: &Path,
) -> Result<globacl_core::Snapshot> {
    if snapshot_path.exists() {
        return read_snapshot_file(snapshot_path);
    }
    let snapshot = fetch_snapshot(relay_addr)?;
    write_snapshot_file(snapshot_path, &snapshot)?;
    Ok(snapshot)
}

fn fetch_snapshot(relay_addr: &str) -> Result<globacl_core::Snapshot> {
    let response = http_get(relay_addr, "/v1/snapshot")?;
    if response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "relay returned status {} for snapshot",
            response.status_code
        )));
    }
    decode_snapshot(&response.body)
}

fn read_state(app: &App) -> Result<std::sync::RwLockReadGuard<'_, ActiveState>> {
    app.state
        .read()
        .map_err(|_| GlobAclError::InvalidData("active state read lock poisoned".to_owned()))
}

fn write_state(app: &App) -> Result<std::sync::RwLockWriteGuard<'_, ActiveState>> {
    app.state
        .write()
        .map_err(|_| GlobAclError::InvalidData("active state write lock poisoned".to_owned()))
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
