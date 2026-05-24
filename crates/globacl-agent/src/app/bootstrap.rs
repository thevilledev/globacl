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

pub(crate) fn run() -> Result<()> {
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

