use globacl_core::{
    decode_mutation_stream, decode_snapshot, decode_snapshot_manifest, encode_snapshot,
    format_decision, http_get, now_unix, parse_form_lines, parse_query_path,
    parse_signature_public_keys, parse_watermarks, read_http_request, read_snapshot_file,
    verify_payload_signature_with_verifier, write_http_response, write_snapshot_file, ActiveState,
    ActiveStateHandle, ActiveStateStats, Decision, GlobAclError, PopAck, Result,
    SignatureVerificationKey, SignatureVerifier, Snapshot, DEFAULT_SIGNATURE_KEY_ID,
    DEFAULT_SIGNATURE_KEY_VERSION,
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

/// In-process handle to the agent-owned edge state.
///
/// Cloning the handle is cheap. Each lookup loads the current RCU state pointer
/// and does not call the localhost HTTP sidecar.
#[derive(Clone)]
pub struct AgentHandle {
    app: Arc<App>,
}

/// Configuration for an embedded agent updater.
///
/// The embedded agent talks to the relay for snapshot bootstrap, mutation
/// polling, gap repair, canary checks, and ack reporting. Application code uses
/// [`AgentHandle`] for request-time lookup.
#[derive(Clone, Debug)]
pub struct AgentConfig {
    pub relay_addr: String,
    pub snapshot_path: PathBuf,
    pub poll_interval: Duration,
    pub agent_id: String,
    pub stale_after: Duration,
    pub signature_verifier: SignatureVerifier,
}

/// Health and state-lag view for an embedded or sidecar agent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentHealth {
    pub stale: bool,
    pub stale_after_secs: u64,
    pub state_lag_secs: u64,
    pub poll_lag_secs: u64,
    pub max_seq: u64,
    pub entries: usize,
    pub stats: ActiveStateStats,
    pub applied_mutations: u64,
    pub repairs: u64,
    pub bundle_repairs: u64,
    pub snapshot_repairs: u64,
    pub last_canary_seq: u64,
    pub last_canary_seen_unix: u64,
}

#[derive(Clone, Debug, Default)]
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

impl AgentConfig {
    pub fn new(relay_addr: impl Into<String>, snapshot_path: impl Into<PathBuf>) -> Result<Self> {
        Ok(Self {
            relay_addr: relay_addr.into(),
            snapshot_path: snapshot_path.into(),
            poll_interval: Duration::from_millis(1000),
            agent_id: "agent-embedded".to_owned(),
            stale_after: Duration::from_secs(60),
            signature_verifier: signature_verifier_from_env()?,
        })
    }

    pub fn with_poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = poll_interval;
        self
    }

    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = agent_id.into();
        self
    }

    pub fn with_stale_after(mut self, stale_after: Duration) -> Self {
        self.stale_after = stale_after;
        self
    }

    pub fn with_signature_verifier(mut self, signature_verifier: SignatureVerifier) -> Self {
        self.signature_verifier = signature_verifier;
        self
    }
}

impl AgentHandle {
    pub fn lookup(&self, tenant_id: &str, namespace: &str, key: &str, now_unix: u64) -> Decision {
        self.current_state()
            .lookup(tenant_id, namespace, key, now_unix)
    }

    pub fn check(&self, tenant_id: &str, namespace: &str, value: &str, now_unix: u64) -> Decision {
        self.current_state()
            .check(tenant_id, namespace, value, now_unix)
    }

    pub fn current_state(&self) -> Arc<ActiveState> {
        self.app.state.load()
    }

    pub fn snapshot(&self) -> Snapshot {
        self.current_state().snapshot()
    }

    pub fn health(&self) -> Result<AgentHealth> {
        let state = self.current_state();
        let metrics = lock_metrics(&self.app)?;
        let now = now_unix();
        let poll_lag_secs = now.saturating_sub(metrics.last_successful_poll_unix);
        let state_lag_secs = now.saturating_sub(metrics.last_sync_unix);
        Ok(AgentHealth {
            stale: poll_lag_secs > self.app.stale_after_secs,
            stale_after_secs: self.app.stale_after_secs,
            state_lag_secs,
            poll_lag_secs,
            max_seq: state.watermarks().iter().copied().max().unwrap_or(0),
            entries: state.entries_len(),
            stats: state.stats(),
            applied_mutations: metrics.applied_mutations,
            repairs: metrics.repairs,
            bundle_repairs: metrics.bundle_repairs,
            snapshot_repairs: metrics.snapshot_repairs,
            last_canary_seq: metrics.last_canary_seq,
            last_canary_seen_unix: metrics.last_canary_seen_unix,
        })
    }
}

/// Start propagation in a background thread and return an in-process lookup handle.
pub fn start_embedded(config: AgentConfig) -> Result<AgentHandle> {
    let poll_interval = config.poll_interval;
    let app = build_app(config)?;
    {
        let app = Arc::clone(&app);
        thread::spawn(move || poll_loop(app, poll_interval));
    }
    Ok(AgentHandle { app })
}

/// Serve the sidecar HTTP API over an existing in-process agent handle.
pub fn serve_http(handle: &AgentHandle, bind_addr: &str) -> Result<()> {
    let listener = TcpListener::bind(bind_addr)?;
    eprintln!(
        "globacl-agent listening on {bind_addr}; agent_id={}; relay_addr={}",
        handle.app.agent_id, handle.app.relay_addr
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let app = Arc::clone(&handle.app);
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

pub fn run() -> Result<()> {
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
    let config = AgentConfig::new(relay_addr, snapshot_path)?
        .with_poll_interval(Duration::from_millis(poll_ms))
        .with_agent_id(agent_id)
        .with_stale_after(Duration::from_secs(stale_after_secs));
    let handle = start_embedded(config)?;
    serve_http(&handle, bind_addr)
}

/// Load a snapshot-backed handle without starting the polling loop.
pub fn load_snapshot_handle(config: AgentConfig) -> Result<AgentHandle> {
    build_app(config).map(|app| AgentHandle { app })
}

fn build_app(config: AgentConfig) -> Result<Arc<App>> {
    let snapshot = load_or_fetch_snapshot(
        &config.relay_addr,
        &config.snapshot_path,
        &config.signature_verifier,
    )?;
    let started_at = now_unix();
    Ok(Arc::new(App {
        agent_id: config.agent_id,
        relay_addr: config.relay_addr,
        snapshot_path: config.snapshot_path,
        stale_after_secs: config.stale_after.as_secs(),
        signature_verifier: config.signature_verifier,
        state: ActiveStateHandle::from_snapshot(snapshot)?,
        metrics: Mutex::new(AgentMetrics {
            last_sync_unix: started_at,
            last_successful_poll_unix: started_at,
            ..AgentMetrics::default()
        }),
    }))
}
