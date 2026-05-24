use globacl_core::{
    append_mutation_to_log, auth_config_from_env_var, compact_logs_to_watermarks, decode_mutation,
    decode_mutation_stream, decode_snapshot, deny_requires_blast_radius_override, encode_mutation,
    encode_mutation_stream, encode_snapshot, encode_snapshot_manifest, format_commit_outcome,
    format_decision, format_watermarks, http_get, http_post, http_post_with_headers,
    immutable_snapshot_object_name, is_safe_snapshot_object_name, load_all_logs,
    nats_jetstream_ensure_stream, nats_jetstream_publish, now_unix, parse_form_lines,
    parse_query_path, parse_watermarks, read_http_request, rule_requires_blast_radius_override,
    sanitize_audit_value, snapshot_artifact_sha256_hex, write_auth_failure_response,
    write_delta_bundle_file, write_http_response, Action, ApplyStatus, AuthConfig, AuthPrincipal,
    DeliveryPriority, DenyRequest, GlobAclError, HttpRequest, Mutation, PropagationAck, Result,
    RuleRequest, SignatureSigner, Snapshot, SnapshotManifest, SourceOfTruth, DEFAULT_SHARD_COUNT,
    DEFAULT_SIGNATURE_KEY_ID, DEFAULT_SIGNATURE_KEY_VERSION, DEFAULT_SIGNATURE_PRIVATE_KEY,
};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct App {
    state: Mutex<SourceOfTruth>,
    log_dir: PathBuf,
    consensus_path: PathBuf,
    idempotency_path: PathBuf,
    pending_dir: PathBuf,
    bundle_dir: PathBuf,
    snapshot_dir: PathBuf,
    snapshot_object_dir: PathBuf,
    snapshot_manifest_dir: PathBuf,
    snapshot_path: PathBuf,
    snapshot_manifest_path: PathBuf,
    audit_path: PathBuf,
    publisher_offsets_path: PathBuf,
    propagation_acks_path: PathBuf,
    signature_signer: SignatureSigner,
    latest_canary: Mutex<Option<CanaryStatus>>,
    replication: ReplicationConfig,
    compaction: CompactionConfig,
    consensus: Mutex<ConsensusState>,
    sync_status: Mutex<SyncStatus>,
    publisher: Option<PublisherConfig>,
    publisher_status: Mutex<PublisherStatus>,
    propagation_acks: Mutex<HashMap<String, PropagationAck>>,
    auth: AuthConfig,
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

#[derive(Clone, Debug)]
struct ControlPeer {
    node_id: String,
    addr: String,
}

#[derive(Clone, Debug)]
struct ReplicationConfig {
    cluster_id: String,
    node_id: String,
    initial_leader_id: Option<String>,
    peers: Vec<ControlPeer>,
    quorum: usize,
    heartbeat_interval_ms: u64,
    election_timeout_ms: u64,
    sync_interval_ms: u64,
}

#[derive(Clone, Debug)]
struct CompactionConfig {
    min_log_entries: usize,
    compact_on_startup: bool,
}

impl ReplicationConfig {
    fn is_clustered(&self) -> bool {
        self.peers.len() > 1 || self.quorum > 1
    }

    fn peer_addr(&self, node_id: &str) -> Option<&str> {
        self.peers
            .iter()
            .find(|peer| peer.node_id == node_id)
            .map(|peer| peer.addr.as_str())
    }

    fn remote_peers(&self) -> impl Iterator<Item = &ControlPeer> {
        self.peers
            .iter()
            .filter(|peer| peer.node_id != self.node_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConsensusRole {
    Follower,
    Candidate,
    Leader,
}

impl ConsensusRole {
    fn as_str(self) -> &'static str {
        match self {
            ConsensusRole::Follower => "follower",
            ConsensusRole::Candidate => "candidate",
            ConsensusRole::Leader => "leader",
        }
    }
}

#[derive(Clone, Debug)]
struct ConsensusState {
    current_term: u64,
    voted_for: Option<String>,
    role: ConsensusRole,
    leader_id: Option<String>,
    last_leader_contact_ms: u64,
    election_deadline_ms: u64,
}

#[derive(Clone, Debug)]
struct SyncStatus {
    last_peer_sync_unix: u64,
    sync_errors: u64,
}

#[derive(Clone, Debug)]
struct PublisherConfig {
    nats_addr: String,
    stream: String,
    subject_prefix: String,
    publish_interval_ms: u64,
    autocreate_stream: bool,
}

#[derive(Clone, Debug)]
struct PublisherStatus {
    last_published: Vec<u64>,
    last_publish_unix: u64,
    publish_errors: u64,
}

pub(crate) fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let data_dir = PathBuf::from(args.get(1).map(String::as_str).unwrap_or("data/commitd"));
    let bind_addr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:7003");
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
    let consensus_path = data_dir.join("consensus.state");
    let idempotency_path = data_dir.join("idempotency.glog");
    let pending_dir = data_dir.join("pending");
    let bundle_dir = data_dir.join("bundles");
    let snapshot_dir = data_dir.join("snapshots");
    let snapshot_object_dir = snapshot_dir.join("objects");
    let snapshot_manifest_dir = snapshot_dir.join("manifests");
    let snapshot_path = snapshot_dir.join("latest.gacl");
    let snapshot_manifest_path = snapshot_manifest_dir.join("latest.manifest");
    let audit_path = data_dir.join("audit.log");
    let publisher_offsets_path = data_dir.join("publisher_offsets.state");
    let propagation_acks_path = data_dir.join("propagation_acks.log");
    let signature_signer = signature_signer_from_env()?;
    let auth = auth_config_from_env_var("GLOBACL_AUTH_TOKENS")?;
    let replication = replication_config(bind_addr)?;
    let compaction = compaction_config()?;
    let publisher = publisher_config()?;
    if let Some(publisher) = &publisher {
        if publisher.autocreate_stream {
            nats_jetstream_ensure_stream(
                &publisher.nats_addr,
                &publisher.stream,
                &[format!("{}.>", publisher.subject_prefix)],
            )?;
        }
    }
    let consensus = load_consensus_state(&consensus_path, &replication)?;
    let last_published = load_publisher_offsets(&publisher_offsets_path, shard_count)?;
    let state = load_source_of_truth(
        &log_dir,
        &snapshot_path,
        &idempotency_path,
        shard_count,
        &replication.cluster_id,
        publisher.as_ref().map(|_| last_published.as_slice()),
    )?;
    let startup_snapshot = state.snapshot();
    write_signed_snapshot_file(&snapshot_path, &startup_snapshot, &signature_signer)?;
    write_snapshot_manifest_publication(
        &snapshot_object_dir,
        &snapshot_manifest_dir,
        &snapshot_manifest_path,
        &startup_snapshot,
        &signature_signer,
    )?;

    let propagation_acks = load_propagation_acks(&propagation_acks_path)?;
    let app = Arc::new(App {
        state: Mutex::new(state),
        log_dir,
        consensus_path,
        idempotency_path,
        pending_dir,
        bundle_dir,
        snapshot_dir,
        snapshot_object_dir,
        snapshot_manifest_dir,
        snapshot_path,
        snapshot_manifest_path,
        audit_path,
        publisher_offsets_path,
        propagation_acks_path,
        signature_signer,
        latest_canary: Mutex::new(None),
        replication,
        compaction,
        consensus: Mutex::new(consensus),
        sync_status: Mutex::new(SyncStatus {
            last_peer_sync_unix: 0,
            sync_errors: 0,
        }),
        publisher,
        publisher_status: Mutex::new(PublisherStatus {
            last_published,
            last_publish_unix: 0,
            publish_errors: 0,
        }),
        propagation_acks: Mutex::new(propagation_acks),
        auth,
    });

    if app.compaction.compact_on_startup {
        if let Err(err) = compact_mutation_logs(&app, true) {
            eprintln!("startup log compaction skipped: {err}");
        }
    }

    if canary_interval_secs > 0 {
        let app = Arc::clone(&app);
        thread::spawn(move || canary_loop(app, Duration::from_secs(canary_interval_secs)));
    }
    if app.replication.is_clustered() {
        let app = Arc::clone(&app);
        thread::spawn(move || consensus_loop(app));
    }
    if app.replication.is_clustered() {
        let app = Arc::clone(&app);
        let interval = Duration::from_millis(app.replication.sync_interval_ms);
        thread::spawn(move || control_sync_loop(app, interval));
    }
    if let Some(publisher) = &app.publisher {
        let app = Arc::clone(&app);
        let interval = Duration::from_millis(publisher.publish_interval_ms);
        thread::spawn(move || publisher_loop(app, interval));
    }

    let listener = TcpListener::bind(bind_addr)?;
    let consensus = lock_consensus(&app)?.clone();
    eprintln!(
        "globacl-commitd listening on {bind_addr}; data_dir={}; node_id={}; role={}; term={}; quorum={}/{}",
        data_dir.display(),
        app.replication.node_id,
        consensus.role.as_str(),
        consensus.current_term,
        app.replication.quorum,
        app.replication.peers.len()
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
