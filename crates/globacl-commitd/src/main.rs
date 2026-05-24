use globacl_core::{
    append_mutation_to_log, decode_mutation, decode_mutation_stream, decode_snapshot,
    deny_requires_blast_radius_override, encode_mutation, encode_mutation_stream, encode_snapshot,
    encode_snapshot_manifest, format_commit_outcome, format_decision, format_watermarks, http_get,
    http_post, immutable_snapshot_object_name, is_safe_snapshot_object_name, load_all_logs,
    nats_jetstream_ensure_stream, nats_jetstream_publish, now_unix, parse_form_lines,
    parse_query_path, parse_watermarks, read_http_request, rule_requires_blast_radius_override,
    snapshot_artifact_sha256_hex, write_delta_bundle_file, write_http_response, Action,
    ApplyStatus, DeliveryPriority, DenyRequest, GlobAclError, Mutation, PropagationAck, Result,
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
    consensus: Mutex<ConsensusState>,
    sync_status: Mutex<SyncStatus>,
    publisher: Option<PublisherConfig>,
    publisher_status: Mutex<PublisherStatus>,
    propagation_acks: Mutex<HashMap<String, PropagationAck>>,
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

fn main() -> Result<()> {
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
    let replication = replication_config(bind_addr)?;
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
    let mutations = load_all_logs(&log_dir, shard_count)?;
    let state = SourceOfTruth::from_mutations(shard_count, &replication.cluster_id, mutations)?;
    let startup_snapshot = state.snapshot();
    write_signed_snapshot_file(&snapshot_path, &startup_snapshot, &signature_signer)?;
    write_snapshot_manifest_publication(
        &snapshot_object_dir,
        &snapshot_manifest_dir,
        &snapshot_manifest_path,
        &startup_snapshot,
        &signature_signer,
    )?;

    let last_published = load_publisher_offsets(&publisher_offsets_path, shard_count)?;
    let propagation_acks = load_propagation_acks(&propagation_acks_path)?;
    let app = Arc::new(App {
        state: Mutex::new(state),
        log_dir,
        consensus_path,
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
    });

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

fn handle_connection(mut stream: TcpStream, app: Arc<App>) -> Result<()> {
    let request = read_http_request(&mut stream)?;
    let (route, query) = parse_query_path(&request.path);

    if requires_leader(&request.method, &route)
        && app.replication.is_clustered()
        && !is_write_leader(&app)?
    {
        proxy_write_to_leader(&mut stream, &app, &request.path, &request.body)?;
        return Ok(());
    }

    match (request.method.as_str(), route.as_str()) {
        ("GET", "/health") => {
            let state = lock_state(&app)?;
            let consensus = lock_consensus(&app)?.clone();
            let sync_status = lock_sync_status(&app)?.clone();
            let publisher_status = lock_publisher_status(&app)?.clone();
            let central_ack_count = lock_propagation_acks(&app)?.len();
            let max_published_seq = publisher_status
                .last_published
                .iter()
                .copied()
                .max()
                .unwrap_or(0);
            let body = format!(
                "status=ok\nrole={}\nnode_id={}\ncluster_id={}\nleader_id={}\nterm={}\nvoted_for={}\nwrite_authority={}\nquorum={}\npeer_count={}\nshard_count={}\nentries={}\nmutations={}\njetstream_publisher={}\nmax_published_seq={}\ncentral_ack_count={}\nlast_publish_unix={}\npublish_errors={}\nlast_peer_sync_unix={}\nsync_errors={}\n",
                consensus.role.as_str(),
                app.replication.node_id,
                app.replication.cluster_id,
                consensus.leader_id.as_deref().unwrap_or(""),
                consensus.current_term,
                consensus.voted_for.as_deref().unwrap_or(""),
                consensus.role == ConsensusRole::Leader,
                app.replication.quorum,
                app.replication.peers.len(),
                state.shard_count(),
                state.entries_len(),
                state.mutations_len(),
                app.publisher.is_some(),
                max_published_seq,
                central_ack_count,
                publisher_status.last_publish_unix,
                publisher_status.publish_errors,
                sync_status.last_peer_sync_unix,
                sync_status.sync_errors
            );
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/v1/propagation/status") => {
            if app.replication.is_clustered() && !is_write_leader(&app)? {
                proxy_get_to_leader(&mut stream, &app, &request.path)?;
                return Ok(());
            }
            let body = format_propagation_status(&app)?;
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("POST", "/v1/ack") => {
            let form = parse_form_lines(&request.body)?;
            let ack = PropagationAck::from_form(&form)?;
            record_propagation_ack(&app, ack)?;
            write_http_response(&mut stream, 200, "text/plain", b"status=ok\n")?;
        }
        ("POST", "/internal/raft/request_vote") => {
            let form = parse_form_lines(&request.body)?;
            let response = handle_request_vote(&app, &form)?;
            write_http_response(&mut stream, 200, "text/plain", response.as_bytes())?;
        }
        ("POST", "/internal/raft/heartbeat") => {
            let form = parse_form_lines(&request.body)?;
            let response = handle_heartbeat(&app, &form)?;
            write_http_response(&mut stream, 200, "text/plain", response.as_bytes())?;
        }
        ("POST", "/internal/replication/prepare") => {
            let mutation = decode_mutation(&request.body)?;
            prepare_replicated_mutation(&app, &mutation)?;
            write_http_response(&mut stream, 200, "text/plain", b"status=prepared\n")?;
        }
        ("POST", "/internal/replication/commit") => {
            let mutation = decode_mutation(&request.body)?;
            let status = commit_replicated_mutation(&app, mutation)?;
            let body = match status {
                ApplyStatus::Applied => "status=applied\n",
                ApplyStatus::DuplicateOrOld => "status=duplicate\n",
            };
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("POST", "/internal/replication/abort") => {
            let mutation = decode_mutation(&request.body)?;
            remove_pending_mutation(&app.pending_dir, &mutation)?;
            write_http_response(&mut stream, 200, "text/plain", b"status=aborted\n")?;
        }
        ("POST", "/internal/replication/ack") => {
            let form = parse_form_lines(&request.body)?;
            let ack = PropagationAck::from_form(&form)?;
            let applied = apply_propagation_ack(&app, ack)?;
            let body = if applied {
                "status=applied\n"
            } else {
                "status=duplicate\n"
            };
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/internal/replication/acks") => {
            let body = format_propagation_ack_log_snapshot(&app)?;
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
            let body = sign_payload(&app, &payload)?;
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
            let body = sign_payload(&app, &payload)?;
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
            let body = match fs::read(signature_path(&app.snapshot_path)) {
                Ok(body) => body,
                Err(_) => match fs::read(&app.snapshot_path) {
                    Ok(bytes) => app.signature_signer.sign_payload(&bytes)?.into_bytes(),
                    Err(_) => Vec::new(),
                },
            };
            write_http_response(&mut stream, 200, "text/plain", &body)?;
        }
        ("GET", "/v1/snapshot_manifest") => {
            ensure_latest_snapshot_manifest(&app)?;
            let body = fs::read(&app.snapshot_manifest_path)?;
            write_http_response(&mut stream, 200, "text/plain", &body)?;
        }
        ("GET", "/v1/snapshot_manifest.sig") => {
            ensure_latest_snapshot_manifest(&app)?;
            let body = fs::read(signature_path(&app.snapshot_manifest_path))?;
            write_http_response(&mut stream, 200, "text/plain", &body)?;
        }
        ("GET", "/v1/snapshot_artifact") => {
            let object = required_query(&query, "object")?;
            if !is_safe_snapshot_object_name(object) {
                write_http_response(
                    &mut stream,
                    400,
                    "text/plain",
                    b"status=rejected\nreason=invalid_snapshot_object\n",
                )?;
                return Ok(());
            }
            let body = fs::read(app.snapshot_object_dir.join(object))?;
            write_http_response(&mut stream, 200, "application/octet-stream", &body)?;
        }
        ("GET", "/v1/snapshot_artifact.sig") => {
            let object = required_query(&query, "object")?;
            if !is_safe_snapshot_object_name(object) {
                write_http_response(
                    &mut stream,
                    400,
                    "text/plain",
                    b"status=rejected\nreason=invalid_snapshot_object\n",
                )?;
                return Ok(());
            }
            let body = fs::read(signature_path(app.snapshot_object_dir.join(object)))?;
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
            let term = ensure_write_authority(&app)?;
            let mutations = {
                let mut state = lock_state(&app)?;
                state.set_epoch(term);
                let mut planned = state.clone();
                planned.set_epoch(term);
                let mutations = planned.restore_snapshot(snapshot, &rollback_id)?;
                for mutation in mutations.iter().cloned() {
                    commit_prepared_outcome(
                        &app,
                        &mut state,
                        globacl_core::CommitOutcome {
                            mutation,
                            duplicate: false,
                        },
                    )?;
                }
                mutations
            };
            let current_snapshot = {
                let state = lock_state(&app)?;
                state.snapshot()
            };
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

fn sign_payload(app: &App, payload: &[u8]) -> Result<String> {
    app.signature_signer.sign_payload(payload)
}

fn ensure_latest_snapshot_manifest(app: &App) -> Result<()> {
    if app.snapshot_manifest_path.exists() && signature_path(&app.snapshot_manifest_path).exists() {
        return Ok(());
    }
    let snapshot = {
        let state = lock_state(app)?;
        state.snapshot()
    };
    persist_latest_snapshot(app, &snapshot)
}

fn commit_request(app: &App, deny_request: DenyRequest) -> Result<globacl_core::CommitOutcome> {
    let term = ensure_write_authority(app)?;
    let mut state = lock_state(app)?;
    state.set_epoch(term);
    let outcome = state.prepare_commit(deny_request)?;
    commit_prepared_outcome(app, &mut state, outcome)
}

fn commit_prepared_outcome(
    app: &App,
    state: &mut SourceOfTruth,
    outcome: globacl_core::CommitOutcome,
) -> Result<globacl_core::CommitOutcome> {
    if outcome.duplicate {
        return Ok(outcome);
    }

    let term = ensure_write_authority(app)?;
    if outcome.mutation.commit_id.epoch != term {
        return Err(GlobAclError::InvalidData(format!(
            "mutation epoch {} does not match current leader term {term}",
            outcome.mutation.commit_id.epoch
        )));
    }
    prepare_on_quorum(app, &outcome.mutation)?;
    apply_prepared_mutation(app, state, outcome.mutation.clone())?;
    commit_on_peers(app, &outcome.mutation);
    Ok(outcome)
}

fn commit_rule_request(
    app: &App,
    rule_request: RuleRequest,
) -> Result<globacl_core::CommitOutcome> {
    let term = ensure_write_authority(app)?;
    let mut state = lock_state(app)?;
    state.set_epoch(term);
    let outcome = state.prepare_rule_commit(rule_request)?;
    commit_prepared_outcome(app, &mut state, outcome)
}

fn apply_prepared_mutation(
    app: &App,
    state: &mut SourceOfTruth,
    mutation: Mutation,
) -> Result<ApplyStatus> {
    let shard_id = mutation.commit_id.shard_id;
    let already_at_or_past_seq = state
        .watermarks()
        .get(shard_id as usize)
        .copied()
        .unwrap_or(0)
        >= mutation.commit_id.seq;
    if !already_at_or_past_seq {
        persist_mutation(app, &mutation)?;
    }
    let status = state.apply_replicated_mutation(mutation.clone())?;
    if status == ApplyStatus::Applied {
        persist_latest_snapshot(app, &state.snapshot())?;
        persist_archived_snapshot(
            app,
            &state.snapshot(),
            &archive_name_for_mutation(&mutation),
        )?;
    }
    remove_pending_mutation(&app.pending_dir, &mutation)?;
    Ok(status)
}

fn ensure_write_authority(app: &App) -> Result<u64> {
    let consensus = lock_consensus(app)?;
    if consensus.role == ConsensusRole::Leader {
        return Ok(consensus.current_term);
    }
    Err(GlobAclError::InvalidData(format!(
        "node {} is not the write leader; leader is {}",
        app.replication.node_id,
        consensus.leader_id.as_deref().unwrap_or("unknown")
    )))
}

fn prepare_on_quorum(app: &App, mutation: &Mutation) -> Result<()> {
    if !app.replication.is_clustered() {
        return Ok(());
    }

    let payload = encode_mutation(mutation);
    let mut prepared = 1usize;
    let mut failures = Vec::new();
    for peer in app.replication.remote_peers() {
        match http_post(&peer.addr, "/internal/replication/prepare", &payload) {
            Ok(response) if response.status_code == 200 => prepared += 1,
            Ok(response) => {
                failures.push(format!("{}:status={}", peer.node_id, response.status_code))
            }
            Err(err) => failures.push(format!("{}:{err}", peer.node_id)),
        }
    }

    if prepared >= app.replication.quorum {
        return Ok(());
    }

    abort_on_peers(app, mutation);
    Err(GlobAclError::InvalidData(format!(
        "commitd quorum unavailable: prepared={prepared} quorum={} failures={}",
        app.replication.quorum,
        failures.join(",")
    )))
}

fn commit_on_peers(app: &App, mutation: &Mutation) {
    if !app.replication.is_clustered() {
        return;
    }

    let payload = encode_mutation(mutation);
    for peer in app.replication.remote_peers() {
        match http_post(&peer.addr, "/internal/replication/commit", &payload) {
            Ok(response) if response.status_code == 200 => {}
            Ok(response) => eprintln!(
                "peer commit failed: peer={} status={}",
                peer.node_id, response.status_code
            ),
            Err(err) => eprintln!("peer commit failed: peer={} error={err}", peer.node_id),
        }
    }
}

fn abort_on_peers(app: &App, mutation: &Mutation) {
    let payload = encode_mutation(mutation);
    for peer in app.replication.remote_peers() {
        if let Err(err) = http_post(&peer.addr, "/internal/replication/abort", &payload) {
            eprintln!("peer abort failed: peer={} error={err}", peer.node_id);
        }
    }
}

fn prepare_replicated_mutation(app: &App, mutation: &Mutation) -> Result<()> {
    ensure_same_cluster(app, mutation)?;
    ensure_mutation_term(app, mutation)?;
    let state = lock_state(app)?;
    let shard_id = mutation.commit_id.shard_id;
    let current_seq = state
        .watermarks()
        .get(shard_id as usize)
        .copied()
        .ok_or_else(|| {
            GlobAclError::InvalidData(format!(
                "shard {shard_id} is outside shard_count {}",
                state.shard_count()
            ))
        })?;
    if mutation.commit_id.seq <= current_seq {
        return Ok(());
    }
    let expected_seq = current_seq + 1;
    if mutation.commit_id.seq != expected_seq {
        return Err(GlobAclError::Gap {
            shard_id,
            expected_seq,
            received_seq: mutation.commit_id.seq,
        });
    }
    write_pending_mutation(&app.pending_dir, mutation)
}

fn commit_replicated_mutation(app: &App, mutation: Mutation) -> Result<ApplyStatus> {
    ensure_same_cluster(app, &mutation)?;
    ensure_mutation_term(app, &mutation)?;
    let mut state = lock_state(app)?;
    apply_prepared_mutation(app, &mut state, mutation)
}

fn ensure_same_cluster(app: &App, mutation: &Mutation) -> Result<()> {
    if mutation.commit_id.source_region == app.replication.cluster_id {
        return Ok(());
    }
    Err(GlobAclError::InvalidData(format!(
        "mutation cluster {} does not match local cluster {}",
        mutation.commit_id.source_region, app.replication.cluster_id
    )))
}

fn ensure_mutation_term(app: &App, mutation: &Mutation) -> Result<()> {
    let mut consensus = lock_consensus(app)?;
    if mutation.commit_id.epoch < consensus.current_term {
        return Err(GlobAclError::InvalidData(format!(
            "stale mutation epoch {} is older than local term {}",
            mutation.commit_id.epoch, consensus.current_term
        )));
    }
    if mutation.commit_id.epoch > consensus.current_term {
        consensus.current_term = mutation.commit_id.epoch;
        consensus.voted_for = None;
        consensus.role = ConsensusRole::Follower;
        consensus.leader_id = None;
        consensus.last_leader_contact_ms = now_unix_millis();
        consensus.election_deadline_ms = next_election_deadline_ms(
            &app.replication.node_id,
            app.replication.election_timeout_ms,
        );
        persist_consensus_state(&app.consensus_path, &consensus)?;
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
    write_signed_snapshot_file(&app.snapshot_path, snapshot, &app.signature_signer)?;
    persist_snapshot_manifest(app, snapshot)?;
    Ok(())
}

fn persist_archived_snapshot(app: &App, snapshot: &Snapshot, name: &str) -> Result<()> {
    let path = app.snapshot_dir.join(format!("{name}.gacl"));
    write_signed_snapshot_file(path, snapshot, &app.signature_signer)?;
    persist_snapshot_manifest(app, snapshot)?;
    Ok(())
}

fn write_signed_snapshot_file(
    path: impl AsRef<Path>,
    snapshot: &Snapshot,
    signer: &SignatureSigner,
) -> Result<()> {
    let payload = encode_snapshot(snapshot);
    write_signed_payload_file(path, &payload, signer)
}

fn persist_snapshot_manifest(app: &App, snapshot: &Snapshot) -> Result<SnapshotManifest> {
    write_snapshot_manifest_publication(
        &app.snapshot_object_dir,
        &app.snapshot_manifest_dir,
        &app.snapshot_manifest_path,
        snapshot,
        &app.signature_signer,
    )
}

fn write_snapshot_manifest_publication(
    object_dir: &Path,
    manifest_dir: &Path,
    latest_manifest_path: &Path,
    snapshot: &Snapshot,
    signer: &SignatureSigner,
) -> Result<SnapshotManifest> {
    let payload = encode_snapshot(snapshot);
    let artifact_sha256 = snapshot_artifact_sha256_hex(&payload);
    let artifact_object = immutable_snapshot_object_name(snapshot, &artifact_sha256);
    let artifact_path = object_dir.join(&artifact_object);
    write_signed_payload_file(&artifact_path, &payload, signer)?;

    let manifest = SnapshotManifest::for_snapshot(
        snapshot,
        now_unix(),
        artifact_object,
        payload.len() as u64,
        artifact_sha256,
    );
    let manifest_payload = encode_snapshot_manifest(&manifest);
    let immutable_manifest_path = manifest_dir.join(format!(
        "epoch_{:020}_seq_{:020}_sha256_{}.manifest",
        manifest.created_at_unix,
        manifest.max_seq,
        &manifest.artifact_sha256[..16]
    ));
    write_signed_payload_file(&immutable_manifest_path, &manifest_payload, signer)?;
    write_signed_payload_file(latest_manifest_path, &manifest_payload, signer)?;
    Ok(manifest)
}

fn write_signed_payload_file(
    path: impl AsRef<Path>,
    payload: &[u8],
    signer: &SignatureSigner,
) -> Result<()> {
    write_payload_file(&path, payload)?;
    let signature = signer.sign_payload(payload)?;
    let sig_path = signature_path(path.as_ref());
    write_payload_file(sig_path, signature.as_bytes())
}

fn write_payload_file(path: impl AsRef<Path>, payload: &[u8]) -> Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.as_ref().with_extension("tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(payload)?;
        file.sync_all()?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

fn write_pending_mutation(pending_dir: &Path, mutation: &Mutation) -> Result<()> {
    fs::create_dir_all(pending_dir)?;
    let path = pending_mutation_path(pending_dir, mutation);
    if path.exists() {
        let existing = decode_mutation(&fs::read(&path)?)?;
        if existing == *mutation {
            return Ok(());
        }
        return Err(GlobAclError::InvalidData(format!(
            "pending mutation conflict at {}",
            path.display()
        )));
    }

    let tmp = path.with_extension("tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(&encode_mutation(mutation))?;
        file.sync_all()?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

fn remove_pending_mutation(pending_dir: &Path, mutation: &Mutation) -> Result<()> {
    let path = pending_mutation_path(pending_dir, mutation);
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn pending_mutation_path(pending_dir: &Path, mutation: &Mutation) -> PathBuf {
    pending_dir.join(format!(
        "shard_{:04}_seq_{:020}.gmut",
        mutation.commit_id.shard_id, mutation.commit_id.seq
    ))
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
    let mut manifests = Vec::new();
    let manifest_dir = snapshot_dir.join("manifests");
    if manifest_dir.exists() {
        for entry in fs::read_dir(manifest_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".manifest") {
                manifests.push(name);
            }
        }
    }
    names.sort();
    manifests.sort();
    let mut body = format!("snapshot_count={}\n", names.len());
    for name in names {
        body.push_str(&format!("snapshot={name}\n"));
    }
    body.push_str(&format!("manifest_count={}\n", manifests.len()));
    for name in manifests {
        body.push_str(&format!("manifest={name}\n"));
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

fn consensus_loop(app: Arc<App>) {
    if !app.replication.is_clustered() {
        return;
    }

    loop {
        let role = lock_consensus(&app)
            .map(|consensus| consensus.role)
            .unwrap_or(ConsensusRole::Follower);

        match role {
            ConsensusRole::Leader => {
                send_heartbeats(&app);
                thread::sleep(Duration::from_millis(app.replication.heartbeat_interval_ms));
            }
            ConsensusRole::Follower | ConsensusRole::Candidate => {
                let should_start_election = lock_consensus(&app)
                    .map(|consensus| now_unix_millis() >= consensus.election_deadline_ms)
                    .unwrap_or(false);
                if should_start_election {
                    if let Err(err) = start_election(&app) {
                        eprintln!("leader election failed: {err}");
                    }
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn start_election(app: &App) -> Result<()> {
    let (last_seq, log_len) = local_log_status(app)?;
    let (term, last_seq, log_len) = {
        let mut consensus = lock_consensus(app)?;
        consensus.current_term += 1;
        consensus.voted_for = Some(app.replication.node_id.clone());
        consensus.role = ConsensusRole::Candidate;
        consensus.leader_id = None;
        consensus.last_leader_contact_ms = 0;
        consensus.election_deadline_ms = next_election_deadline_ms(
            &app.replication.node_id,
            app.replication.election_timeout_ms,
        );
        persist_consensus_state(&app.consensus_path, &consensus)?;
        (consensus.current_term, last_seq, log_len)
    };

    let mut votes = 1usize;
    for peer in app.replication.remote_peers() {
        let body = format!(
            "term={term}\ncandidate_id={}\nlast_seq={last_seq}\nlog_len={log_len}\n",
            app.replication.node_id
        );
        match http_post(&peer.addr, "/internal/raft/request_vote", body.as_bytes()) {
            Ok(response) if response.status_code == 200 => {
                let form = parse_form_lines(&response.body)?;
                let peer_term = parse_form_u64(&form, "term", term)?;
                if peer_term > term {
                    step_down_to_term(app, peer_term, None)?;
                    return Ok(());
                }
                if form_bool(&form, "vote_granted") {
                    votes += 1;
                }
            }
            Ok(response) => eprintln!(
                "vote request failed: peer={} status={}",
                peer.node_id, response.status_code
            ),
            Err(err) => eprintln!("vote request failed: peer={} error={err}", peer.node_id),
        }
    }

    if votes >= app.replication.quorum {
        let mut consensus = lock_consensus(app)?;
        if consensus.current_term == term && consensus.role == ConsensusRole::Candidate {
            consensus.role = ConsensusRole::Leader;
            consensus.leader_id = Some(app.replication.node_id.clone());
            consensus.last_leader_contact_ms = now_unix_millis();
            persist_consensus_state(&app.consensus_path, &consensus)?;
            drop(consensus);
            if let Err(err) = sync_acks_from_peers(app) {
                eprintln!("leader ack merge failed: {err}");
            }
            send_heartbeats(app);
        }
    }

    Ok(())
}

fn send_heartbeats(app: &App) {
    let term = match lock_consensus(app) {
        Ok(consensus) if consensus.role == ConsensusRole::Leader => consensus.current_term,
        _ => return,
    };

    let body = format!("term={term}\nleader_id={}\n", app.replication.node_id);
    for peer in app.replication.remote_peers() {
        match http_post(&peer.addr, "/internal/raft/heartbeat", body.as_bytes()) {
            Ok(response) if response.status_code == 200 => {
                if let Ok(form) = parse_form_lines(&response.body) {
                    if let Ok(peer_term) = parse_form_u64(&form, "term", term) {
                        if peer_term > term {
                            let _ = step_down_to_term(app, peer_term, None);
                            return;
                        }
                    }
                }
            }
            Ok(response) => eprintln!(
                "heartbeat failed: peer={} status={}",
                peer.node_id, response.status_code
            ),
            Err(err) => eprintln!("heartbeat failed: peer={} error={err}", peer.node_id),
        }
    }
}

fn handle_request_vote(
    app: &App,
    form: &std::collections::HashMap<String, String>,
) -> Result<String> {
    let candidate_term = parse_form_u64(form, "term", 0)?;
    let candidate_id = required_form(form, "candidate_id")?;
    let candidate_last_seq = parse_form_u64(form, "last_seq", 0)?;
    let candidate_log_len = parse_form_u64(form, "log_len", 0)?;
    let (local_last_seq, local_log_len) = local_log_status(app)?;

    let mut consensus = lock_consensus(app)?;
    if candidate_term > consensus.current_term {
        consensus.current_term = candidate_term;
        consensus.voted_for = None;
        consensus.role = ConsensusRole::Follower;
        consensus.leader_id = None;
    }

    let up_to_date = candidate_last_seq > local_last_seq
        || (candidate_last_seq == local_last_seq && candidate_log_len >= local_log_len);
    let no_conflicting_leader = consensus
        .leader_id
        .as_ref()
        .map(|leader_id| leader_id == candidate_id)
        .unwrap_or(true);
    let can_vote = candidate_term == consensus.current_term
        && up_to_date
        && no_conflicting_leader
        && consensus
            .voted_for
            .as_ref()
            .map(|voted_for| voted_for == candidate_id)
            .unwrap_or(true);

    if can_vote {
        consensus.voted_for = Some(candidate_id.to_owned());
        consensus.role = ConsensusRole::Follower;
        consensus.leader_id = None;
        consensus.last_leader_contact_ms = now_unix_millis();
        consensus.election_deadline_ms = next_election_deadline_ms(
            &app.replication.node_id,
            app.replication.election_timeout_ms,
        );
        persist_consensus_state(&app.consensus_path, &consensus)?;
    } else if candidate_term >= consensus.current_term {
        persist_consensus_state(&app.consensus_path, &consensus)?;
    }

    Ok(format!(
        "term={}\nvote_granted={}\n",
        consensus.current_term, can_vote
    ))
}

fn handle_heartbeat(app: &App, form: &std::collections::HashMap<String, String>) -> Result<String> {
    let leader_term = parse_form_u64(form, "term", 0)?;
    let leader_id = required_form(form, "leader_id")?;
    let mut consensus = lock_consensus(app)?;
    let higher_term = leader_term > consensus.current_term;
    let same_term = leader_term == consensus.current_term;
    let conflicting_leader = same_term
        && consensus
            .leader_id
            .as_ref()
            .map(|known_leader| known_leader != leader_id)
            .unwrap_or(false);
    let conflicting_vote = same_term
        && consensus
            .voted_for
            .as_ref()
            .map(|voted_for| voted_for != leader_id)
            .unwrap_or(false);
    let accepted = higher_term || (same_term && !conflicting_leader && !conflicting_vote);

    if accepted {
        consensus.current_term = leader_term;
        if higher_term {
            consensus.voted_for = None;
        }
        consensus.role = ConsensusRole::Follower;
        consensus.leader_id = Some(leader_id.to_owned());
        if consensus.voted_for.is_none() {
            consensus.voted_for = Some(leader_id.to_owned());
        }
        consensus.last_leader_contact_ms = now_unix_millis();
        consensus.election_deadline_ms = next_election_deadline_ms(
            &app.replication.node_id,
            app.replication.election_timeout_ms,
        );
        persist_consensus_state(&app.consensus_path, &consensus)?;
    }

    Ok(format!(
        "term={}\nsuccess={}\n",
        consensus.current_term, accepted
    ))
}

fn step_down_to_term(app: &App, term: u64, leader_id: Option<String>) -> Result<()> {
    let mut consensus = lock_consensus(app)?;
    if term > consensus.current_term {
        consensus.current_term = term;
        consensus.voted_for = None;
    }
    consensus.role = ConsensusRole::Follower;
    consensus.leader_id = leader_id;
    consensus.last_leader_contact_ms = now_unix_millis();
    consensus.election_deadline_ms = next_election_deadline_ms(
        &app.replication.node_id,
        app.replication.election_timeout_ms,
    );
    persist_consensus_state(&app.consensus_path, &consensus)
}

fn control_sync_loop(app: Arc<App>, interval: Duration) {
    loop {
        if let Err(err) = sync_from_leader(&app) {
            eprintln!("commitd peer sync failed: {err}");
            if let Ok(mut status) = lock_sync_status(&app) {
                status.sync_errors += 1;
            }
        }
        thread::sleep(interval);
    }
}

fn sync_from_leader(app: &App) -> Result<()> {
    if is_write_leader(app)? {
        return Ok(());
    }
    let leader_addr = current_leader_addr(app)?
        .ok_or_else(|| GlobAclError::InvalidData("leader address is not configured".to_owned()))?;
    let watermarks_response = http_get(&leader_addr, "/v1/watermarks")?;
    if watermarks_response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "leader returned status {} for watermarks",
            watermarks_response.status_code
        )));
    }
    let remote_watermarks = parse_watermarks(&watermarks_response.body)?;
    let shard_count = {
        let state = lock_state(app)?;
        state.shard_count()
    };

    for shard_id in 0..shard_count {
        let local_seq = {
            let state = lock_state(app)?;
            state.watermarks()[shard_id as usize]
        };
        let remote_seq = remote_watermarks
            .get(shard_id as usize)
            .copied()
            .unwrap_or(local_seq);
        if remote_seq <= local_seq {
            continue;
        }

        let path = format!("/v1/mutations?shard={shard_id}&from_seq={local_seq}");
        let response = http_get(&leader_addr, &path)?;
        if response.status_code != 200 {
            return Err(GlobAclError::InvalidData(format!(
                "leader returned status {} for {path}",
                response.status_code
            )));
        }
        for mutation in decode_mutation_stream(&response.body)? {
            commit_replicated_mutation(app, mutation)?;
        }
    }

    sync_acks_from_peer(app, &leader_addr)?;

    let mut status = lock_sync_status(app)?;
    status.last_peer_sync_unix = now_unix();
    Ok(())
}

fn publisher_loop(app: Arc<App>, interval: Duration) {
    loop {
        if let Err(err) = publish_committed_mutations(&app) {
            eprintln!("commitd JetStream publish failed: {err}");
            if let Ok(mut status) = lock_publisher_status(&app) {
                status.publish_errors += 1;
            }
        }
        thread::sleep(interval);
    }
}

fn publish_committed_mutations(app: &App) -> Result<()> {
    let Some(publisher) = &app.publisher else {
        return Ok(());
    };
    if app.replication.is_clustered() && !is_write_leader(app)? {
        return Ok(());
    }

    let last_published = lock_publisher_status(app)?.last_published.clone();
    let mutations = {
        let state = lock_state(app)?;
        let mut mutations = Vec::new();
        for shard_id in 0..state.shard_count() {
            let from_seq = last_published.get(shard_id as usize).copied().unwrap_or(0);
            mutations.extend(state.mutations_for_shard(shard_id, from_seq));
        }
        mutations.sort_by_key(|mutation| {
            (
                mutation.committed_at_unix,
                mutation.commit_id.shard_id,
                mutation.commit_id.seq,
            )
        });
        mutations
    };

    if mutations.is_empty() {
        return Ok(());
    }

    let mut next_published = last_published;
    for mutation in mutations {
        let subject = mutation_subject(&publisher.subject_prefix, &mutation);
        nats_jetstream_publish(&publisher.nats_addr, &subject, &encode_mutation(&mutation))?;
        let slot = mutation.commit_id.shard_id as usize;
        if let Some(seq) = next_published.get_mut(slot) {
            *seq = (*seq).max(mutation.commit_id.seq);
        }
    }

    let mut status = lock_publisher_status(app)?;
    persist_publisher_offsets(&app.publisher_offsets_path, &next_published)?;
    status.last_published = next_published;
    status.last_publish_unix = now_unix();
    Ok(())
}

fn mutation_subject(prefix: &str, mutation: &Mutation) -> String {
    format!(
        "{}.{}.shard.{}",
        prefix,
        mutation.delivery_priority.as_str(),
        mutation.commit_id.shard_id
    )
}

fn load_publisher_offsets(path: &Path, shard_count: u16) -> Result<Vec<u64>> {
    let mut offsets = vec![0; shard_count as usize];
    if !path.exists() {
        return Ok(offsets);
    }
    let bytes = fs::read(path)?;
    let form = parse_form_lines(&bytes)?;
    for (shard_id, offset) in offsets.iter_mut().enumerate() {
        let key = format!("shard_{shard_id:04}");
        if let Some(value) = form.get(&key) {
            *offset = parse_query_u64(value, &key)?;
        }
    }
    Ok(offsets)
}

fn persist_publisher_offsets(path: &Path, offsets: &[u64]) -> Result<()> {
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
        writeln!(file, "shard_count={}", offsets.len())?;
        for (shard_id, seq) in offsets.iter().enumerate() {
            writeln!(file, "shard_{shard_id:04}={seq}")?;
        }
        file.sync_all()?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

fn record_propagation_ack(app: &App, ack: PropagationAck) -> Result<()> {
    if app.replication.is_clustered() {
        ensure_write_authority(app)?;
    }
    apply_propagation_ack(app, ack.clone())?;
    replicate_propagation_ack_on_quorum(app, &ack)
}

fn apply_propagation_ack(app: &App, ack: PropagationAck) -> Result<bool> {
    let mut acks = lock_propagation_acks(app)?;
    apply_propagation_ack_to_store(&app.propagation_acks_path, &mut acks, ack)
}

fn apply_propagation_ack_to_store(
    path: &Path,
    acks: &mut HashMap<String, PropagationAck>,
    ack: PropagationAck,
) -> Result<bool> {
    let key = ack.key();
    if let Some(existing) = acks.get(&key) {
        if existing.seq > ack.seq || existing == &ack {
            return Ok(false);
        }
    }
    append_propagation_ack(path, &ack)?;
    acks.insert(key, ack);
    Ok(true)
}

fn replicate_propagation_ack_on_quorum(app: &App, ack: &PropagationAck) -> Result<()> {
    if !app.replication.is_clustered() {
        return Ok(());
    }

    let payload = ack.to_form_body();
    let mut replicated = 1usize;
    let mut failures = Vec::new();
    for peer in app.replication.remote_peers() {
        match http_post(&peer.addr, "/internal/replication/ack", payload.as_bytes()) {
            Ok(response) if response.status_code == 200 => replicated += 1,
            Ok(response) => {
                failures.push(format!("{}:status={}", peer.node_id, response.status_code))
            }
            Err(err) => failures.push(format!("{}:{err}", peer.node_id)),
        }
    }

    if replicated >= app.replication.quorum {
        return Ok(());
    }

    Err(GlobAclError::InvalidData(format!(
        "commitd ack quorum unavailable: replicated={replicated} quorum={} failures={}",
        app.replication.quorum,
        failures.join(",")
    )))
}

fn load_propagation_acks(path: &Path) -> Result<HashMap<String, PropagationAck>> {
    let mut acks = HashMap::new();
    if !path.exists() {
        return Ok(acks);
    }
    let text = String::from_utf8(fs::read(path)?)
        .map_err(|err| GlobAclError::Parse(format!("ack log is not utf8: {err}")))?;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let ack = parse_propagation_ack_log_line(line)?;
        let key = ack.key();
        if acks
            .get(&key)
            .map(|existing| existing.seq <= ack.seq)
            .unwrap_or(true)
        {
            acks.insert(key, ack);
        }
    }
    Ok(acks)
}

fn append_propagation_ack(path: &Path, ack: &PropagationAck) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", format_propagation_ack_log_line(ack))?;
    file.sync_all()?;
    Ok(())
}

fn format_propagation_ack_log_line(ack: &PropagationAck) -> String {
    format!(
        "relay_id={}\tlocation={}\tagent_id={}\tshard_id={}\tseq={}\tentries={}\tapplied_at_unix={}\trelay_received_at_unix={}",
        encode_ack_field(&ack.relay_id),
        encode_ack_field(&ack.location),
        encode_ack_field(&ack.agent_id),
        ack.shard_id,
        ack.seq,
        ack.entries,
        ack.applied_at_unix,
        ack.relay_received_at_unix,
    )
}

fn parse_propagation_ack_log_line(line: &str) -> Result<PropagationAck> {
    let mut form = HashMap::new();
    for part in line.split('\t') {
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| GlobAclError::Parse(format!("invalid ack log field {part:?}")))?;
        form.insert(key.to_owned(), decode_ack_field(value)?);
    }
    PropagationAck::from_form(&form)
}

fn format_propagation_ack_log_snapshot(app: &App) -> Result<String> {
    let mut acks = lock_propagation_acks(app)?
        .values()
        .cloned()
        .collect::<Vec<_>>();
    acks.sort_by(|left, right| {
        left.relay_id
            .cmp(&right.relay_id)
            .then(left.agent_id.cmp(&right.agent_id))
            .then(left.shard_id.cmp(&right.shard_id))
    });
    let mut body = String::new();
    for ack in acks {
        body.push_str(&format_propagation_ack_log_line(&ack));
        body.push('\n');
    }
    Ok(body)
}

fn apply_propagation_ack_log_snapshot(app: &App, body: &[u8]) -> Result<usize> {
    let text = String::from_utf8(body.to_vec())
        .map_err(|err| GlobAclError::Parse(format!("ack snapshot is not utf8: {err}")))?;
    let mut applied = 0usize;
    let mut acks = lock_propagation_acks(app)?;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let ack = parse_propagation_ack_log_line(line)?;
        if apply_propagation_ack_to_store(&app.propagation_acks_path, &mut acks, ack)? {
            applied += 1;
        }
    }
    Ok(applied)
}

fn sync_acks_from_peer(app: &App, peer_addr: &str) -> Result<usize> {
    let response = http_get(peer_addr, "/internal/replication/acks")?;
    if response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "peer returned status {} for ack snapshot",
            response.status_code
        )));
    }
    apply_propagation_ack_log_snapshot(app, &response.body)
}

fn sync_acks_from_peers(app: &App) -> Result<usize> {
    let mut applied = 0usize;
    let mut failures = Vec::new();
    for peer in app.replication.remote_peers() {
        match sync_acks_from_peer(app, &peer.addr) {
            Ok(count) => applied += count,
            Err(err) => failures.push(format!("{}:{err}", peer.node_id)),
        }
    }
    if failures.is_empty() {
        return Ok(applied);
    }
    Err(GlobAclError::InvalidData(format!(
        "ack peer sync failed: {}",
        failures.join(",")
    )))
}

fn format_propagation_status(app: &App) -> Result<String> {
    let watermarks = {
        let state = lock_state(app)?;
        state.watermarks().to_vec()
    };
    let now = now_unix();
    let mut acks = lock_propagation_acks(app)?
        .values()
        .cloned()
        .collect::<Vec<_>>();
    acks.sort_by(|left, right| {
        left.relay_id
            .cmp(&right.relay_id)
            .then(left.agent_id.cmp(&right.agent_id))
            .then(left.shard_id.cmp(&right.shard_id))
    });

    let source_max_seq = watermarks.iter().copied().max().unwrap_or(0);
    let ack_count = acks.len();
    let relay_count = acks
        .iter()
        .map(|ack| ack.relay_id.as_str())
        .collect::<HashSet<_>>()
        .len();
    let agent_count = acks
        .iter()
        .map(|ack| ack.agent_id.as_str())
        .collect::<HashSet<_>>()
        .len();
    let acked_shards = acks
        .iter()
        .map(|ack| ack.shard_id)
        .collect::<HashSet<_>>()
        .len();
    let min_ack_seq = acks.iter().map(|ack| ack.seq).min().unwrap_or(0);
    let max_ack_seq = acks.iter().map(|ack| ack.seq).max().unwrap_or(0);
    let mut max_seq_lag = 0u64;
    let mut lagging_ack_count = 0usize;
    let mut max_ack_age_secs = 0u64;
    for ack in &acks {
        let source_seq = watermarks
            .get(ack.shard_id as usize)
            .copied()
            .unwrap_or_default();
        let seq_lag = source_seq.saturating_sub(ack.seq);
        if seq_lag > 0 {
            lagging_ack_count += 1;
            max_seq_lag = max_seq_lag.max(seq_lag);
        }
        max_ack_age_secs = max_ack_age_secs.max(now.saturating_sub(ack.applied_at_unix));
    }
    let status = if source_max_seq > 0 && (ack_count == 0 || lagging_ack_count > 0) {
        "degraded"
    } else {
        "ok"
    };

    let mut body = format!(
        "status={status}\nshard_count={}\nsource_max_seq={source_max_seq}\nack_count={ack_count}\nrelay_count={relay_count}\nagent_count={agent_count}\nacked_shards={acked_shards}\nmin_ack_seq={min_ack_seq}\nmax_ack_seq={max_ack_seq}\nmax_seq_lag={max_seq_lag}\nlagging_ack_count={lagging_ack_count}\nmax_ack_age_secs={max_ack_age_secs}\n",
        watermarks.len()
    );
    for ack in acks {
        let source_seq = watermarks
            .get(ack.shard_id as usize)
            .copied()
            .unwrap_or_default();
        let seq_lag = source_seq.saturating_sub(ack.seq);
        let ack_age_secs = now.saturating_sub(ack.applied_at_unix);
        body.push_str(&format!(
            "ack relay_id={} location={} agent_id={} shard_id={} seq={} source_seq={} seq_lag={} entries={} applied_at_unix={} relay_received_at_unix={} ack_age_secs={}\n",
            ack.relay_id,
            ack.location,
            ack.agent_id,
            ack.shard_id,
            ack.seq,
            source_seq,
            seq_lag,
            ack.entries,
            ack.applied_at_unix,
            ack.relay_received_at_unix,
            ack_age_secs
        ));
    }
    Ok(body)
}

fn encode_ack_field(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            ch => out.push(ch),
        }
    }
    out
}

fn decode_ack_field(value: &str) -> Result<String> {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let escaped = chars
            .next()
            .ok_or_else(|| GlobAclError::Parse("dangling ack field escape".to_owned()))?;
        match escaped {
            '\\' => out.push('\\'),
            't' => out.push('\t'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            other => {
                return Err(GlobAclError::Parse(format!(
                    "unknown ack field escape \\{other}"
                )));
            }
        }
    }
    Ok(out)
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

fn proxy_get_to_leader(stream: &mut TcpStream, app: &App, path: &str) -> Result<()> {
    let Some(leader_addr) = current_leader_addr(app)? else {
        write_http_response(
            stream,
            503,
            "text/plain",
            b"status=unavailable\nreason=leader_not_configured\n",
        )?;
        return Ok(());
    };
    match http_get(&leader_addr, path) {
        Ok(response) => {
            write_http_response(stream, response.status_code, "text/plain", &response.body)
        }
        Err(err) => {
            let body = format!("status=unavailable\nreason=leader_proxy_failed\nerror={err}\n");
            write_http_response(stream, 503, "text/plain", body.as_bytes())
        }
    }
}

fn proxy_write_to_leader(stream: &mut TcpStream, app: &App, path: &str, body: &[u8]) -> Result<()> {
    let Some(leader_addr) = current_leader_addr(app)? else {
        write_http_response(
            stream,
            503,
            "text/plain",
            b"status=unavailable\nreason=leader_not_configured\n",
        )?;
        return Ok(());
    };
    match http_post(&leader_addr, path, body) {
        Ok(response) => {
            write_http_response(stream, response.status_code, "text/plain", &response.body)?;
        }
        Err(err) => {
            let body = format!("status=unavailable\nreason=leader_proxy_failed\nerror={err}\n");
            write_http_response(stream, 503, "text/plain", body.as_bytes())?;
        }
    }
    Ok(())
}

fn is_write_leader(app: &App) -> Result<bool> {
    if !app.replication.is_clustered() {
        return Ok(true);
    }
    Ok(lock_consensus(app)?.role == ConsensusRole::Leader)
}

fn current_leader_addr(app: &App) -> Result<Option<String>> {
    let leader_id = lock_consensus(app)?.leader_id.clone();
    Ok(leader_id.and_then(|node_id| {
        app.replication
            .peer_addr(&node_id)
            .map(|addr| addr.to_owned())
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
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

fn load_consensus_state(path: &Path, replication: &ReplicationConfig) -> Result<ConsensusState> {
    let mut current_term = 0u64;
    let mut voted_for = None;
    if path.exists() {
        let form = parse_form_lines(&fs::read(path)?)?;
        current_term = parse_form_u64(&form, "current_term", 0)?;
        voted_for = form
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
        write!(
            file,
            "current_term={}\nvoted_for={}\n",
            consensus.current_term,
            consensus.voted_for.as_deref().unwrap_or("")
        )?;
        file.sync_all()?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

fn local_log_status(app: &App) -> Result<(u64, u64)> {
    let state = lock_state(app)?;
    let last_seq = state.watermarks().iter().copied().max().unwrap_or(0);
    Ok((last_seq, state.mutations_len() as u64))
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

fn required_form<'a>(
    form: &'a std::collections::HashMap<String, String>,
    key: &str,
) -> Result<&'a str> {
    form.get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| GlobAclError::Parse(format!("missing required field {key}")))
}

fn parse_form_u64(
    form: &std::collections::HashMap<String, String>,
    key: &str,
    default: u64,
) -> Result<u64> {
    form.get(key)
        .map(|value| parse_query_u64(value, key))
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn form_bool(form: &std::collections::HashMap<String, String>, key: &str) -> bool {
    form.get(key)
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consensus_test_app(root: &Path, node_id: &str, role: ConsensusRole, term: u64) -> App {
        let shard_count = 4u16;
        App {
            state: Mutex::new(SourceOfTruth::new(shard_count, "cluster-a")),
            log_dir: root.join("logs"),
            consensus_path: root.join("consensus.state"),
            pending_dir: root.join("pending"),
            bundle_dir: root.join("bundles"),
            snapshot_dir: root.join("snapshots"),
            snapshot_object_dir: root.join("snapshots").join("objects"),
            snapshot_manifest_dir: root.join("snapshots").join("manifests"),
            snapshot_path: root.join("snapshots").join("latest.gacl"),
            snapshot_manifest_path: root
                .join("snapshots")
                .join("manifests")
                .join("latest.manifest"),
            audit_path: root.join("audit.log"),
            publisher_offsets_path: root.join("publisher_offsets.state"),
            propagation_acks_path: root.join("propagation_acks.log"),
            signature_signer: SignatureSigner::ed25519_private_key(
                DEFAULT_SIGNATURE_KEY_ID,
                DEFAULT_SIGNATURE_KEY_VERSION,
                DEFAULT_SIGNATURE_PRIVATE_KEY,
            )
            .expect("test signer"),
            latest_canary: Mutex::new(None),
            replication: ReplicationConfig {
                cluster_id: "cluster-a".to_owned(),
                node_id: node_id.to_owned(),
                initial_leader_id: None,
                peers: vec![
                    ControlPeer {
                        node_id: "node-a".to_owned(),
                        addr: "127.0.0.1:7101".to_owned(),
                    },
                    ControlPeer {
                        node_id: "node-b".to_owned(),
                        addr: "127.0.0.1:7102".to_owned(),
                    },
                    ControlPeer {
                        node_id: "node-c".to_owned(),
                        addr: "127.0.0.1:7103".to_owned(),
                    },
                ],
                quorum: 2,
                heartbeat_interval_ms: 250,
                election_timeout_ms: 1200,
                sync_interval_ms: 1000,
            },
            consensus: Mutex::new(ConsensusState {
                current_term: term,
                voted_for: None,
                role,
                leader_id: (role == ConsensusRole::Leader).then(|| node_id.to_owned()),
                last_leader_contact_ms: 0,
                election_deadline_ms: u64::MAX,
            }),
            sync_status: Mutex::new(SyncStatus {
                last_peer_sync_unix: 0,
                sync_errors: 0,
            }),
            publisher: None,
            publisher_status: Mutex::new(PublisherStatus {
                last_published: vec![0; shard_count as usize],
                last_publish_unix: 0,
                publish_errors: 0,
            }),
            propagation_acks: Mutex::new(HashMap::new()),
        }
    }

    fn test_form(fields: &[(&str, &str)]) -> HashMap<String, String> {
        fields
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn response_bool(body: &str, key: &str) -> bool {
        let form = parse_form_lines(body.as_bytes()).expect("parse response form");
        form_bool(&form, key)
    }

    fn deny_request(op_id: &str, key: &str) -> DenyRequest {
        DenyRequest {
            op_id: op_id.to_owned(),
            tenant_id: "tenant-a".to_owned(),
            namespace: "user".to_owned(),
            key: key.to_owned(),
            action: Action::Deny,
            priority: 0,
            reason_code: "test".to_owned(),
            expires_at: 0,
            created_by: "test".to_owned(),
            delivery_priority: DeliveryPriority::P1,
        }
    }

    fn remove_test_dir(path: impl AsRef<Path>) {
        match std::fs::remove_dir_all(path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => panic!("remove temp dir: {err}"),
        }
    }

    #[test]
    fn vote_request_rejects_stale_candidate_term() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-vote-stale-term-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 3);
        let response = handle_request_vote(
            &app,
            &test_form(&[
                ("term", "2"),
                ("candidate_id", "node-b"),
                ("last_seq", "0"),
                ("log_len", "0"),
            ]),
        )
        .expect("vote response");

        assert!(!response_bool(&response, "vote_granted"));
        let consensus = lock_consensus(&app).expect("consensus");
        assert_eq!(consensus.current_term, 3);
        assert_eq!(consensus.voted_for, None);
        drop(consensus);
        remove_test_dir(root);
    }

    #[test]
    fn vote_request_rejects_stale_candidate_log() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-vote-stale-log-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 1);
        {
            let mut state = lock_state(&app).expect("state");
            state.set_epoch(1);
            state
                .commit(deny_request("op-1", "user-1"))
                .expect("commit local mutation");
        }

        let response = handle_request_vote(
            &app,
            &test_form(&[
                ("term", "2"),
                ("candidate_id", "node-b"),
                ("last_seq", "0"),
                ("log_len", "0"),
            ]),
        )
        .expect("vote response");

        assert!(!response_bool(&response, "vote_granted"));
        let consensus = lock_consensus(&app).expect("consensus");
        assert_eq!(consensus.current_term, 2);
        assert_eq!(consensus.voted_for, None);
        drop(consensus);
        remove_test_dir(root);
    }

    #[test]
    fn vote_request_grants_only_one_vote_per_term() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-vote-once-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 1);

        let first = handle_request_vote(
            &app,
            &test_form(&[
                ("term", "2"),
                ("candidate_id", "node-b"),
                ("last_seq", "0"),
                ("log_len", "0"),
            ]),
        )
        .expect("first vote response");
        let second = handle_request_vote(
            &app,
            &test_form(&[
                ("term", "2"),
                ("candidate_id", "node-c"),
                ("last_seq", "0"),
                ("log_len", "0"),
            ]),
        )
        .expect("second vote response");

        assert!(response_bool(&first, "vote_granted"));
        assert!(!response_bool(&second, "vote_granted"));
        let consensus = lock_consensus(&app).expect("consensus");
        assert_eq!(consensus.current_term, 2);
        assert_eq!(consensus.voted_for.as_deref(), Some("node-b"));
        drop(consensus);
        remove_test_dir(root);
    }

    #[test]
    fn heartbeat_rejects_conflicting_leader_in_same_term() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-heartbeat-conflict-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 5);
        {
            let mut consensus = lock_consensus(&app).expect("consensus");
            consensus.voted_for = Some("node-b".to_owned());
            consensus.leader_id = Some("node-b".to_owned());
        }

        let conflicting =
            handle_heartbeat(&app, &test_form(&[("term", "5"), ("leader_id", "node-c")]))
                .expect("conflicting heartbeat");
        let accepted =
            handle_heartbeat(&app, &test_form(&[("term", "5"), ("leader_id", "node-b")]))
                .expect("accepted heartbeat");

        assert!(!response_bool(&conflicting, "success"));
        assert!(response_bool(&accepted, "success"));
        let consensus = lock_consensus(&app).expect("consensus");
        assert_eq!(consensus.current_term, 5);
        assert_eq!(consensus.leader_id.as_deref(), Some("node-b"));
        assert_eq!(consensus.voted_for.as_deref(), Some("node-b"));
        drop(consensus);
        remove_test_dir(root);
    }

    #[test]
    fn higher_term_heartbeat_steps_down_current_leader() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-heartbeat-stepdown-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Leader, 5);

        let response =
            handle_heartbeat(&app, &test_form(&[("term", "6"), ("leader_id", "node-b")]))
                .expect("heartbeat response");

        assert!(response_bool(&response, "success"));
        assert!(ensure_write_authority(&app).is_err());
        let consensus = lock_consensus(&app).expect("consensus");
        assert_eq!(consensus.current_term, 6);
        assert_eq!(consensus.role, ConsensusRole::Follower);
        assert_eq!(consensus.leader_id.as_deref(), Some("node-b"));
        assert_eq!(consensus.voted_for.as_deref(), Some("node-b"));
        drop(consensus);
        remove_test_dir(root);
    }

    #[test]
    fn publisher_offsets_round_trip() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-offsets-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let path = root.join("publisher_offsets.state");
        let offsets = vec![1, 0, 42, u64::MAX - 1];

        persist_publisher_offsets(&path, &offsets).expect("persist offsets");

        let loaded = load_publisher_offsets(&path, offsets.len() as u16).expect("load offsets");
        assert_eq!(loaded, offsets);

        let expanded = load_publisher_offsets(&path, 6).expect("load expanded offsets");
        assert_eq!(&expanded[..4], offsets.as_slice());
        assert_eq!(&expanded[4..], &[0, 0]);

        std::fs::remove_dir_all(root).expect("remove temp offset dir");
    }

    #[test]
    fn propagation_ack_log_replays_latest_ack() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-acks-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let path = root.join("propagation_acks.log");
        let first = PropagationAck {
            relay_id: "relay-a".to_owned(),
            location: "region-a".to_owned(),
            agent_id: "agent-a".to_owned(),
            shard_id: 7,
            seq: 41,
            entries: 10,
            applied_at_unix: 1000,
            relay_received_at_unix: 1001,
        };
        let second = PropagationAck {
            seq: 42,
            entries: 11,
            applied_at_unix: 1002,
            relay_received_at_unix: 1003,
            ..first.clone()
        };

        append_propagation_ack(&path, &first).expect("append first ack");
        append_propagation_ack(&path, &second).expect("append second ack");

        let loaded = load_propagation_acks(&path).expect("load propagation acks");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get(&second.key()).expect("ack").seq, 42);

        std::fs::remove_dir_all(root).expect("remove temp ack dir");
    }

    #[test]
    fn propagation_ack_snapshot_rehydrates_follower_store() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-ack-snapshot-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let follower_path = root.join("follower").join("propagation_acks.log");
        let first = PropagationAck {
            relay_id: "relay-a".to_owned(),
            location: "region-a".to_owned(),
            agent_id: "agent-a".to_owned(),
            shard_id: 7,
            seq: 41,
            entries: 10,
            applied_at_unix: 1000,
            relay_received_at_unix: 1001,
        };
        let second = PropagationAck {
            seq: 42,
            entries: 11,
            applied_at_unix: 1002,
            relay_received_at_unix: 1003,
            ..first.clone()
        };
        let snapshot = format!(
            "{}\n{}\n",
            format_propagation_ack_log_line(&first),
            format_propagation_ack_log_line(&second)
        );

        let mut follower_acks = HashMap::new();
        for line in snapshot.lines().filter(|line| !line.trim().is_empty()) {
            let ack = parse_propagation_ack_log_line(line).expect("parse ack snapshot line");
            apply_propagation_ack_to_store(&follower_path, &mut follower_acks, ack)
                .expect("apply ack snapshot line");
        }

        let loaded = load_propagation_acks(&follower_path).expect("load follower acks");
        assert_eq!(follower_acks.len(), 1);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get(&second.key()).expect("ack").seq, 42);

        std::fs::remove_dir_all(root).expect("remove temp ack snapshot dir");
    }
}
