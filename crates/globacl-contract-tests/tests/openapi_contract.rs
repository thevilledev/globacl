use globacl_core::{
    decode_mutation_stream, decode_snapshot, decode_snapshot_manifest, parse_form_lines,
    GlobAclError,
};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TEST_KEY_ID: &str = "contract-ed25519";
const TEST_KEY_VERSION: &str = "7";
const TEST_PRIVATE_KEY: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const TEST_PUBLIC_KEY: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

#[test]
fn documented_openapi_surface_is_present() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let spec_path = manifest_dir.join("../../docs/openapi.yaml");
    let spec = fs::read_to_string(spec_path).expect("read docs/openapi.yaml");

    for path in [
        "/health",
        "/v1/deny",
        "/v1/mutation",
        "/v1/rule",
        "/v1/canary",
        "/v1/canary/latest",
        "/v1/lookup",
        "/v1/check",
        "/v1/watermarks",
        "/v1/compaction_watermarks",
        "/v1/mutations",
        "/v1/mutations.sig",
        "/v1/delta_bundle",
        "/v1/delta_bundle.sig",
        "/v1/ack",
        "/v1/acks",
        "/v1/propagation/status",
        "/v1/snapshot",
        "/v1/snapshot.sig",
        "/v1/snapshot_manifest",
        "/v1/snapshot_manifest.sig",
        "/v1/snapshot_artifact",
        "/v1/snapshot_artifact.sig",
        "/v1/snapshots",
        "/v1/rollback",
        "/v1/audit",
    ] {
        assert!(
            spec.contains(&format!("  {path}:")),
            "OpenAPI spec is missing path {path}"
        );
    }

    for operation_id in [
        "getHealth",
        "createDenyMutation",
        "createPointMutation",
        "createRuleMutation",
        "createCanary",
        "getLatestCanary",
        "lookupPointDecision",
        "checkAclDecision",
        "getWatermarks",
        "getCompactionWatermarks",
        "getMutations",
        "getMutationsSignature",
        "getDeltaBundle",
        "getDeltaBundleSignature",
        "recordAck",
        "getRelayAcks",
        "getPropagationStatus",
        "getSnapshot",
        "uploadSnapshot",
        "getSnapshotSignature",
        "getSnapshotManifest",
        "getSnapshotManifestSignature",
        "getSnapshotArtifact",
        "getSnapshotArtifactSignature",
        "listSnapshots",
        "rollbackToSnapshot",
        "getAuditLog",
    ] {
        assert!(
            spec.contains(&format!("operationId: {operation_id}")),
            "OpenAPI spec is missing operationId {operation_id}"
        );
    }
}

#[test]
fn backend_conforms_to_documented_openapi_contract() {
    let cluster = TestCluster::start();

    let health = raw_get(&cluster.control_addr, "/health");
    assert_status(&health, 200);
    assert_content_type(&health, "text/plain");
    assert_fields(
        &form(&health),
        &["status", "role", "commitd", "commit_addr"],
    );

    let deny = raw_post(
        &cluster.control_addr,
        "/v1/deny",
        "text/plain",
        b"op_id=contract-deny-1\n\
          tenant_id=tenant-a\n\
          namespace=user\n\
          key=user-123\n\
          action=deny\n\
          delivery_priority=p0\n\
          priority=100\n\
          reason_code=contract\n\
          created_by=contract-test\n",
    );
    assert_status(&deny, 200);
    assert_content_type(&deny, "text/plain");
    let deny_form = form(&deny);
    assert_fields(
        &deny_form,
        &[
            "duplicate",
            "shard_id",
            "seq",
            "epoch",
            "action",
            "key_hash",
            "delivery_priority",
            "committed_at_unix",
            "entries_changed",
        ],
    );
    assert_eq!(deny_form.get("delivery_priority").unwrap(), "p0");
    let deny_shard = deny_form.get("shard_id").unwrap().parse::<u16>().unwrap();
    let deny_seq = deny_form.get("seq").unwrap().parse::<u64>().unwrap();

    let mutation = raw_post(
        &cluster.control_addr,
        "/v1/mutation",
        "text/plain",
        b"op_id=contract-mutation-1\n\
          tenant_id=tenant-a\n\
          namespace=user\n\
          key=user-alias\n\
          action=delete\n\
          reason_code=contract_alias\n\
          created_by=contract-test\n",
    );
    assert_status(&mutation, 200);
    assert_content_type(&mutation, "text/plain");
    assert_fields(
        &form(&mutation),
        &["duplicate", "shard_id", "seq", "action"],
    );

    let rule = raw_post(
        &cluster.control_addr,
        "/v1/rule",
        "text/plain",
        b"op_id=contract-rule-1\n\
          tenant_id=tenant-a\n\
          kind=ipv4_cidr\n\
          pattern=10.0.0.0/8\n\
          action=deny\n\
          reason_code=contract_rule\n\
          created_by=contract-test\n",
    );
    assert_status(&rule, 200);
    assert_content_type(&rule, "text/plain");
    assert_fields(
        &form(&rule),
        &[
            "duplicate",
            "shard_id",
            "seq",
            "rule_kind",
            "pattern",
            "rule_hash",
        ],
    );

    let canary = raw_post(&cluster.control_addr, "/v1/canary", "text/plain", b"");
    assert_status(&canary, 200);
    assert_content_type(&canary, "text/plain");
    assert_fields(
        &form(&canary),
        &[
            "status",
            "op_id",
            "tenant_id",
            "namespace",
            "key",
            "shard_id",
            "seq",
            "delivery_priority",
        ],
    );

    let latest_canary = raw_get(&cluster.control_addr, "/v1/canary/latest");
    assert_status(&latest_canary, 200);
    assert_content_type(&latest_canary, "text/plain");
    assert_fields(&form(&latest_canary), &["status", "op_id", "key", "seq"]);

    let lookup = wait_for_form(
        &cluster.agent_addr,
        "/v1/lookup?tenant_id=tenant-a&namespace=user&key=user-123",
        "decision",
        "deny",
    );
    assert_fields(
        &lookup,
        &["decision", "reason_code", "priority", "shard_id", "seq"],
    );

    let check = wait_for_form(
        &cluster.agent_addr,
        "/v1/check?tenant_id=tenant-a&namespace=ip&value=10.1.2.3",
        "decision",
        "deny",
    );
    assert_fields(
        &check,
        &["decision", "reason_code", "priority", "shard_id", "seq"],
    );

    let watermarks = raw_get(&cluster.control_addr, "/v1/watermarks");
    assert_status(&watermarks, 200);
    assert_content_type(&watermarks, "text/plain");
    assert_fields(&form(&watermarks), &["shard_count", "shard_0000"]);

    let compaction_watermarks = raw_get(&cluster.control_addr, "/v1/compaction_watermarks");
    assert_status(&compaction_watermarks, 200);
    assert_content_type(&compaction_watermarks, "text/plain");
    assert_fields(
        &form(&compaction_watermarks),
        &["shard_count", "shard_0000"],
    );

    let mutations_path = format!("/v1/mutations?shard={deny_shard}&from_seq=0");
    let mutations = raw_get(&cluster.control_addr, &mutations_path);
    assert_status(&mutations, 200);
    assert_content_type(&mutations, "application/octet-stream");
    let decoded_mutations = decode_mutation_stream(&mutations.body).unwrap();
    assert!(
        decoded_mutations
            .iter()
            .any(|mutation| mutation.commit_id.seq == deny_seq),
        "mutation stream did not include committed deny seq {deny_seq}"
    );

    let mutation_sig = raw_get(
        &cluster.control_addr,
        &format!("/v1/mutations.sig?shard={deny_shard}&from_seq=0"),
    );
    assert_status(&mutation_sig, 200);
    assert_content_type(&mutation_sig, "text/plain");
    assert_signature_fields(&form(&mutation_sig));

    let delta_path = format!("/v1/delta_bundle?shard={deny_shard}&from_seq=0&to_seq={deny_seq}");
    let delta = raw_get(&cluster.control_addr, &delta_path);
    assert_status(&delta, 200);
    assert_content_type(&delta, "application/octet-stream");
    assert!(!decode_mutation_stream(&delta.body).unwrap().is_empty());

    let delta_sig = raw_get(
        &cluster.control_addr,
        &format!("/v1/delta_bundle.sig?shard={deny_shard}&from_seq=0&to_seq={deny_seq}"),
    );
    assert_status(&delta_sig, 200);
    assert_content_type(&delta_sig, "text/plain");
    assert_signature_fields(&form(&delta_sig));

    let snapshot = raw_get(&cluster.control_addr, "/v1/snapshot");
    assert_status(&snapshot, 200);
    assert_content_type(&snapshot, "application/octet-stream");
    decode_snapshot(&snapshot.body).unwrap();

    let upload = raw_post(
        &cluster.control_addr,
        "/v1/snapshot",
        "application/octet-stream",
        &snapshot.body,
    );
    assert_status(&upload, 200);
    assert_content_type(&upload, "text/plain");
    assert_eq!(form(&upload).get("status").unwrap(), "ok");

    let snapshot_sig = raw_get(&cluster.control_addr, "/v1/snapshot.sig");
    assert_status(&snapshot_sig, 200);
    assert_content_type(&snapshot_sig, "text/plain");
    assert_signature_fields(&form(&snapshot_sig));

    let manifest = raw_get(&cluster.control_addr, "/v1/snapshot_manifest");
    assert_status(&manifest, 200);
    assert_content_type(&manifest, "text/plain");
    let manifest_body = form(&manifest);
    assert_fields(
        &manifest_body,
        &[
            "manifest_version",
            "artifact_object",
            "artifact_sha256",
            "shard_count",
            "max_seq",
        ],
    );
    let decoded_manifest = decode_snapshot_manifest(&manifest.body).unwrap();

    let manifest_sig = raw_get(&cluster.control_addr, "/v1/snapshot_manifest.sig");
    assert_status(&manifest_sig, 200);
    assert_content_type(&manifest_sig, "text/plain");
    assert_signature_fields(&form(&manifest_sig));

    let artifact = raw_get(
        &cluster.control_addr,
        &format!(
            "/v1/snapshot_artifact?object={}",
            decoded_manifest.artifact_object
        ),
    );
    assert_status(&artifact, 200);
    assert_content_type(&artifact, "application/octet-stream");
    decode_snapshot(&artifact.body).unwrap();

    let artifact_sig = raw_get(
        &cluster.control_addr,
        &format!(
            "/v1/snapshot_artifact.sig?object={}",
            decoded_manifest.artifact_object
        ),
    );
    assert_status(&artifact_sig, 200);
    assert_content_type(&artifact_sig, "text/plain");
    assert_signature_fields(&form(&artifact_sig));

    let snapshots = raw_get(&cluster.control_addr, "/v1/snapshots");
    assert_status(&snapshots, 200);
    assert_content_type(&snapshots, "text/plain");
    let snapshots_form = form(&snapshots);
    assert_fields(&snapshots_form, &["snapshot_count", "manifest_count"]);
    let rollback_target = first_value_for_key(&snapshots.body, "snapshot")
        .expect("expected at least one archived snapshot");

    let rollback = raw_post(
        &cluster.control_addr,
        "/v1/rollback",
        "text/plain",
        format!("snapshot={rollback_target}\n").as_bytes(),
    );
    assert_status(&rollback, 200);
    assert_content_type(&rollback, "text/plain");
    assert_fields(&form(&rollback), &["status", "snapshot", "mutations"]);

    let central_ack = raw_post(
        &cluster.control_addr,
        "/v1/ack",
        "text/plain",
        format!(
            "relay_id=relay-contract\n\
             location=local\n\
             agent_id=agent-contract\n\
             shard_id={deny_shard}\n\
             seq={deny_seq}\n\
             entries=1\n\
             applied_at_unix=1760000000\n\
             relay_received_at_unix=1760000001\n"
        )
        .as_bytes(),
    );
    assert_status(&central_ack, 200);
    assert_content_type(&central_ack, "text/plain");
    assert_eq!(form(&central_ack).get("status").unwrap(), "ok");

    let propagation = raw_get(&cluster.control_addr, "/v1/propagation/status");
    assert_status(&propagation, 200);
    assert_content_type(&propagation, "text/plain");
    assert_fields(
        &form(&propagation),
        &[
            "status",
            "shard_count",
            "source_max_seq",
            "ack_count",
            "relay_count",
            "agent_count",
            "max_seq_lag",
        ],
    );

    let relay_ack = raw_post(
        &cluster.relay_addr,
        "/v1/ack",
        "text/plain",
        format!(
            "agent_id=agent-contract\n\
             shard_id={deny_shard}\n\
             seq={deny_seq}\n\
             entries=1\n\
             applied_at_unix=1760000002\n"
        )
        .as_bytes(),
    );
    assert_status(&relay_ack, 200);
    assert_content_type(&relay_ack, "text/plain");
    assert_eq!(form(&relay_ack).get("status").unwrap(), "ok");

    let relay_acks = raw_get(&cluster.relay_addr, "/v1/acks");
    assert_status(&relay_acks, 200);
    assert_content_type(&relay_acks, "text/plain");
    let relay_acks_body = String::from_utf8_lossy(&relay_acks.body);
    assert!(relay_acks_body.contains("ack_count="));
    assert!(relay_acks_body.contains("agent_id=agent-contract"));

    let audit = raw_get(&cluster.control_addr, "/v1/audit");
    assert_status(&audit, 200);
    assert_content_type(&audit, "text/plain");
    let audit_body = String::from_utf8_lossy(&audit.body);
    assert!(audit_body.contains("event=deny"));
    assert!(audit_body.contains("contract-deny-1"));
}

struct TestCluster {
    _root: TempRoot,
    _commitd: ChildGuard,
    _control: ChildGuard,
    _relay: ChildGuard,
    _agent: ChildGuard,
    control_addr: String,
    relay_addr: String,
    agent_addr: String,
}

impl TestCluster {
    fn start() -> Self {
        let root = TempRoot::new("globacl-contract");
        let commit_addr = free_addr();
        let control_addr = free_addr();
        let relay_addr = free_addr();
        let agent_addr = free_addr();
        let snapshot_path = root.path.join("agent").join("latest.gacl");
        fs::create_dir_all(snapshot_path.parent().unwrap()).unwrap();

        let commitd = spawn(
            "commitd",
            env!("CARGO_BIN_EXE_globacl-contract-commitd"),
            &[
                root.path.join("commitd").to_string_lossy().as_ref(),
                &commit_addr,
                "16",
                "0",
            ],
            &[("GLOBACL_COMMITD_COMPACTION_MIN_LOG_ENTRIES", "0")],
        );
        wait_for_health("commitd", &commit_addr);

        let control = spawn(
            "control",
            env!("CARGO_BIN_EXE_globacl-contract-control"),
            &[&commit_addr, &control_addr],
            &[],
        );
        wait_for_health("control", &control_addr);

        let relay = spawn(
            "relay",
            env!("CARGO_BIN_EXE_globacl-contract-relay"),
            &[&control_addr, &relay_addr, "relay-contract", "local"],
            &[],
        );
        wait_for_health("relay", &relay_addr);

        let agent = spawn(
            "agent",
            env!("CARGO_BIN_EXE_globacl-contract-agent"),
            &[
                &relay_addr,
                &agent_addr,
                snapshot_path.to_string_lossy().as_ref(),
                "50",
                "agent-contract",
                "60",
            ],
            &[],
        );
        wait_for_health("agent", &agent_addr);

        Self {
            _root: root,
            _commitd: commitd,
            _control: control,
            _relay: relay,
            _agent: agent,
            control_addr,
            relay_addr,
            agent_addr,
        }
    }
}

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new(prefix: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Debug)]
struct RawResponse {
    status_code: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn spawn(name: &str, binary: &str, args: &[&str], envs: &[(&str, &str)]) -> ChildGuard {
    let mut command = Command::new(binary);
    command
        .args(args)
        .env("GLOBACL_SIGNATURE_KEY_ID", TEST_KEY_ID)
        .env("GLOBACL_SIGNATURE_KEY_VERSION", TEST_KEY_VERSION)
        .env("GLOBACL_SIGNATURE_PRIVATE_KEY", TEST_PRIVATE_KEY)
        .env("GLOBACL_SIGNATURE_PUBLIC_KEY", TEST_PUBLIC_KEY)
        .env("GLOBACL_SIGNATURE_MIN_KEY_VERSION", TEST_KEY_VERSION)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in envs {
        command.env(key, value);
    }
    let child = command
        .spawn()
        .unwrap_or_else(|err| panic!("spawn {name} from {binary}: {err}"));
    ChildGuard { child }
}

fn free_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().unwrap().to_string()
}

fn wait_for_health(name: &str, addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_status = None;
    while Instant::now() < deadline {
        if let Ok(response) = try_raw_get(addr, "/health") {
            last_status = Some(response.status_code);
            if response.status_code == 200 {
                return;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("{name} at {addr} did not become healthy; last_status={last_status:?}");
}

fn wait_for_form(
    addr: &str,
    path: &str,
    expected_key: &str,
    expected_value: &str,
) -> HashMap<String, String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_body = String::new();
    while Instant::now() < deadline {
        let response = raw_get(addr, path);
        assert_status(&response, 200);
        assert_content_type(&response, "text/plain");
        let parsed = form(&response);
        if parsed.get(expected_key).map(String::as_str) == Some(expected_value) {
            return parsed;
        }
        last_body = String::from_utf8_lossy(&response.body).into_owned();
        thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "timed out waiting for {path} to return {expected_key}={expected_value}; last={last_body}"
    );
}

fn raw_get(addr: &str, path: &str) -> RawResponse {
    try_raw_get(addr, path).unwrap_or_else(|err| panic!("GET {addr}{path}: {err}"))
}

fn try_raw_get(addr: &str, path: &str) -> Result<RawResponse, GlobAclError> {
    raw_request(addr, "GET", path, None, &[])
}

fn raw_post(addr: &str, path: &str, content_type: &str, body: &[u8]) -> RawResponse {
    raw_request(addr, "POST", path, Some(content_type), body)
        .unwrap_or_else(|err| panic!("POST {addr}{path}: {err}"))
}

fn raw_request(
    addr: &str,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<RawResponse, GlobAclError> {
    let mut stream = TcpStream::connect(addr)?;
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(content_type) = content_type {
        request.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes())?;
    stream.write_all(body)?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes)?;
    parse_raw_http_response(&bytes)
}

fn parse_raw_http_response(bytes: &[u8]) -> Result<RawResponse, GlobAclError> {
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| GlobAclError::Parse("HTTP response missing header terminator".to_owned()))?;
    let headers_text = std::str::from_utf8(&bytes[..header_end])
        .map_err(|err| GlobAclError::Parse(format!("HTTP headers are not utf8: {err}")))?;
    let mut lines = headers_text.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| GlobAclError::Parse("HTTP response missing status line".to_owned()))?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| GlobAclError::Parse(format!("invalid status line {status_line:?}")))?
        .parse::<u16>()
        .map_err(|err| GlobAclError::Parse(format!("invalid status code: {err}")))?;

    let mut headers = HashMap::new();
    for line in lines {
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| GlobAclError::Parse(format!("invalid HTTP header {line:?}")))?;
        headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_owned());
    }

    Ok(RawResponse {
        status_code,
        headers,
        body: bytes[header_end + 4..].to_vec(),
    })
}

fn form(response: &RawResponse) -> HashMap<String, String> {
    parse_form_lines(&response.body)
        .unwrap_or_else(|err| panic!("response body is not key=value form: {err:?}"))
}

fn assert_status(response: &RawResponse, expected: u16) {
    assert_eq!(
        response.status_code,
        expected,
        "unexpected status; body={}",
        String::from_utf8_lossy(&response.body)
    );
}

fn assert_content_type(response: &RawResponse, expected: &str) {
    let actual = response
        .headers
        .get("content-type")
        .unwrap_or_else(|| panic!("response missing Content-Type header: {response:?}"));
    assert!(
        actual.starts_with(expected),
        "expected Content-Type {expected}, got {actual}"
    );
}

fn assert_fields(form: &HashMap<String, String>, fields: &[&str]) {
    for field in fields {
        assert!(
            form.contains_key(*field),
            "missing field {field} in {form:?}"
        );
    }
}

fn assert_signature_fields(form: &HashMap<String, String>) {
    assert_fields(form, &["algorithm", "key_id", "key_version", "signature"]);
    assert_eq!(form.get("algorithm").unwrap(), "ed25519");
    assert_eq!(form.get("key_id").unwrap(), TEST_KEY_ID);
    assert_eq!(form.get("key_version").unwrap(), TEST_KEY_VERSION);
    assert!(!form.get("signature").unwrap().is_empty());
}

fn first_value_for_key(body: &[u8], key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    std::str::from_utf8(body).ok()?.lines().find_map(|line| {
        line.trim()
            .strip_prefix(&prefix)
            .map(|value| value.trim().to_owned())
    })
}
