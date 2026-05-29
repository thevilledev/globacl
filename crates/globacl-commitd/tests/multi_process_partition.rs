use globacl_core::{
    http_get, http_get_with_headers, http_post, parse_json_body, parse_json_fields,
    parse_watermarks,
};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const NODE_A: &str = "node-a";
const NODE_B: &str = "node-b";
const NODE_C: &str = "node-c";
const PEER_TOKEN: &str = "partition-test-peer-token";

static MULTI_PROCESS_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[test]
fn isolated_leader_cannot_commit_while_majority_side_elects_and_commits() {
    let _guard = multi_process_test_guard();
    let mut cluster = CommitdCluster::start();

    wait_for_healthy_nodes(&cluster);
    wait_for_role(cluster.addr(NODE_A), "leader");

    cluster.isolate(NODE_A);

    let isolated_response = http_post(
        cluster.addr(NODE_A),
        "/v1/deny",
        deny_body("partition-old-leader", "user-isolated").as_bytes(),
    );
    assert!(
        isolated_response
            .as_ref()
            .map(|response| response.status_code != 200)
            .unwrap_or(true),
        "isolated leader unexpectedly committed: {isolated_response:?}"
    );
    assert_all_watermarks_zero(cluster.addr(NODE_A));

    let majority_addrs = [cluster.addr(NODE_B), cluster.addr(NODE_C)];
    let majority_leader = wait_for_leader_among(&majority_addrs);
    let committed = http_post(
        majority_leader,
        "/v1/deny",
        deny_body("partition-majority", "user-majority").as_bytes(),
    )
    .expect("majority leader commit request should receive a response");
    assert_eq!(committed.status_code, 200, "{}", body_text(&committed.body));

    let form = parse_json_fields(&committed.body).expect("commit response should be JSON");
    let shard_id = parse_json_usize(&form, "shard_id");
    let seq = parse_json_u64(&form, "seq");
    assert_eq!(seq, 1);

    wait_for_watermark_at_least(cluster.addr(NODE_B), shard_id, seq);
    wait_for_watermark_at_least(cluster.addr(NODE_C), shard_id, seq);
}

#[test]
fn restarted_follower_recovers_missed_ack_from_leader_snapshot() {
    let _guard = multi_process_test_guard();
    let mut cluster = CommitdCluster::start();

    wait_for_healthy_nodes(&cluster);
    wait_for_role(cluster.addr(NODE_A), "leader");
    assert_empty_ack_snapshot(cluster.addr(NODE_A));

    cluster.stop_node(NODE_B);

    let ack = http_post(
        cluster.addr(NODE_A),
        "/v1/ack",
        ack_body("relay-regression", "agent-regression", 2, 9).as_bytes(),
    )
    .expect("leader ack request should receive a response");
    assert_eq!(ack.status_code, 200, "{}", body_text(&ack.body));

    wait_for_ack_count_at_least(cluster.addr(NODE_A), 1);
    wait_for_ack_count_at_least(cluster.addr(NODE_C), 1);

    cluster.restart_node(NODE_B);
    wait_for_healthy_node(cluster.addr(NODE_B));
    wait_for_ack_count_at_least(cluster.addr(NODE_B), 1);
}

#[test]
fn killed_leader_fails_over_and_restarted_node_catches_up() {
    let _guard = multi_process_test_guard();
    let mut cluster = CommitdCluster::start();

    wait_for_healthy_nodes(&cluster);
    wait_for_role(cluster.addr(NODE_A), "leader");

    let (first_shard, first_seq) = commit_deny(
        cluster.addr(NODE_A),
        "chaos-before-kill",
        "user-before-kill",
    );
    wait_for_watermark_at_least(cluster.addr(NODE_B), first_shard, first_seq);
    wait_for_watermark_at_least(cluster.addr(NODE_C), first_shard, first_seq);

    cluster.stop_node(NODE_A);

    let majority_addrs = [cluster.addr(NODE_B), cluster.addr(NODE_C)];
    let majority_leader = wait_for_leader_among(&majority_addrs);
    let (second_shard, second_seq) =
        commit_deny(majority_leader, "chaos-after-kill", "user-after-kill");
    wait_for_watermark_at_least(cluster.addr(NODE_B), second_shard, second_seq);
    wait_for_watermark_at_least(cluster.addr(NODE_C), second_shard, second_seq);

    cluster.restart_node(NODE_A);
    wait_for_healthy_node(cluster.addr(NODE_A));
    wait_for_watermark_at_least(cluster.addr(NODE_A), second_shard, second_seq);
}

#[test]
fn healed_partitioned_old_leader_steps_down_and_catches_up() {
    let _guard = multi_process_test_guard();
    let mut cluster = CommitdCluster::start();

    wait_for_healthy_nodes(&cluster);
    wait_for_role(cluster.addr(NODE_A), "leader");

    cluster.isolate(NODE_A);

    let majority_addrs = [cluster.addr(NODE_B), cluster.addr(NODE_C)];
    let majority_leader = wait_for_leader_among(&majority_addrs);
    let (shard_id, seq) = commit_deny(
        majority_leader,
        "chaos-majority-partition",
        "user-majority-partition",
    );
    wait_for_watermark_at_least(cluster.addr(NODE_B), shard_id, seq);
    wait_for_watermark_at_least(cluster.addr(NODE_C), shard_id, seq);

    cluster.heal(NODE_A);

    wait_for_role(cluster.addr(NODE_A), "follower");
    wait_for_watermark_at_least(cluster.addr(NODE_A), shard_id, seq);
}

#[test]
fn lagging_follower_repairs_from_compacted_leader_snapshot() {
    let _guard = multi_process_test_guard();
    let mut cluster = CommitdCluster::start_with(ClusterOptions {
        compaction_min_log_entries: Some(1),
    });

    wait_for_healthy_nodes(&cluster);
    wait_for_role(cluster.addr(NODE_A), "leader");

    cluster.stop_node(NODE_B);

    let (shard_id, seq) = commit_deny(
        cluster.addr(NODE_A),
        "chaos-compacted-follower",
        "user-compacted-follower",
    );
    wait_for_watermark_at_least(cluster.addr(NODE_C), shard_id, seq);
    wait_for_compaction_watermark_at_least(cluster.addr(NODE_A), shard_id, seq);

    cluster.restart_node(NODE_B);
    wait_for_healthy_node(cluster.addr(NODE_B));
    wait_for_watermark_at_least(cluster.addr(NODE_B), shard_id, seq);
}

#[test]
#[ignore = "soak test; run explicitly with GLOBACL_SOAK_SECONDS/GLOBACL_SOAK_WRITERS"]
fn compacting_cluster_survives_sustained_write_load() {
    let _guard = multi_process_test_guard();
    let mut cluster = CommitdCluster::start_with(ClusterOptions {
        compaction_min_log_entries: Some(16),
    });
    let duration = Duration::from_secs(env_usize("GLOBACL_SOAK_SECONDS", 30) as u64);
    let writers = env_usize("GLOBACL_SOAK_WRITERS", 4).max(1);
    let min_commits = env_usize("GLOBACL_SOAK_MIN_COMMITS", 100);

    wait_for_healthy_nodes(&cluster);
    wait_for_role(cluster.addr(NODE_A), "leader");

    let leader_addr = cluster.addr(NODE_A).to_owned();
    let started = Instant::now();
    let stop_at = started + duration;
    let committed = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for writer_id in 0..writers {
        let leader_addr = leader_addr.clone();
        let committed = Arc::clone(&committed);
        let errors = Arc::clone(&errors);
        handles.push(thread::spawn(move || {
            let mut index = 0usize;
            while Instant::now() < stop_at {
                let op_id = format!("soak-{writer_id}-{index}");
                let key = format!("user-soak-{writer_id}-{index}");
                match http_post(&leader_addr, "/v1/deny", deny_body(&op_id, &key).as_bytes()) {
                    Ok(response) if response.status_code == 200 => {
                        committed.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(response) => {
                        eprintln!(
                            "soak writer {writer_id} got HTTP status {}: {}",
                            response.status_code,
                            body_text(&response.body)
                        );
                        errors.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(err) => {
                        eprintln!("soak writer {writer_id} request failed: {err}");
                        errors.fetch_add(1, Ordering::SeqCst);
                    }
                }
                index += 1;
            }
        }));
    }

    thread::sleep(duration / 3);
    cluster.stop_node(NODE_B);
    thread::sleep(Duration::from_millis(750));
    cluster.restart_node(NODE_B);
    wait_for_healthy_node(cluster.addr(NODE_B));

    for handle in handles {
        handle.join().expect("soak writer should not panic");
    }

    assert_eq!(errors.load(Ordering::SeqCst), 0, "soak write errors");
    let committed = committed.load(Ordering::SeqCst);
    assert!(
        committed >= min_commits,
        "soak committed {committed} writes, expected at least {min_commits}"
    );

    wait_for_healthy_nodes(&cluster);
    let all_addrs = [
        cluster.addr(NODE_A),
        cluster.addr(NODE_B),
        cluster.addr(NODE_C),
    ];
    let current_leader = wait_for_leader_among(&all_addrs);
    let leader_watermarks = watermarks(current_leader).expect("leader watermarks");
    eprintln!(
        "soak write phase complete: committed={committed} writers={writers} duration_secs={}",
        duration.as_secs()
    );
    for node_id in [NODE_A, NODE_B, NODE_C] {
        wait_for_watermarks_at_least(
            cluster.addr(node_id),
            &leader_watermarks,
            Duration::from_secs(60),
            node_id,
        );
    }
    let compaction_total = compaction_watermarks(current_leader)
        .expect("leader compaction watermarks")
        .iter()
        .sum::<u64>();
    assert!(
        compaction_total > 0,
        "compaction should advance during sustained write load"
    );

    eprintln!(
        "soak complete: committed={committed} writers={writers} duration_secs={}",
        duration.as_secs()
    );
}

fn multi_process_test_guard() -> MutexGuard<'static, ()> {
    MULTI_PROCESS_TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("multi-process test lock should not be poisoned")
}

#[derive(Clone, Copy, Debug, Default)]
struct ClusterOptions {
    compaction_min_log_entries: Option<usize>,
}

struct CommitdCluster {
    temp_dir: PathBuf,
    nodes: HashMap<&'static str, Node>,
    links: DirectedLinks,
    cluster_id: String,
    options: ClusterOptions,
}

impl CommitdCluster {
    fn start() -> Self {
        Self::start_with(ClusterOptions::default())
    }

    fn start_with(options: ClusterOptions) -> Self {
        let temp_dir = temp_root();
        fs::create_dir_all(&temp_dir).expect("temp root should be created");

        let addr_a = free_addr();
        let addr_b = free_addr();
        let addr_c = free_addr();

        let links = DirectedLinks::start(&addr_a, &addr_b, &addr_c);

        let cluster_id = format!("partition-test-{}", unique_suffix());
        let mut nodes = HashMap::new();
        nodes.insert(
            NODE_A,
            Node::start(
                NODE_A,
                &addr_a,
                &temp_dir,
                &cluster_id,
                &options,
                &format!(
                    "{NODE_A}={addr_a},{NODE_B}={},{}={}",
                    links.ab.addr, NODE_C, links.ac.addr
                ),
            ),
        );
        nodes.insert(
            NODE_B,
            Node::start(
                NODE_B,
                &addr_b,
                &temp_dir,
                &cluster_id,
                &options,
                &format!(
                    "{NODE_A}={},{}={addr_b},{}={}",
                    links.ba.addr, NODE_B, NODE_C, links.bc.addr
                ),
            ),
        );
        nodes.insert(
            NODE_C,
            Node::start(
                NODE_C,
                &addr_c,
                &temp_dir,
                &cluster_id,
                &options,
                &format!(
                    "{NODE_A}={},{}={},{}={addr_c}",
                    links.ca.addr, NODE_B, links.cb.addr, NODE_C
                ),
            ),
        );

        Self {
            temp_dir,
            nodes,
            links,
            cluster_id,
            options,
        }
    }

    fn addr(&self, node_id: &str) -> &str {
        &self
            .nodes
            .get(node_id)
            .unwrap_or_else(|| panic!("unknown node {node_id}"))
            .addr
    }

    fn isolate(&mut self, node_id: &str) {
        match node_id {
            NODE_A => {
                self.links.ab.disable();
                self.links.ac.disable();
                self.links.ba.disable();
                self.links.ca.disable();
            }
            NODE_B => {
                self.links.ba.disable();
                self.links.bc.disable();
                self.links.ab.disable();
                self.links.cb.disable();
            }
            NODE_C => {
                self.links.ca.disable();
                self.links.cb.disable();
                self.links.ac.disable();
                self.links.bc.disable();
            }
            other => panic!("unknown node {other}"),
        }
    }

    fn heal(&mut self, node_id: &str) {
        match node_id {
            NODE_A => {
                self.links.ab.enable();
                self.links.ac.enable();
                self.links.ba.enable();
                self.links.ca.enable();
            }
            NODE_B => {
                self.links.ba.enable();
                self.links.bc.enable();
                self.links.ab.enable();
                self.links.cb.enable();
            }
            NODE_C => {
                self.links.ca.enable();
                self.links.cb.enable();
                self.links.ac.enable();
                self.links.bc.enable();
            }
            other => panic!("unknown node {other}"),
        }
    }

    fn stop_node(&mut self, node_id: &'static str) {
        self.nodes
            .get_mut(node_id)
            .unwrap_or_else(|| panic!("unknown node {node_id}"))
            .stop();
    }

    fn restart_node(&mut self, node_id: &'static str) {
        let peers = self.peers_for(node_id);
        self.nodes
            .get_mut(node_id)
            .unwrap_or_else(|| panic!("unknown node {node_id}"))
            .restart(&self.temp_dir, &self.cluster_id, &self.options, &peers);
    }

    fn peers_for(&self, node_id: &str) -> String {
        match node_id {
            NODE_A => format!(
                "{NODE_A}={},{}={},{}={}",
                self.addr(NODE_A),
                NODE_B,
                self.links.ab.addr,
                NODE_C,
                self.links.ac.addr
            ),
            NODE_B => format!(
                "{NODE_A}={},{}={},{}={}",
                self.links.ba.addr,
                NODE_B,
                self.addr(NODE_B),
                NODE_C,
                self.links.bc.addr
            ),
            NODE_C => format!(
                "{NODE_A}={},{}={},{}={}",
                self.links.ca.addr,
                NODE_B,
                self.links.cb.addr,
                NODE_C,
                self.addr(NODE_C)
            ),
            other => panic!("unknown node {other}"),
        }
    }
}

impl Drop for CommitdCluster {
    fn drop(&mut self) {
        for node in self.nodes.values_mut() {
            node.stop();
        }
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

struct Node {
    node_id: &'static str,
    addr: String,
    child: Child,
}

impl Node {
    fn start(
        node_id: &'static str,
        addr: &str,
        temp_dir: &Path,
        cluster_id: &str,
        options: &ClusterOptions,
        peers: &str,
    ) -> Self {
        let child = Self::spawn(node_id, addr, temp_dir, cluster_id, options, peers);

        Self {
            node_id,
            addr: addr.to_owned(),
            child,
        }
    }

    fn spawn(
        node_id: &'static str,
        addr: &str,
        temp_dir: &Path,
        cluster_id: &str,
        options: &ClusterOptions,
        peers: &str,
    ) -> Child {
        let data_dir = temp_dir.join(node_id);
        fs::create_dir_all(&data_dir).expect("node data dir should be created");

        let mut command = Command::new(env!("CARGO_BIN_EXE_globacl-commitd"));
        command
            .arg(&data_dir)
            .arg(addr)
            .arg("4")
            .arg("0")
            .env("GLOBACL_COMMITD_NODE_ID", node_id)
            .env("GLOBACL_COMMITD_CLUSTER_ID", cluster_id)
            .env("GLOBACL_COMMITD_INITIAL_LEADER_ID", NODE_A)
            .env("GLOBACL_COMMITD_PEERS", peers)
            .env("GLOBACL_COMMITD_QUORUM", "2")
            .env("GLOBACL_COMMITD_PEER_TOKEN", PEER_TOKEN)
            .env("GLOBACL_COMMITD_HEARTBEAT_MS", "50")
            .env("GLOBACL_COMMITD_ELECTION_MS", "250")
            .env("GLOBACL_COMMITD_SYNC_MS", "50")
            .env("GLOBACL_COMMITD_METRICS_ADDR", "off")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(min_log_entries) = options.compaction_min_log_entries {
            command.env(
                "GLOBACL_COMMITD_COMPACTION_MIN_LOG_ENTRIES",
                min_log_entries.to_string(),
            );
        }
        command.spawn().expect("commitd process should start")
    }

    fn restart(
        &mut self,
        temp_dir: &Path,
        cluster_id: &str,
        options: &ClusterOptions,
        peers: &str,
    ) {
        self.stop();
        self.child = Self::spawn(
            self.node_id,
            &self.addr,
            temp_dir,
            cluster_id,
            options,
            peers,
        );
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
    }
}

struct DirectedLinks {
    ab: TcpProxy,
    ac: TcpProxy,
    ba: TcpProxy,
    bc: TcpProxy,
    ca: TcpProxy,
    cb: TcpProxy,
}

impl DirectedLinks {
    fn start(addr_a: &str, addr_b: &str, addr_c: &str) -> Self {
        Self {
            ab: TcpProxy::start(addr_b),
            ac: TcpProxy::start(addr_c),
            ba: TcpProxy::start(addr_a),
            bc: TcpProxy::start(addr_c),
            ca: TcpProxy::start(addr_a),
            cb: TcpProxy::start(addr_b),
        }
    }
}

struct TcpProxy {
    addr: String,
    enabled: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl TcpProxy {
    fn start(target_addr: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("proxy listener should bind");
        listener
            .set_nonblocking(true)
            .expect("proxy listener should become nonblocking");
        let addr = listener
            .local_addr()
            .expect("proxy listener should have local addr")
            .to_string();
        let enabled = Arc::new(AtomicBool::new(true));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_enabled = Arc::clone(&enabled);
        let thread_stop = Arc::clone(&stop);
        let target_addr = target_addr.to_owned();
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let target_addr = target_addr.clone();
                        let enabled = Arc::clone(&thread_enabled);
                        thread::spawn(move || proxy_connection(stream, target_addr, enabled));
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => thread::sleep(Duration::from_millis(10)),
                }
            }
        });

        Self {
            addr,
            enabled,
            stop,
            thread: Some(thread),
        }
    }

    fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }

    fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }
}

impl Drop for TcpProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn proxy_connection(mut client: TcpStream, target_addr: String, enabled: Arc<AtomicBool>) {
    if !enabled.load(Ordering::SeqCst) {
        return;
    }

    let Ok(mut server) = TcpStream::connect(target_addr) else {
        return;
    };
    let Ok(mut client_reader) = client.try_clone() else {
        return;
    };
    let Ok(mut server_writer) = server.try_clone() else {
        return;
    };

    let upstream = thread::spawn(move || {
        let _ = io::copy(&mut client_reader, &mut server_writer);
        let _ = server_writer.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut server, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let _ = upstream.join();
}

fn wait_for_healthy_nodes(cluster: &CommitdCluster) {
    for node_id in [NODE_A, NODE_B, NODE_C] {
        let addr = cluster.addr(node_id).to_owned();
        wait_for_healthy_node(&addr);
    }
}

fn wait_for_healthy_node(addr: &str) {
    wait_until(Duration::from_secs(10), || {
        health(addr)
            .map(|form| (form.get("status").map(String::as_str) == Some("ok")).then_some(()))?
    });
}

fn wait_for_role(addr: &str, role: &str) {
    wait_until(Duration::from_secs(10), || {
        let form = health(addr)?;
        (form.get("role").map(String::as_str) == Some(role)).then_some(())
    });
}

fn wait_for_leader_among<'a>(addrs: &'a [&'a str]) -> &'a str {
    wait_until(Duration::from_secs(10), || {
        addrs.iter().copied().find(|addr| {
            health(addr)
                .and_then(|form| form.get("role").cloned())
                .as_deref()
                == Some("leader")
        })
    })
}

fn wait_for_watermark_at_least(addr: &str, shard_id: usize, seq: u64) {
    wait_until(Duration::from_secs(10), || {
        let watermarks = watermarks(addr)?;
        (watermarks.get(shard_id).copied().unwrap_or(0) >= seq).then_some(())
    });
}

fn wait_for_watermarks_at_least(addr: &str, expected: &[u64], timeout: Duration, label: &str) {
    let started = Instant::now();
    let mut last_observed = Vec::new();
    loop {
        if let Some(watermarks) = watermarks(addr) {
            let caught_up = expected.iter().enumerate().all(|(shard_id, expected_seq)| {
                watermarks.get(shard_id).copied().unwrap_or(0) >= *expected_seq
            });
            if caught_up {
                return;
            }
            last_observed = watermarks;
        }
        assert!(
            started.elapsed() < timeout,
            "{label} did not catch up within {timeout:?}; expected={expected:?}; observed={last_observed:?}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_compaction_watermark_at_least(addr: &str, shard_id: usize, seq: u64) {
    wait_until(Duration::from_secs(10), || {
        let watermarks = compaction_watermarks(addr)?;
        (watermarks.get(shard_id).copied().unwrap_or(0) >= seq).then_some(())
    });
}

fn wait_for_ack_count_at_least(addr: &str, expected: u64) {
    wait_until(Duration::from_secs(10), || {
        let form = health(addr)?;
        let count = parse_json_u64(&form, "central_ack_count");
        (count >= expected).then_some(())
    });
}

fn assert_empty_ack_snapshot(addr: &str) {
    let response = http_get_with_headers(
        addr,
        "/internal/replication/acks",
        &[("X-Globacl-Peer-Token", PEER_TOKEN)],
    )
    .expect("internal ack snapshot should respond");
    assert_eq!(response.status_code, 200, "{}", body_text(&response.body));
    let body = parse_json_body(&response.body).expect("ack snapshot should be JSON");
    assert_eq!(
        body.get("acks")
            .and_then(|value| value.as_array())
            .map(Vec::len),
        Some(0),
        "empty ack snapshot should be a JSON acks array: {body:?}"
    );
}

fn assert_all_watermarks_zero(addr: &str) {
    let watermarks = watermarks(addr).expect("isolated node watermarks should be readable");
    assert!(
        watermarks.iter().all(|seq| *seq == 0),
        "isolated node applied a mutation unexpectedly: {watermarks:?}"
    );
}

fn health(addr: &str) -> Option<HashMap<String, String>> {
    let response = http_get(addr, "/health").ok()?;
    (response.status_code == 200).then_some(())?;
    parse_json_fields(&response.body).ok()
}

fn watermarks(addr: &str) -> Option<Vec<u64>> {
    let response = http_get(addr, "/v1/watermarks").ok()?;
    (response.status_code == 200).then_some(())?;
    parse_watermarks(&response.body).ok()
}

fn compaction_watermarks(addr: &str) -> Option<Vec<u64>> {
    let response = http_get(addr, "/v1/compaction_watermarks").ok()?;
    (response.status_code == 200).then_some(())?;
    parse_watermarks(&response.body).ok()
}

fn wait_until<T>(timeout: Duration, mut check: impl FnMut() -> Option<T>) -> T {
    let started = Instant::now();
    loop {
        if let Some(value) = check() {
            return value;
        }
        assert!(
            started.elapsed() < timeout,
            "condition was not met within {timeout:?}"
        );
        thread::sleep(Duration::from_millis(25));
    }
}

fn deny_body(op_id: &str, key: &str) -> String {
    json_body(&[
        ("op_id", op_id),
        ("tenant_id", "tenant-a"),
        ("namespace", "user"),
        ("key", key),
        ("action", "deny"),
        ("created_by", "partition-test"),
        ("reason_code", "partition"),
    ])
}

fn commit_deny(addr: &str, op_id: &str, key: &str) -> (usize, u64) {
    let response = http_post(addr, "/v1/deny", deny_body(op_id, key).as_bytes())
        .expect("commit request should receive a response");
    assert_eq!(response.status_code, 200, "{}", body_text(&response.body));
    let form = parse_json_fields(&response.body).expect("commit response should be JSON");
    (
        parse_json_usize(&form, "shard_id"),
        parse_json_u64(&form, "seq"),
    )
}

fn ack_body(relay_id: &str, agent_id: &str, shard_id: u16, seq: u64) -> String {
    format!(
        r#"{{"relay_id":"{relay_id}","location":"local","agent_id":"{agent_id}","shard_id":{shard_id},"seq":{seq},"entries":1,"applied_at_unix":1760000000,"relay_received_at_unix":1760000001}}"#
    )
}

fn json_body(fields: &[(&str, &str)]) -> String {
    let mut body = String::from("{");
    for (index, (key, value)) in fields.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        body.push('"');
        body.push_str(key);
        body.push_str("\":\"");
        body.push_str(value);
        body.push('"');
    }
    body.push('}');
    body
}

fn parse_json_usize(form: &HashMap<String, String>, field: &str) -> usize {
    form.get(field)
        .unwrap_or_else(|| panic!("missing field {field}"))
        .parse()
        .unwrap_or_else(|err| panic!("invalid {field}: {err}"))
}

fn parse_json_u64(form: &HashMap<String, String>, field: &str) -> u64 {
    form.get(field)
        .unwrap_or_else(|| panic!("missing field {field}"))
        .parse()
        .unwrap_or_else(|err| panic!("invalid {field}: {err}"))
}

fn body_text(body: &[u8]) -> String {
    String::from_utf8_lossy(body).into_owned()
}

fn temp_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "globacl-commitd-partition-{}-{}",
        std::process::id(),
        unique_suffix()
    ))
}

fn free_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("free port listener should bind");
    listener
        .local_addr()
        .expect("free port listener should have local addr")
        .to_string()
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}
