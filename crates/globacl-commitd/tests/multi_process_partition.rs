use globacl_core::{http_get, http_post, parse_form_lines, parse_watermarks};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const NODE_A: &str = "node-a";
const NODE_B: &str = "node-b";
const NODE_C: &str = "node-c";

#[test]
fn isolated_leader_cannot_commit_while_majority_side_elects_and_commits() {
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

    let form = parse_form_lines(&committed.body).expect("commit response should be form lines");
    let shard_id = parse_form_usize(&form, "shard_id");
    let seq = parse_form_u64(&form, "seq");
    assert_eq!(seq, 1);

    wait_for_watermark_at_least(cluster.addr(NODE_B), shard_id, seq);
    wait_for_watermark_at_least(cluster.addr(NODE_C), shard_id, seq);
}

struct CommitdCluster {
    temp_dir: PathBuf,
    nodes: HashMap<&'static str, Node>,
    links: DirectedLinks,
}

impl CommitdCluster {
    fn start() -> Self {
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
    addr: String,
    child: Child,
}

impl Node {
    fn start(
        node_id: &'static str,
        addr: &str,
        temp_dir: &Path,
        cluster_id: &str,
        peers: &str,
    ) -> Self {
        let data_dir = temp_dir.join(node_id);
        fs::create_dir_all(&data_dir).expect("node data dir should be created");

        let child = Command::new(env!("CARGO_BIN_EXE_globacl-commitd"))
            .arg(&data_dir)
            .arg(addr)
            .arg("4")
            .arg("0")
            .env("GLOBACL_COMMITD_NODE_ID", node_id)
            .env("GLOBACL_COMMITD_CLUSTER_ID", cluster_id)
            .env("GLOBACL_COMMITD_INITIAL_LEADER_ID", NODE_A)
            .env("GLOBACL_COMMITD_PEERS", peers)
            .env("GLOBACL_COMMITD_QUORUM", "2")
            .env("GLOBACL_COMMITD_HEARTBEAT_MS", "50")
            .env("GLOBACL_COMMITD_ELECTION_MS", "250")
            .env("GLOBACL_COMMITD_SYNC_MS", "50")
            .env("GLOBACL_COMMITD_METRICS_ADDR", "off")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("commitd process should start");

        Self {
            addr: addr.to_owned(),
            child,
        }
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
        wait_until(Duration::from_secs(10), || {
            health(&addr)
                .map(|form| (form.get("status").map(String::as_str) == Some("ok")).then_some(()))?
        });
    }
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
    parse_form_lines(&response.body).ok()
}

fn watermarks(addr: &str) -> Option<Vec<u64>> {
    let response = http_get(addr, "/v1/watermarks").ok()?;
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
    format!(
        "op_id={op_id}\ntenant_id=tenant-a\nnamespace=user\nkey={key}\naction=deny\ncreated_by=partition-test\nreason_code=partition\n"
    )
}

fn parse_form_usize(form: &HashMap<String, String>, field: &str) -> usize {
    form.get(field)
        .unwrap_or_else(|| panic!("missing field {field}"))
        .parse()
        .unwrap_or_else(|err| panic!("invalid {field}: {err}"))
}

fn parse_form_u64(form: &HashMap<String, String>, field: &str) -> u64 {
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
