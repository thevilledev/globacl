use globacl_core::{
    decode_mutation, decode_mutation_stream, decode_snapshot, encode_mutation_stream,
    format_watermarks, http_get, http_post, nats_ack, nats_jetstream_consumer_info,
    nats_jetstream_ensure_consumer, nats_jetstream_ensure_stream, nats_jetstream_pull, now_unix,
    parse_form_lines, parse_query_path, parse_watermarks, read_http_request, write_http_response,
    DeliveryPriority, GlobAclError, HttpResponse, Mutation, PopAck, PropagationAck, Result,
    SignatureSigner, DEFAULT_SHARD_COUNT, DEFAULT_SIGNATURE_KEY_ID, DEFAULT_SIGNATURE_KEY_VERSION,
    DEFAULT_SIGNATURE_PRIVATE_KEY,
};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

struct App {
    source: Arc<dyn RelaySource>,
    relay_id: String,
    location: String,
    acks: Mutex<HashMap<String, PropagationAck>>,
    ack_forward_status: Mutex<AckForwardStatus>,
}

struct SourceHealth {
    ok: bool,
    details: String,
}

#[derive(Clone, Debug, Default)]
struct AckForwardStatus {
    last_ack_forward_unix: u64,
    ack_forward_errors: u64,
}

trait RelaySource: Send + Sync {
    fn kind(&self) -> &'static str;
    fn upstream_addr(&self) -> &str;
    fn health(&self) -> Result<SourceHealth>;
    fn get(&self, path: &str) -> Result<HttpResponse>;
    fn post(&self, path: &str, body: &[u8]) -> Result<HttpResponse>;
}

struct HttpPullSource {
    upstream_addr: String,
}

struct JetStreamSource {
    bootstrap_addr: String,
    nats_addr: String,
    stream: String,
    durable: String,
    batch: usize,
    signature_signer: SignatureSigner,
    cache: Mutex<RelayCache>,
    status: Mutex<JetStreamStatus>,
}

#[derive(Clone, Debug)]
struct RelayCache {
    base_watermarks: Vec<u64>,
    watermarks: Vec<u64>,
    mutations: Vec<Vec<Mutation>>,
}

#[derive(Clone, Debug)]
struct JetStreamStatus {
    last_pull_unix: u64,
    applied_messages: u64,
    duplicate_messages: u64,
    gap_repairs: u64,
    errors: u64,
    source_lag_max: u64,
    source_lag_sum: u64,
    lagging_shards: usize,
    consumer_num_pending: u64,
    consumer_num_ack_pending: u64,
    consumer_num_redelivered: u64,
    consumer_num_waiting: u64,
}

pub(crate) fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let upstream_addr = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:7000".to_owned());
    let bind_addr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:7001");
    let relay_id = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "relay-local".to_owned());
    let location = args.get(4).cloned().unwrap_or_else(|| "local".to_owned());
    let source = build_source(&upstream_addr, &relay_id)?;
    let app = Arc::new(App {
        source,
        relay_id,
        location,
        acks: Mutex::new(HashMap::new()),
        ack_forward_status: Mutex::new(AckForwardStatus::default()),
    });

    {
        let app = Arc::clone(&app);
        let interval_ms = env::var("GLOBACL_ACK_FORWARD_MS")
            .ok()
            .map(|value| parse_env_u64(&value, "GLOBACL_ACK_FORWARD_MS"))
            .transpose()?
            .unwrap_or(5_000);
        thread::spawn(move || ack_forward_loop(app, Duration::from_millis(interval_ms)));
    }

    let listener = TcpListener::bind(bind_addr)?;
    eprintln!(
        "globacl-relay listening on {bind_addr}; relay_id={}; location={}; source={}; upstream={}",
        app.relay_id,
        app.location,
        app.source.kind(),
        app.source.upstream_addr()
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

fn build_source(upstream_addr: &str, relay_id: &str) -> Result<Arc<dyn RelaySource>> {
    let mode = env::var("GLOBACL_RELAY_SOURCE").unwrap_or_else(|_| "http".to_owned());
    match mode.trim().to_ascii_lowercase().as_str() {
        "" | "http" | "pull" | "proxy" | "pull_proxy" => Ok(Arc::new(HttpPullSource {
            upstream_addr: upstream_addr.to_owned(),
        })),
        "jetstream" | "nats" | "nats_jetstream" => {
            let source = Arc::new(JetStreamSource::new(upstream_addr.to_owned(), relay_id)?);
            let loop_source = Arc::clone(&source);
            thread::spawn(move || jetstream_pull_loop(loop_source));
            Ok(source)
        }
        other => Err(GlobAclError::Parse(format!(
            "unknown GLOBACL_RELAY_SOURCE mode {other:?}"
        ))),
    }
}

