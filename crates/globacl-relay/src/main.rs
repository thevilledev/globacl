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

fn main() -> Result<()> {
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

fn handle_connection(mut stream: TcpStream, app: Arc<App>) -> Result<()> {
    let request = read_http_request(&mut stream)?;

    match request.method.as_str() {
        "GET" if request.path == "/health" => {
            let health = app.source.health()?;
            let ack_count = lock_acks(&app)?.len();
            let ack_forward_status = lock_ack_forward_status(&app)?.clone();
            let status = if health.ok { "ok" } else { "degraded" };
            let upstream = if health.ok { "ok" } else { "bad" };
            let body = format!(
                "status={status}\nrole=relay\nrelay_id={}\nlocation={}\nsource={}\nupstream={upstream}\nupstream_addr={}\nack_count={ack_count}\nlast_ack_forward_unix={}\nack_forward_errors={}\n{}\n",
                app.relay_id,
                app.location,
                app.source.kind(),
                app.source.upstream_addr(),
                ack_forward_status.last_ack_forward_unix,
                ack_forward_status.ack_forward_errors,
                health.details.trim_end()
            );
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        "GET" if request.path == "/v1/acks" => {
            let body = format_acks(&app)?;
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        "POST" if request.path == "/v1/ack" => {
            let form = parse_form_lines(&request.body)?;
            let ack = propagation_ack_from_form(&app, &form)?;
            lock_acks(&app)?.insert(ack.key(), ack.clone());
            if let Err(err) = forward_ack(&app, &ack) {
                eprintln!("central ack forward failed: {err}");
                lock_ack_forward_status(&app)?.ack_forward_errors += 1;
            }
            write_http_response(&mut stream, 200, "text/plain", b"status=ok\n")?;
        }
        "GET" => {
            let upstream = app.source.get(&request.path)?;
            write_http_response(
                &mut stream,
                upstream.status_code,
                content_type_for(&request.path),
                &upstream.body,
            )?;
        }
        "POST" => {
            let upstream = app.source.post(&request.path, &request.body)?;
            write_http_response(
                &mut stream,
                upstream.status_code,
                "text/plain",
                &upstream.body,
            )?;
        }
        method => {
            return Err(GlobAclError::Parse(format!(
                "unsupported relay method {method}"
            )));
        }
    }

    Ok(())
}

impl RelaySource for HttpPullSource {
    fn kind(&self) -> &'static str {
        "http_pull"
    }

    fn upstream_addr(&self) -> &str {
        &self.upstream_addr
    }

    fn health(&self) -> Result<SourceHealth> {
        let upstream = http_get(&self.upstream_addr, "/health")?;
        Ok(SourceHealth {
            ok: upstream.status_code == 200,
            details: format!("http_status={}\n", upstream.status_code),
        })
    }

    fn get(&self, path: &str) -> Result<HttpResponse> {
        http_get(&self.upstream_addr, path)
    }

    fn post(&self, path: &str, body: &[u8]) -> Result<HttpResponse> {
        http_post(&self.upstream_addr, path, body)
    }
}

impl JetStreamSource {
    fn new(bootstrap_addr: String, relay_id: &str) -> Result<Self> {
        let nats_addr = env::var("GLOBACL_NATS_ADDR")
            .or_else(|_| env::var("GLOBACL_NATS_URL"))
            .unwrap_or_else(|_| "127.0.0.1:4222".to_owned());
        let stream = env::var("GLOBACL_NATS_STREAM").unwrap_or_else(|_| "GLOBACL".to_owned());
        let subject_prefix =
            env::var("GLOBACL_NATS_SUBJECT_PREFIX").unwrap_or_else(|_| "globacl".to_owned());
        let filter_subject = env::var("GLOBACL_NATS_SUBJECT_FILTER")
            .unwrap_or_else(|_| format!("{subject_prefix}.>"));
        let durable =
            env::var("GLOBACL_NATS_CONSUMER").unwrap_or_else(|_| sanitize_nats_name(relay_id));
        let batch = env::var("GLOBACL_NATS_BATCH")
            .ok()
            .map(|value| parse_env_usize(&value, "GLOBACL_NATS_BATCH"))
            .transpose()?
            .unwrap_or(128);
        if env_bool("GLOBACL_NATS_AUTOCREATE", true) {
            nats_jetstream_ensure_stream(
                &nats_addr,
                &stream,
                std::slice::from_ref(&filter_subject),
            )?;
            nats_jetstream_ensure_consumer(&nats_addr, &stream, &durable, &filter_subject)?;
        }
        let signature_signer = signature_signer_from_env()?;
        let cache = bootstrap_cache(&bootstrap_addr)?;
        Ok(Self {
            bootstrap_addr,
            nats_addr,
            stream,
            durable,
            batch,
            signature_signer,
            cache: Mutex::new(cache),
            status: Mutex::new(JetStreamStatus {
                last_pull_unix: 0,
                applied_messages: 0,
                duplicate_messages: 0,
                gap_repairs: 0,
                errors: 0,
                source_lag_max: 0,
                source_lag_sum: 0,
                lagging_shards: 0,
                consumer_num_pending: 0,
                consumer_num_ack_pending: 0,
                consumer_num_redelivered: 0,
                consumer_num_waiting: 0,
            }),
        })
    }

    fn pull_once(&self) -> Result<usize> {
        let messages = nats_jetstream_pull(
            &self.nats_addr,
            &self.stream,
            &self.durable,
            self.batch,
            1_000,
        )?;
        let count = messages.len();
        for message in messages {
            let mutation = decode_mutation(&message.payload)?;
            let applied = self.apply_or_repair(mutation)?;
            if applied {
                lock_jetstream_status(self)?.applied_messages += 1;
            } else {
                lock_jetstream_status(self)?.duplicate_messages += 1;
            }
            if let Some(reply_to) = message.reply_to {
                nats_ack(&self.nats_addr, &reply_to)?;
            }
        }
        if count > 0 {
            lock_jetstream_status(self)?.last_pull_unix = now_unix();
        }
        if let Err(err) = self.refresh_source_lag() {
            eprintln!("JetStream source lag refresh failed: {err}");
        }
        Ok(count)
    }

    fn apply_or_repair(&self, mutation: Mutation) -> Result<bool> {
        match self.apply_to_cache(mutation.clone()) {
            Ok(applied) => Ok(applied),
            Err(GlobAclError::Gap {
                shard_id,
                expected_seq,
                received_seq,
            }) => {
                self.repair_gap(shard_id, expected_seq.saturating_sub(1), received_seq)?;
                lock_jetstream_status(self)?.gap_repairs += 1;
                self.apply_to_cache(mutation)
            }
            Err(err) => Err(err),
        }
    }

    fn apply_to_cache(&self, mutation: Mutation) -> Result<bool> {
        let mut cache = lock_cache(self)?;
        cache.apply(mutation)
    }

    fn repair_gap(&self, shard_id: u16, from_seq: u64, to_seq: u64) -> Result<()> {
        let path = format!("/v1/delta_bundle?shard={shard_id}&from_seq={from_seq}&to_seq={to_seq}");
        let response = http_get(&self.bootstrap_addr, &path)?;
        if response.status_code != 200 {
            return self.rebuild_cache_from_snapshot();
        }
        let mutations = decode_mutation_stream(&response.body)?;
        let mut cache = lock_cache(self)?;
        for mutation in mutations {
            cache.apply(mutation)?;
        }
        Ok(())
    }

    fn rebuild_cache_from_snapshot(&self) -> Result<()> {
        let response = http_get(&self.bootstrap_addr, "/v1/snapshot")?;
        if response.status_code != 200 {
            return Err(GlobAclError::InvalidData(format!(
                "bootstrap returned status {} for snapshot repair",
                response.status_code
            )));
        }
        let snapshot = decode_snapshot(&response.body)?;
        let mut cache = lock_cache(self)?;
        *cache = RelayCache::new(snapshot.watermarks);
        Ok(())
    }

    fn local_mutations_for_path(&self, path: &str) -> Result<Option<Vec<Mutation>>> {
        let (route, query) = parse_query_path(path);
        let shard_id = required_query_u16(&query, "shard")?;
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
        let cache = lock_cache(self)?;
        if route == "/v1/mutations" || route == "/v1/mutations.sig" {
            return cache.mutations_for_shard(shard_id, from_seq, priority_filter);
        }
        let to_seq = query
            .get("to_seq")
            .or_else(|| query.get("to"))
            .map(|value| parse_query_u64(value, "to_seq"))
            .transpose()?
            .unwrap_or(u64::MAX);
        cache.delta_bundle(shard_id, from_seq, to_seq)
    }

    fn signed_stream_response(&self, mutations: Vec<Mutation>) -> Result<HttpResponse> {
        let payload = encode_mutation_stream(&mutations);
        Ok(HttpResponse {
            status_code: 200,
            body: self.signature_signer.sign_payload(&payload)?.into_bytes(),
        })
    }

    fn refresh_source_lag(&self) -> Result<()> {
        let response = http_get(&self.bootstrap_addr, "/v1/watermarks")?;
        if response.status_code != 200 {
            return Err(GlobAclError::InvalidData(format!(
                "bootstrap returned status {} for watermarks",
                response.status_code
            )));
        }
        let source_watermarks = parse_watermarks(&response.body)?;
        let cache = lock_cache(self)?;
        let mut source_lag_max = 0u64;
        let mut source_lag_sum = 0u64;
        let mut lagging_shards = 0usize;
        for (shard_id, source_seq) in source_watermarks.iter().copied().enumerate() {
            let local_seq = cache.watermarks.get(shard_id).copied().unwrap_or(0);
            let lag = source_seq.saturating_sub(local_seq);
            if lag > 0 {
                lagging_shards += 1;
                source_lag_sum = source_lag_sum.saturating_add(lag);
                source_lag_max = source_lag_max.max(lag);
            }
        }
        drop(cache);

        let mut status = lock_jetstream_status(self)?;
        status.source_lag_max = source_lag_max;
        status.source_lag_sum = source_lag_sum;
        status.lagging_shards = lagging_shards;
        Ok(())
    }

    fn refresh_consumer_lag(&self) -> Result<()> {
        let info = nats_jetstream_consumer_info(&self.nats_addr, &self.stream, &self.durable)?;
        let mut status = lock_jetstream_status(self)?;
        status.consumer_num_pending = info.num_pending;
        status.consumer_num_ack_pending = info.num_ack_pending;
        status.consumer_num_redelivered = info.num_redelivered;
        status.consumer_num_waiting = info.num_waiting;
        Ok(())
    }
}

impl RelaySource for JetStreamSource {
    fn kind(&self) -> &'static str {
        "jetstream"
    }

    fn upstream_addr(&self) -> &str {
        &self.bootstrap_addr
    }

    fn health(&self) -> Result<SourceHealth> {
        if let Err(err) = self.refresh_source_lag() {
            eprintln!("JetStream source lag refresh failed: {err}");
        }
        if let Err(err) = self.refresh_consumer_lag() {
            eprintln!("JetStream consumer lag refresh failed: {err}");
        }
        let status = lock_jetstream_status(self)?.clone();
        let bootstrap_status = http_get(&self.bootstrap_addr, "/health")
            .map(|response| response.status_code)
            .unwrap_or(503);
        let cache = lock_cache(self)?;
        let max_cached_seq = cache.watermarks.iter().copied().max().unwrap_or(0);
        let cached_mutations = cache.mutations.iter().map(Vec::len).sum::<usize>();
        let shard_count = cache.watermarks.len();
        drop(cache);
        Ok(SourceHealth {
            ok: status.errors == 0 || status.last_pull_unix > 0,
            details: format!(
                "nats_addr={}\nstream={}\nconsumer={}\nbootstrap_status={bootstrap_status}\nshard_count={shard_count}\nmax_cached_seq={max_cached_seq}\ncached_mutations={cached_mutations}\nsource_lag_max={}\nsource_lag_sum={}\nlagging_shards={}\nconsumer_num_pending={}\nconsumer_num_ack_pending={}\nconsumer_num_redelivered={}\nconsumer_num_waiting={}\nlast_pull_unix={}\napplied_messages={}\nduplicate_messages={}\ngap_repairs={}\njetstream_errors={}\n",
                self.nats_addr,
                self.stream,
                self.durable,
                status.source_lag_max,
                status.source_lag_sum,
                status.lagging_shards,
                status.consumer_num_pending,
                status.consumer_num_ack_pending,
                status.consumer_num_redelivered,
                status.consumer_num_waiting,
                status.last_pull_unix,
                status.applied_messages,
                status.duplicate_messages,
                status.gap_repairs,
                status.errors
            ),
        })
    }

    fn get(&self, path: &str) -> Result<HttpResponse> {
        let (route, _) = parse_query_path(path);
        match route.as_str() {
            "/v1/watermarks" => {
                let cache = lock_cache(self)?;
                Ok(HttpResponse {
                    status_code: 200,
                    body: format_watermarks(&cache.watermarks).into_bytes(),
                })
            }
            "/v1/mutations" | "/v1/delta_bundle" => {
                if let Some(mutations) = self.local_mutations_for_path(path)? {
                    Ok(HttpResponse {
                        status_code: 200,
                        body: encode_mutation_stream(&mutations),
                    })
                } else {
                    http_get(&self.bootstrap_addr, path)
                }
            }
            "/v1/mutations.sig" | "/v1/delta_bundle.sig" => {
                if let Some(mutations) = self.local_mutations_for_path(path)? {
                    self.signed_stream_response(mutations)
                } else {
                    http_get(&self.bootstrap_addr, path)
                }
            }
            _ => http_get(&self.bootstrap_addr, path),
        }
    }

    fn post(&self, path: &str, body: &[u8]) -> Result<HttpResponse> {
        http_post(&self.bootstrap_addr, path, body)
    }
}

impl RelayCache {
    fn new(base_watermarks: Vec<u64>) -> Self {
        let shard_count = base_watermarks.len().max(1);
        Self {
            base_watermarks: base_watermarks.clone(),
            watermarks: base_watermarks,
            mutations: vec![Vec::new(); shard_count],
        }
    }

    fn apply(&mut self, mutation: Mutation) -> Result<bool> {
        let shard_id = mutation.commit_id.shard_id as usize;
        if shard_id >= self.watermarks.len() {
            return Err(GlobAclError::InvalidData(format!(
                "shard {} is outside relay shard_count {}",
                mutation.commit_id.shard_id,
                self.watermarks.len()
            )));
        }
        let current_seq = self.watermarks[shard_id];
        if mutation.commit_id.seq <= current_seq {
            return Ok(false);
        }
        let expected_seq = current_seq + 1;
        if mutation.commit_id.seq != expected_seq {
            return Err(GlobAclError::Gap {
                shard_id: mutation.commit_id.shard_id,
                expected_seq,
                received_seq: mutation.commit_id.seq,
            });
        }
        self.watermarks[shard_id] = mutation.commit_id.seq;
        self.mutations[shard_id].push(mutation);
        Ok(true)
    }

    fn mutations_for_shard(
        &self,
        shard_id: u16,
        from_seq: u64,
        priority_filter: Option<DeliveryPriority>,
    ) -> Result<Option<Vec<Mutation>>> {
        let shard_index = shard_id as usize;
        if shard_index >= self.watermarks.len() {
            return Err(GlobAclError::InvalidData(format!(
                "shard {shard_id} is outside relay shard_count {}",
                self.watermarks.len()
            )));
        }
        if from_seq < self.base_watermarks[shard_index] {
            return Ok(None);
        }
        Ok(Some(
            self.mutations[shard_index]
                .iter()
                .filter(|mutation| mutation.commit_id.seq > from_seq)
                .filter(|mutation| {
                    priority_filter
                        .map(|priority| mutation.delivery_priority == priority)
                        .unwrap_or(true)
                })
                .cloned()
                .collect(),
        ))
    }

    fn delta_bundle(
        &self,
        shard_id: u16,
        from_seq: u64,
        to_seq: u64,
    ) -> Result<Option<Vec<Mutation>>> {
        let shard_index = shard_id as usize;
        if shard_index >= self.watermarks.len() {
            return Err(GlobAclError::InvalidData(format!(
                "shard {shard_id} is outside relay shard_count {}",
                self.watermarks.len()
            )));
        }
        if from_seq < self.base_watermarks[shard_index] {
            return Ok(None);
        }
        let upper = to_seq.min(self.watermarks[shard_index]);
        let mutations = self.mutations[shard_index]
            .iter()
            .filter(|mutation| mutation.commit_id.seq > from_seq && mutation.commit_id.seq <= upper)
            .cloned()
            .collect::<Vec<_>>();
        if upper > from_seq && mutations.len() != (upper - from_seq) as usize {
            return Ok(None);
        }
        Ok(Some(mutations))
    }
}

fn jetstream_pull_loop(source: Arc<JetStreamSource>) {
    loop {
        match source.pull_once() {
            Ok(0) => thread::sleep(Duration::from_millis(100)),
            Ok(_) => {}
            Err(err) => {
                eprintln!("JetStream relay pull failed: {err}");
                if let Ok(mut status) = lock_jetstream_status(&source) {
                    status.errors += 1;
                }
                thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

fn ack_forward_loop(app: Arc<App>, interval: Duration) {
    loop {
        if let Err(err) = forward_all_acks(&app) {
            eprintln!("central ack forward loop failed: {err}");
            if let Ok(mut status) = lock_ack_forward_status(&app) {
                status.ack_forward_errors += 1;
            }
        }
        thread::sleep(interval);
    }
}

fn forward_all_acks(app: &App) -> Result<()> {
    let acks = lock_acks(app)?.values().cloned().collect::<Vec<_>>();
    for ack in acks {
        forward_ack(app, &ack)?;
    }
    Ok(())
}

fn forward_ack(app: &App, ack: &PropagationAck) -> Result<()> {
    let response = http_post(
        app.source.upstream_addr(),
        "/v1/ack",
        ack.to_form_body().as_bytes(),
    )?;
    if response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "upstream returned status {} for propagation ack",
            response.status_code
        )));
    }
    let mut status = lock_ack_forward_status(app)?;
    status.last_ack_forward_unix = now_unix();
    Ok(())
}

fn propagation_ack_from_form(app: &App, form: &HashMap<String, String>) -> Result<PropagationAck> {
    if form.contains_key("relay_id") {
        return PropagationAck::from_form(form);
    }
    let ack = PopAck::from_form(form)?;
    Ok(PropagationAck::from_pop_ack(
        &app.relay_id,
        &app.location,
        ack,
        now_unix(),
    ))
}

fn bootstrap_cache(bootstrap_addr: &str) -> Result<RelayCache> {
    let snapshot_response = http_get(bootstrap_addr, "/v1/snapshot");
    if let Ok(response) = snapshot_response {
        if response.status_code == 200 {
            let snapshot = decode_snapshot(&response.body)?;
            return Ok(RelayCache::new(snapshot.watermarks));
        }
    }

    let watermarks_response = http_get(bootstrap_addr, "/v1/watermarks");
    if let Ok(response) = watermarks_response {
        if response.status_code == 200 {
            return Ok(RelayCache::new(parse_watermarks(&response.body)?));
        }
    }

    let shard_count = env::var("GLOBACL_SHARD_COUNT")
        .ok()
        .map(|value| parse_env_u16(&value, "GLOBACL_SHARD_COUNT"))
        .transpose()?
        .unwrap_or(DEFAULT_SHARD_COUNT);
    Ok(RelayCache::new(vec![0; shard_count as usize]))
}

fn content_type_for(path: &str) -> &'static str {
    let route = path.split_once('?').map_or(path, |(route, _)| route);
    if route.ends_with(".sig") || route == "/v1/snapshot_manifest" || route == "/v1/snapshots" {
        "text/plain"
    } else if matches!(
        route,
        "/v1/mutations" | "/v1/snapshot" | "/v1/snapshot_artifact" | "/v1/delta_bundle"
    ) {
        "application/octet-stream"
    } else {
        "text/plain"
    }
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

fn lock_acks(app: &App) -> Result<std::sync::MutexGuard<'_, HashMap<String, PropagationAck>>> {
    app.acks
        .lock()
        .map_err(|_| GlobAclError::InvalidData("ack lock poisoned".to_owned()))
}

fn lock_ack_forward_status(app: &App) -> Result<std::sync::MutexGuard<'_, AckForwardStatus>> {
    app.ack_forward_status
        .lock()
        .map_err(|_| GlobAclError::InvalidData("ack forward status lock poisoned".to_owned()))
}

fn lock_cache(source: &JetStreamSource) -> Result<std::sync::MutexGuard<'_, RelayCache>> {
    source
        .cache
        .lock()
        .map_err(|_| GlobAclError::InvalidData("relay cache lock poisoned".to_owned()))
}

fn lock_jetstream_status(
    source: &JetStreamSource,
) -> Result<std::sync::MutexGuard<'_, JetStreamStatus>> {
    source
        .status
        .lock()
        .map_err(|_| GlobAclError::InvalidData("JetStream status lock poisoned".to_owned()))
}

fn format_acks(app: &App) -> Result<String> {
    let now = now_unix();
    let mut acks = lock_acks(app)?.values().cloned().collect::<Vec<_>>();
    acks.sort_by(|left, right| {
        left.agent_id
            .cmp(&right.agent_id)
            .then(left.shard_id.cmp(&right.shard_id))
    });

    let mut body = format!(
        "relay_id={}\nlocation={}\nack_count={}\n",
        app.relay_id,
        app.location,
        acks.len()
    );
    for ack in acks {
        let lag_secs = now.saturating_sub(ack.applied_at_unix);
        body.push_str(&format!(
            "ack relay_id={} location={} agent_id={} shard_id={} seq={} entries={} applied_at_unix={} relay_received_at_unix={} lag_secs={}\n",
            ack.relay_id,
            ack.location,
            ack.agent_id,
            ack.shard_id,
            ack.seq,
            ack.entries,
            ack.applied_at_unix,
            ack.relay_received_at_unix,
            lag_secs
        ));
    }
    Ok(body)
}

fn required_query_u16(query: &HashMap<String, String>, key: &str) -> Result<u16> {
    query
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| GlobAclError::Parse(format!("missing query parameter {key}")))?
        .parse::<u16>()
        .map_err(|err| GlobAclError::Parse(format!("invalid {key}: {err}")))
}

fn parse_query_u64(value: &str, field: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|err| GlobAclError::Parse(format!("invalid {field}: {err}")))
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

fn parse_env_u16(value: &str, field: &str) -> Result<u16> {
    value
        .parse::<u16>()
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

fn sanitize_nats_name(value: &str) -> String {
    let mut out = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if out.is_empty() {
        out = "relay".to_owned();
    }
    out
}
