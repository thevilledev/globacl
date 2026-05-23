use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const DEFAULT_SHARD_COUNT: u16 = 4096;
pub const SNAPSHOT_MAGIC: &[u8; 4] = b"GACL";
pub const MUTATION_MAGIC: &[u8; 4] = b"GMUT";
pub const MUTATION_STREAM_MAGIC: &[u8; 4] = b"GLOG";
pub const FORMAT_VERSION: u16 = 1;

pub type Result<T> = std::result::Result<T, GlobAclError>;

#[derive(Debug)]
pub enum GlobAclError {
    Io(io::Error),
    Parse(String),
    InvalidData(String),
    Gap {
        shard_id: u16,
        expected_seq: u64,
        received_seq: u64,
    },
}

impl fmt::Display for GlobAclError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GlobAclError::Io(err) => write!(f, "io error: {err}"),
            GlobAclError::Parse(message) => write!(f, "parse error: {message}"),
            GlobAclError::InvalidData(message) => write!(f, "invalid data: {message}"),
            GlobAclError::Gap {
                shard_id,
                expected_seq,
                received_seq,
            } => write!(
                f,
                "mutation gap on shard {shard_id}: expected seq {expected_seq}, got {received_seq}"
            ),
        }
    }
}

impl std::error::Error for GlobAclError {}

impl From<io::Error> for GlobAclError {
    fn from(value: io::Error) -> Self {
        GlobAclError::Io(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Deny,
    AllowOverride,
    Delete,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Deny => "deny",
            Action::AllowOverride => "allow_override",
            Action::Delete => "delete",
        }
    }

    pub fn from_name(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "deny" => Ok(Action::Deny),
            "allow" | "allow_override" => Ok(Action::AllowOverride),
            "delete" | "remove" | "unblock" => Ok(Action::Delete),
            other => Err(GlobAclError::Parse(format!("unknown action {other:?}"))),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            Action::Deny => 1,
            Action::AllowOverride => 2,
            Action::Delete => 3,
        }
    }

    fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Action::Deny),
            2 => Ok(Action::AllowOverride),
            3 => Ok(Action::Delete),
            _ => Err(GlobAclError::InvalidData(format!(
                "unknown action tag {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AclKey {
    pub tenant_id: String,
    pub namespace: String,
    pub key_hash: u64,
}

impl AclKey {
    pub fn from_raw(tenant_id: &str, namespace: &str, raw_key: &str) -> Self {
        Self {
            tenant_id: tenant_id.to_owned(),
            namespace: namespace.to_owned(),
            key_hash: stable_key_hash(tenant_id, namespace, raw_key),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenyRequest {
    pub op_id: String,
    pub tenant_id: String,
    pub namespace: String,
    pub key: String,
    pub action: Action,
    pub priority: u32,
    pub reason_code: String,
    pub expires_at: u64,
    pub created_by: String,
}

impl DenyRequest {
    pub fn from_form(form: &HashMap<String, String>) -> Result<Self> {
        let op_id = required(form, "op_id")?;
        let tenant_id = required(form, "tenant_id")?;
        let namespace = required(form, "namespace")?;
        let key = required(form, "key")?;
        let action = Action::from_name(form.get("action").map(String::as_str).unwrap_or("deny"))?;
        let priority = parse_u32(form.get("priority").map(String::as_str), 0, "priority")?;
        let reason_code = form
            .get("reason_code")
            .cloned()
            .unwrap_or_else(|| "unspecified".to_owned());
        let expires_at = parse_u64(form.get("expires_at").map(String::as_str), 0, "expires_at")?;
        let created_by = form
            .get("created_by")
            .cloned()
            .unwrap_or_else(|| "unknown".to_owned());

        Ok(Self {
            op_id,
            tenant_id,
            namespace,
            key,
            action,
            priority,
            reason_code,
            expires_at,
            created_by,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenyEntry {
    pub tenant_id: String,
    pub namespace: String,
    pub key_hash: u64,
    pub action: Action,
    pub priority: u32,
    pub reason_code: String,
    pub expires_at: u64,
    pub created_by: String,
    pub commit_seq: u64,
    pub shard_id: u16,
}

impl DenyEntry {
    pub fn acl_key(&self) -> AclKey {
        AclKey {
            tenant_id: self.tenant_id.clone(),
            namespace: self.namespace.clone(),
            key_hash: self.key_hash,
        }
    }

    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.expires_at != 0 && self.expires_at <= now_unix
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitId {
    pub shard_id: u16,
    pub seq: u64,
    pub epoch: u64,
    pub source_region: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mutation {
    pub op_id: String,
    pub commit_id: CommitId,
    pub entry: DenyEntry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitOutcome {
    pub mutation: Mutation,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision {
    Allow,
    Deny {
        reason_code: String,
        priority: u32,
        commit_id: CommitId,
    },
}

impl Decision {
    pub fn is_denied(&self) -> bool {
        matches!(self, Decision::Deny { .. })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyStatus {
    Applied,
    DuplicateOrOld,
}

#[derive(Clone, Debug)]
pub struct SourceOfTruth {
    shard_count: u16,
    entries: HashMap<AclKey, DenyEntry>,
    watermarks: Vec<u64>,
    mutations: Vec<Mutation>,
    op_index: HashMap<String, Mutation>,
    epoch: u64,
    source_region: String,
}

impl SourceOfTruth {
    pub fn new(shard_count: u16, source_region: impl Into<String>) -> Self {
        let shard_count = shard_count.max(1);
        Self {
            shard_count,
            entries: HashMap::new(),
            watermarks: vec![0; shard_count as usize],
            mutations: Vec::new(),
            op_index: HashMap::new(),
            epoch: 1,
            source_region: source_region.into(),
        }
    }

    pub fn from_mutations(
        shard_count: u16,
        source_region: impl Into<String>,
        mut mutations: Vec<Mutation>,
    ) -> Result<Self> {
        mutations.sort_by_key(|mutation| {
            (
                mutation.commit_id.shard_id,
                mutation.commit_id.seq,
                mutation.op_id.clone(),
            )
        });

        let mut state = Self::new(shard_count, source_region);
        for mutation in mutations {
            state.apply_loaded_mutation(mutation)?;
        }
        Ok(state)
    }

    pub fn commit(&mut self, request: DenyRequest) -> Result<CommitOutcome> {
        if request.op_id.trim().is_empty() {
            return Err(GlobAclError::Parse("op_id must not be empty".to_owned()));
        }

        if let Some(existing) = self.op_index.get(&request.op_id) {
            return Ok(CommitOutcome {
                mutation: existing.clone(),
                duplicate: true,
            });
        }

        let key = AclKey::from_raw(&request.tenant_id, &request.namespace, &request.key);
        let shard_id = shard_for_hash(key.key_hash, self.shard_count);
        let seq = self.watermarks[shard_id as usize] + 1;
        let commit_id = CommitId {
            shard_id,
            seq,
            epoch: self.epoch,
            source_region: self.source_region.clone(),
        };
        let entry = DenyEntry {
            tenant_id: request.tenant_id,
            namespace: request.namespace,
            key_hash: key.key_hash,
            action: request.action,
            priority: request.priority,
            reason_code: request.reason_code,
            expires_at: request.expires_at,
            created_by: request.created_by,
            commit_seq: seq,
            shard_id,
        };
        let mutation = Mutation {
            op_id: request.op_id,
            commit_id,
            entry,
        };

        self.apply_committed_mutation(&mutation)?;
        self.op_index
            .insert(mutation.op_id.clone(), mutation.clone());
        self.mutations.push(mutation.clone());

        Ok(CommitOutcome {
            mutation,
            duplicate: false,
        })
    }

    pub fn lookup(
        &self,
        tenant_id: &str,
        namespace: &str,
        raw_key: &str,
        now_unix: u64,
    ) -> Decision {
        let key = AclKey::from_raw(tenant_id, namespace, raw_key);
        decision_for_entry(self.entries.get(&key), now_unix)
    }

    pub fn mutations_for_shard(&self, shard_id: u16, from_seq: u64) -> Vec<Mutation> {
        self.mutations
            .iter()
            .filter(|mutation| {
                mutation.commit_id.shard_id == shard_id && mutation.commit_id.seq > from_seq
            })
            .cloned()
            .collect()
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            shard_count: self.shard_count,
            watermarks: self.watermarks.clone(),
            entries: self.entries.values().cloned().collect(),
        }
    }

    pub fn shard_count(&self) -> u16 {
        self.shard_count
    }

    pub fn watermarks(&self) -> &[u64] {
        &self.watermarks
    }

    pub fn entries_len(&self) -> usize {
        self.entries.len()
    }

    pub fn mutations_len(&self) -> usize {
        self.mutations.len()
    }

    fn apply_loaded_mutation(&mut self, mutation: Mutation) -> Result<()> {
        self.apply_committed_mutation(&mutation)?;
        self.op_index
            .insert(mutation.op_id.clone(), mutation.clone());
        self.mutations.push(mutation);
        Ok(())
    }

    fn apply_committed_mutation(&mut self, mutation: &Mutation) -> Result<()> {
        let shard_id = mutation.commit_id.shard_id;
        if shard_id >= self.shard_count {
            return Err(GlobAclError::InvalidData(format!(
                "shard {shard_id} is outside shard_count {}",
                self.shard_count
            )));
        }

        let expected_seq = self.watermarks[shard_id as usize] + 1;
        if mutation.commit_id.seq != expected_seq {
            return Err(GlobAclError::Gap {
                shard_id,
                expected_seq,
                received_seq: mutation.commit_id.seq,
            });
        }

        let key = mutation.entry.acl_key();
        match mutation.entry.action {
            Action::Delete => {
                self.entries.remove(&key);
            }
            Action::Deny | Action::AllowOverride => {
                self.entries.insert(key, mutation.entry.clone());
            }
        }
        self.watermarks[shard_id as usize] = mutation.commit_id.seq;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub shard_count: u16,
    pub watermarks: Vec<u64>,
    pub entries: Vec<DenyEntry>,
}

#[derive(Clone, Debug)]
pub struct ActiveState {
    shard_count: u16,
    entries: HashMap<AclKey, DenyEntry>,
    watermarks: Vec<u64>,
}

impl ActiveState {
    pub fn new(shard_count: u16) -> Self {
        let shard_count = shard_count.max(1);
        Self {
            shard_count,
            entries: HashMap::new(),
            watermarks: vec![0; shard_count as usize],
        }
    }

    pub fn from_snapshot(snapshot: Snapshot) -> Result<Self> {
        if snapshot.watermarks.len() != snapshot.shard_count as usize {
            return Err(GlobAclError::InvalidData(format!(
                "snapshot has {} watermarks for {} shards",
                snapshot.watermarks.len(),
                snapshot.shard_count
            )));
        }

        let mut entries = HashMap::with_capacity(snapshot.entries.len());
        for entry in snapshot.entries {
            if entry.shard_id >= snapshot.shard_count {
                return Err(GlobAclError::InvalidData(format!(
                    "entry shard {} is outside shard_count {}",
                    entry.shard_id, snapshot.shard_count
                )));
            }
            entries.insert(entry.acl_key(), entry);
        }

        Ok(Self {
            shard_count: snapshot.shard_count,
            entries,
            watermarks: snapshot.watermarks,
        })
    }

    pub fn apply_mutation(&mut self, mutation: &Mutation) -> Result<ApplyStatus> {
        let shard_id = mutation.commit_id.shard_id;
        if shard_id >= self.shard_count {
            return Err(GlobAclError::InvalidData(format!(
                "shard {shard_id} is outside shard_count {}",
                self.shard_count
            )));
        }

        let current_seq = self.watermarks[shard_id as usize];
        if mutation.commit_id.seq <= current_seq {
            return Ok(ApplyStatus::DuplicateOrOld);
        }

        let expected_seq = current_seq + 1;
        if mutation.commit_id.seq != expected_seq {
            return Err(GlobAclError::Gap {
                shard_id,
                expected_seq,
                received_seq: mutation.commit_id.seq,
            });
        }

        let key = mutation.entry.acl_key();
        match mutation.entry.action {
            Action::Delete => {
                self.entries.remove(&key);
            }
            Action::Deny | Action::AllowOverride => {
                self.entries.insert(key, mutation.entry.clone());
            }
        }
        self.watermarks[shard_id as usize] = mutation.commit_id.seq;
        Ok(ApplyStatus::Applied)
    }

    pub fn lookup(
        &self,
        tenant_id: &str,
        namespace: &str,
        raw_key: &str,
        now_unix: u64,
    ) -> Decision {
        let key = AclKey::from_raw(tenant_id, namespace, raw_key);
        decision_for_entry(self.entries.get(&key), now_unix)
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            shard_count: self.shard_count,
            watermarks: self.watermarks.clone(),
            entries: self.entries.values().cloned().collect(),
        }
    }

    pub fn shard_count(&self) -> u16 {
        self.shard_count
    }

    pub fn entries_len(&self) -> usize {
        self.entries.len()
    }

    pub fn watermarks(&self) -> &[u64] {
        &self.watermarks
    }
}

pub fn stable_key_hash(tenant_id: &str, namespace: &str, raw_key: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for chunk in [
        tenant_id.as_bytes(),
        namespace.as_bytes(),
        raw_key.as_bytes(),
    ] {
        for byte in chunk {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub fn shard_for_hash(key_hash: u64, shard_count: u16) -> u16 {
    (key_hash % u64::from(shard_count.max(1))) as u16
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

pub fn encode_snapshot(snapshot: &Snapshot) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(SNAPSHOT_MAGIC);
    write_u16(&mut out, FORMAT_VERSION);
    write_u16(&mut out, snapshot.shard_count);
    write_u32(&mut out, snapshot.watermarks.len() as u32);
    write_u64(&mut out, snapshot.entries.len() as u64);
    for watermark in &snapshot.watermarks {
        write_u64(&mut out, *watermark);
    }
    for entry in &snapshot.entries {
        encode_entry(&mut out, entry);
    }
    out
}

pub fn decode_snapshot(bytes: &[u8]) -> Result<Snapshot> {
    let mut cursor = Cursor::new(bytes);
    expect_magic(&mut cursor, SNAPSHOT_MAGIC)?;
    let version = read_u16(&mut cursor)?;
    if version != FORMAT_VERSION {
        return Err(GlobAclError::InvalidData(format!(
            "unsupported snapshot version {version}"
        )));
    }

    let shard_count = read_u16(&mut cursor)?;
    let watermark_count = read_u32(&mut cursor)? as usize;
    let entry_count = read_u64(&mut cursor)? as usize;

    if watermark_count != shard_count as usize {
        return Err(GlobAclError::InvalidData(format!(
            "snapshot has {watermark_count} watermarks for {shard_count} shards"
        )));
    }

    let mut watermarks = Vec::with_capacity(watermark_count);
    for _ in 0..watermark_count {
        watermarks.push(read_u64(&mut cursor)?);
    }

    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        entries.push(decode_entry(&mut cursor)?);
    }

    Ok(Snapshot {
        shard_count,
        watermarks,
        entries,
    })
}

pub fn write_snapshot_file(path: impl AsRef<Path>, snapshot: &Snapshot) -> Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.as_ref().with_extension("tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(&encode_snapshot(snapshot))?;
        file.sync_all()?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

pub fn read_snapshot_file(path: impl AsRef<Path>) -> Result<Snapshot> {
    let bytes = fs::read(path)?;
    decode_snapshot(&bytes)
}

pub fn encode_mutation(mutation: &Mutation) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MUTATION_MAGIC);
    write_u16(&mut out, FORMAT_VERSION);
    write_string(&mut out, &mutation.op_id);
    write_u16(&mut out, mutation.commit_id.shard_id);
    write_u64(&mut out, mutation.commit_id.seq);
    write_u64(&mut out, mutation.commit_id.epoch);
    write_string(&mut out, &mutation.commit_id.source_region);
    encode_entry(&mut out, &mutation.entry);
    out
}

pub fn decode_mutation(bytes: &[u8]) -> Result<Mutation> {
    let mut cursor = Cursor::new(bytes);
    decode_mutation_from_cursor(&mut cursor)
}

pub fn encode_mutation_stream(mutations: &[Mutation]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MUTATION_STREAM_MAGIC);
    write_u16(&mut out, FORMAT_VERSION);
    write_u64(&mut out, mutations.len() as u64);
    for mutation in mutations {
        let encoded = encode_mutation(mutation);
        write_u32(&mut out, encoded.len() as u32);
        out.extend_from_slice(&encoded);
    }
    out
}

pub fn decode_mutation_stream(bytes: &[u8]) -> Result<Vec<Mutation>> {
    let mut cursor = Cursor::new(bytes);
    expect_magic(&mut cursor, MUTATION_STREAM_MAGIC)?;
    let version = read_u16(&mut cursor)?;
    if version != FORMAT_VERSION {
        return Err(GlobAclError::InvalidData(format!(
            "unsupported mutation stream version {version}"
        )));
    }
    let count = read_u64(&mut cursor)? as usize;
    let mut mutations = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_u32(&mut cursor)? as usize;
        let bytes = read_exact_vec(&mut cursor, len)?;
        mutations.push(decode_mutation(&bytes)?);
    }
    Ok(mutations)
}

pub fn append_mutation_to_log(log_dir: impl AsRef<Path>, mutation: &Mutation) -> Result<()> {
    fs::create_dir_all(&log_dir)?;
    let path = shard_log_path(log_dir, mutation.commit_id.shard_id);
    let encoded = encode_mutation(mutation);
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&(encoded.len() as u32).to_le_bytes())?;
    file.write_all(&encoded)?;
    file.sync_data()?;
    Ok(())
}

pub fn read_shard_log(log_dir: impl AsRef<Path>, shard_id: u16) -> Result<Vec<Mutation>> {
    let path = shard_log_path(log_dir, shard_id);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let bytes = fs::read(path)?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let mut mutations = Vec::new();
    while (cursor.position() as usize) < bytes.len() {
        let len = read_u32(&mut cursor)? as usize;
        let payload = read_exact_vec(&mut cursor, len)?;
        mutations.push(decode_mutation(&payload)?);
    }
    Ok(mutations)
}

pub fn load_all_logs(log_dir: impl AsRef<Path>, shard_count: u16) -> Result<Vec<Mutation>> {
    let mut mutations = Vec::new();
    for shard_id in 0..shard_count {
        mutations.extend(read_shard_log(&log_dir, shard_id)?);
    }
    Ok(mutations)
}

pub fn shard_log_path(log_dir: impl AsRef<Path>, shard_id: u16) -> PathBuf {
    log_dir.as_ref().join(format!("shard_{shard_id:04}.glog"))
}

pub fn parse_form_lines(body: &[u8]) -> Result<HashMap<String, String>> {
    let text = std::str::from_utf8(body)
        .map_err(|err| GlobAclError::Parse(format!("request body is not utf8: {err}")))?;
    let mut form = HashMap::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| GlobAclError::Parse(format!("expected key=value line, got {line:?}")))?;
        form.insert(key.trim().to_owned(), value.trim().to_owned());
    }
    Ok(form)
}

pub fn parse_query_path(path: &str) -> (String, HashMap<String, String>) {
    let (route, query) = path.split_once('?').unwrap_or((path, ""));
    let mut params = HashMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        params.insert(percent_decode(key), percent_decode(value));
    }
    (route.to_owned(), params)
}

pub fn http_get(addr: &str, path: &str) -> Result<HttpResponse> {
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    send_http(addr, request.as_bytes())
}

pub fn http_post(addr: &str, path: &str, body: &[u8]) -> Result<HttpResponse> {
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    send_http(addr, &request)
}

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status_code: u16,
    pub body: Vec<u8>,
}

pub fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end;

    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(GlobAclError::Parse(
                "connection closed before headers".to_owned(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(pos) = find_subslice(&buffer, b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if buffer.len() > 64 * 1024 {
            return Err(GlobAclError::Parse("http headers too large".to_owned()));
        }
    }

    let header_text = std::str::from_utf8(&buffer[..header_end])
        .map_err(|err| GlobAclError::Parse(format!("http headers are not utf8: {err}")))?;
    let mut lines = header_text.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| GlobAclError::Parse("missing request line".to_owned()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| GlobAclError::Parse("missing method".to_owned()))?
        .to_owned();
    let path = parts
        .next()
        .ok_or_else(|| GlobAclError::Parse("missing path".to_owned()))?
        .to_owned();

    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|err| GlobAclError::Parse(format!("invalid content-length: {err}")))?;
            }
        }
    }

    let target_len = header_end + content_length;
    while buffer.len() < target_len {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(GlobAclError::Parse(
                "connection closed before body".to_owned(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }

    Ok(HttpRequest {
        method,
        path,
        body: buffer[header_end..target_len].to_vec(),
    })
}

pub fn write_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let reason = match status_code {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let header = format!(
        "HTTP/1.1 {status_code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

pub fn format_commit_outcome(outcome: &CommitOutcome) -> String {
    let entries_changed = if outcome.duplicate { 0 } else { 1 };
    format!(
        "duplicate={}\nshard_id={}\nseq={}\nepoch={}\naction={}\nkey_hash={}\nentries_changed={entries_changed}\n",
        outcome.duplicate,
        outcome.mutation.commit_id.shard_id,
        outcome.mutation.commit_id.seq,
        outcome.mutation.commit_id.epoch,
        outcome.mutation.entry.action.as_str(),
        outcome.mutation.entry.key_hash
    )
}

pub fn format_decision(decision: &Decision) -> String {
    match decision {
        Decision::Allow => "decision=allow\n".to_owned(),
        Decision::Deny {
            reason_code,
            priority,
            commit_id,
        } => format!(
            "decision=deny\nreason_code={reason_code}\npriority={priority}\nshard_id={}\nseq={}\nepoch={}\n",
            commit_id.shard_id, commit_id.seq, commit_id.epoch
        ),
    }
}

fn send_http(addr: &str, request: &[u8]) -> Result<HttpResponse> {
    let mut stream = TcpStream::connect(addr)?;
    stream.write_all(request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    parse_http_response(&response)
}

fn parse_http_response(bytes: &[u8]) -> Result<HttpResponse> {
    let header_end = find_subslice(bytes, b"\r\n\r\n")
        .ok_or_else(|| GlobAclError::Parse("missing http response headers".to_owned()))?
        + 4;
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|err| GlobAclError::Parse(format!("response header is not utf8: {err}")))?;
    let status_line = header
        .lines()
        .next()
        .ok_or_else(|| GlobAclError::Parse("missing response status line".to_owned()))?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| GlobAclError::Parse("missing response status code".to_owned()))?
        .parse::<u16>()
        .map_err(|err| GlobAclError::Parse(format!("invalid status code: {err}")))?;
    Ok(HttpResponse {
        status_code,
        body: bytes[header_end..].to_vec(),
    })
}

fn decision_for_entry(entry: Option<&DenyEntry>, now_unix: u64) -> Decision {
    let Some(entry) = entry else {
        return Decision::Allow;
    };
    if entry.is_expired(now_unix) {
        return Decision::Allow;
    }
    match entry.action {
        Action::Deny => Decision::Deny {
            reason_code: entry.reason_code.clone(),
            priority: entry.priority,
            commit_id: CommitId {
                shard_id: entry.shard_id,
                seq: entry.commit_seq,
                epoch: 1,
                source_region: String::new(),
            },
        },
        Action::AllowOverride | Action::Delete => Decision::Allow,
    }
}

fn required(form: &HashMap<String, String>, key: &str) -> Result<String> {
    form.get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| GlobAclError::Parse(format!("missing required field {key}")))
}

fn parse_u64(value: Option<&str>, default: u64, field: &str) -> Result<u64> {
    match value {
        Some(value) if !value.trim().is_empty() => value
            .trim()
            .parse::<u64>()
            .map_err(|err| GlobAclError::Parse(format!("invalid {field}: {err}"))),
        _ => Ok(default),
    }
}

fn parse_u32(value: Option<&str>, default: u32, field: &str) -> Result<u32> {
    match value {
        Some(value) if !value.trim().is_empty() => value
            .trim()
            .parse::<u32>()
            .map_err(|err| GlobAclError::Parse(format!("invalid {field}: {err}"))),
        _ => Ok(default),
    }
}

fn encode_entry(out: &mut Vec<u8>, entry: &DenyEntry) {
    write_string(out, &entry.tenant_id);
    write_string(out, &entry.namespace);
    write_u64(out, entry.key_hash);
    out.push(entry.action.to_u8());
    write_u32(out, entry.priority);
    write_string(out, &entry.reason_code);
    write_u64(out, entry.expires_at);
    write_string(out, &entry.created_by);
    write_u64(out, entry.commit_seq);
    write_u16(out, entry.shard_id);
}

fn decode_entry(cursor: &mut Cursor<&[u8]>) -> Result<DenyEntry> {
    Ok(DenyEntry {
        tenant_id: read_string(cursor)?,
        namespace: read_string(cursor)?,
        key_hash: read_u64(cursor)?,
        action: Action::from_u8(read_u8(cursor)?)?,
        priority: read_u32(cursor)?,
        reason_code: read_string(cursor)?,
        expires_at: read_u64(cursor)?,
        created_by: read_string(cursor)?,
        commit_seq: read_u64(cursor)?,
        shard_id: read_u16(cursor)?,
    })
}

fn decode_mutation_from_cursor(cursor: &mut Cursor<&[u8]>) -> Result<Mutation> {
    expect_magic(cursor, MUTATION_MAGIC)?;
    let version = read_u16(cursor)?;
    if version != FORMAT_VERSION {
        return Err(GlobAclError::InvalidData(format!(
            "unsupported mutation version {version}"
        )));
    }
    let op_id = read_string(cursor)?;
    let shard_id = read_u16(cursor)?;
    let seq = read_u64(cursor)?;
    let epoch = read_u64(cursor)?;
    let source_region = read_string(cursor)?;
    let entry = decode_entry(cursor)?;
    Ok(Mutation {
        op_id,
        commit_id: CommitId {
            shard_id,
            seq,
            epoch,
            source_region,
        },
        entry,
    })
}

fn expect_magic(cursor: &mut Cursor<&[u8]>, expected: &[u8; 4]) -> Result<()> {
    let actual = read_exact_vec(cursor, 4)?;
    if actual.as_slice() != expected {
        return Err(GlobAclError::InvalidData(format!(
            "bad magic {:?}, expected {:?}",
            String::from_utf8_lossy(&actual),
            String::from_utf8_lossy(expected)
        )));
    }
    Ok(())
}

fn write_string(out: &mut Vec<u8>, value: &str) {
    write_u32(out, value.len() as u32);
    out.extend_from_slice(value.as_bytes());
}

fn read_string(cursor: &mut Cursor<&[u8]>) -> Result<String> {
    let len = read_u32(cursor)? as usize;
    let bytes = read_exact_vec(cursor, len)?;
    String::from_utf8(bytes)
        .map_err(|err| GlobAclError::InvalidData(format!("string is not utf8: {err}")))
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn read_u8(cursor: &mut Cursor<&[u8]>) -> Result<u8> {
    Ok(read_exact_vec(cursor, 1)?[0])
}

fn read_u16(cursor: &mut Cursor<&[u8]>) -> Result<u16> {
    let bytes = read_exact_vec(cursor, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32> {
    let bytes = read_exact_vec(cursor, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64> {
    let bytes = read_exact_vec(cursor, 8)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_exact_vec(cursor: &mut Cursor<&[u8]>, len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    cursor.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn percent_decode(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                if let Ok(hex) = u8::from_str_radix(&value[index + 1..index + 3], 16) {
                    out.push(hex);
                    index += 3;
                } else {
                    out.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(op_id: &str, key: &str, action: Action) -> DenyRequest {
        DenyRequest {
            op_id: op_id.to_owned(),
            tenant_id: "tenant-a".to_owned(),
            namespace: "user".to_owned(),
            key: key.to_owned(),
            action,
            priority: 10,
            reason_code: "test".to_owned(),
            expires_at: 0,
            created_by: "unit-test".to_owned(),
        }
    }

    #[test]
    fn duplicate_op_id_is_idempotent() {
        let mut source = SourceOfTruth::new(16, "local");
        let first = source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let second = source.commit(request("op-1", "u1", Action::Deny)).unwrap();

        assert!(!first.duplicate);
        assert!(second.duplicate);
        assert_eq!(first.mutation.commit_id, second.mutation.commit_id);
        assert_eq!(source.mutations_len(), 1);
    }

    #[test]
    fn active_state_applies_and_deletes_mutations() {
        let mut source = SourceOfTruth::new(16, "local");
        let add = source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let delete = source
            .commit(request("op-2", "u1", Action::Delete))
            .unwrap();

        let mut active = ActiveState::new(16);
        active.apply_mutation(&add.mutation).unwrap();
        assert!(active
            .lookup("tenant-a", "user", "u1", now_unix())
            .is_denied());

        active.apply_mutation(&delete.mutation).unwrap();
        assert_eq!(
            active.lookup("tenant-a", "user", "u1", now_unix()),
            Decision::Allow
        );
    }

    #[test]
    fn snapshot_round_trips() {
        let mut source = SourceOfTruth::new(16, "local");
        source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        source.commit(request("op-2", "u2", Action::Deny)).unwrap();

        let snapshot = source.snapshot();
        let decoded = decode_snapshot(&encode_snapshot(&snapshot)).unwrap();
        let active = ActiveState::from_snapshot(decoded).unwrap();

        assert!(active
            .lookup("tenant-a", "user", "u1", now_unix())
            .is_denied());
        assert!(active
            .lookup("tenant-a", "user", "u2", now_unix())
            .is_denied());
        assert_eq!(
            active.lookup("tenant-a", "user", "u3", now_unix()),
            Decision::Allow
        );
    }

    #[test]
    fn mutation_stream_round_trips() {
        let mut source = SourceOfTruth::new(16, "local");
        let one = source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let two = source.commit(request("op-2", "u2", Action::Deny)).unwrap();

        let encoded = encode_mutation_stream(&[one.mutation.clone(), two.mutation.clone()]);
        let decoded = decode_mutation_stream(&encoded).unwrap();
        assert_eq!(decoded, vec![one.mutation, two.mutation]);
    }

    #[test]
    fn gap_detection_rejects_out_of_order_apply() {
        let mut source = SourceOfTruth::new(1, "local");
        let first = source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let second = source.commit(request("op-2", "u2", Action::Deny)).unwrap();
        let mut active = ActiveState::new(1);

        let err = active.apply_mutation(&second.mutation).unwrap_err();
        assert!(matches!(err, GlobAclError::Gap { .. }));

        active.apply_mutation(&first.mutation).unwrap();
        active.apply_mutation(&second.mutation).unwrap();
        assert!(active
            .lookup("tenant-a", "user", "u2", now_unix())
            .is_denied());
    }

    #[test]
    fn append_log_replays_source_of_truth() {
        let root = std::env::temp_dir().join(format!(
            "globacl-core-test-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let log_dir = root.join("logs");

        let mut source = SourceOfTruth::new(16, "local");
        let one = source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let two = source.commit(request("op-2", "u2", Action::Deny)).unwrap();
        append_mutation_to_log(&log_dir, &one.mutation).unwrap();
        append_mutation_to_log(&log_dir, &two.mutation).unwrap();

        let loaded = load_all_logs(&log_dir, 16).unwrap();
        let replayed = SourceOfTruth::from_mutations(16, "local", loaded).unwrap();

        assert_eq!(replayed.mutations_len(), 2);
        assert!(replayed
            .lookup("tenant-a", "user", "u1", now_unix())
            .is_denied());
        assert!(replayed
            .lookup("tenant-a", "user", "u2", now_unix())
            .is_denied());

        let _ = std::fs::remove_dir_all(root);
    }
}
