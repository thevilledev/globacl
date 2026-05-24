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
    write_u64(&mut out, snapshot.rules.len() as u64);
    for rule in &snapshot.rules {
        encode_rule_entry(&mut out, rule);
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
    let mut rules = Vec::new();
    if cursor_remaining(&cursor) >= 8 {
        let rule_count = read_u64(&mut cursor)? as usize;
        rules = Vec::with_capacity(rule_count);
        for _ in 0..rule_count {
            rules.push(decode_rule_entry(&mut cursor)?);
        }
    }

    Ok(Snapshot {
        shard_count,
        watermarks,
        entries,
        rules,
    })
}

pub fn snapshot_artifact_sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

pub fn immutable_snapshot_object_name(snapshot: &Snapshot, artifact_sha256: &str) -> String {
    let max_seq = snapshot.watermarks.iter().copied().max().unwrap_or(0);
    format!(
        "snapshots/max_seq_{max_seq:020}_sha256_{}.gacl",
        artifact_sha256
    )
}

pub fn encode_snapshot_manifest(manifest: &SnapshotManifest) -> Vec<u8> {
    let mut out = JsonMap::new();
    out.insert(
        "manifest_version".to_owned(),
        Value::Number(JsonNumber::from(manifest.manifest_version)),
    );
    out.insert(
        "format_version".to_owned(),
        Value::Number(JsonNumber::from(manifest.format_version)),
    );
    out.insert(
        "created_at_unix".to_owned(),
        Value::Number(JsonNumber::from(manifest.created_at_unix)),
    );
    out.insert(
        "artifact_object".to_owned(),
        Value::String(manifest.artifact_object.clone()),
    );
    out.insert(
        "artifact_signature_object".to_owned(),
        Value::String(manifest.artifact_signature_object.clone()),
    );
    out.insert(
        "artifact_bytes".to_owned(),
        Value::Number(JsonNumber::from(manifest.artifact_bytes)),
    );
    out.insert(
        "artifact_sha256".to_owned(),
        Value::String(manifest.artifact_sha256.clone()),
    );
    out.insert(
        "shard_count".to_owned(),
        Value::Number(JsonNumber::from(manifest.shard_count)),
    );
    out.insert(
        "entry_count".to_owned(),
        Value::Number(JsonNumber::from(manifest.entry_count)),
    );
    out.insert(
        "rule_count".to_owned(),
        Value::Number(JsonNumber::from(manifest.rule_count)),
    );
    out.insert(
        "max_seq".to_owned(),
        Value::Number(JsonNumber::from(manifest.max_seq)),
    );
    for (shard_id, seq) in manifest.watermarks.iter().enumerate() {
        out.insert(
            format!("shard_{shard_id:04}"),
            Value::Number(JsonNumber::from(*seq)),
        );
    }
    serde_json::to_vec(&Value::Object(out)).expect("snapshot manifest JSON should encode")
}

pub fn decode_snapshot_manifest(bytes: &[u8]) -> Result<SnapshotManifest> {
    let form = parse_json_fields(bytes)?;
    let shard_count = parse_u16_manifest(&form, "shard_count")?;
    let mut watermarks = Vec::with_capacity(shard_count as usize);
    for shard_id in 0..shard_count {
        let key = format!("shard_{shard_id:04}");
        watermarks.push(parse_u64(form.get(&key).map(String::as_str), 0, &key)?);
    }
    let manifest = SnapshotManifest {
        manifest_version: parse_u16_manifest(&form, "manifest_version")?,
        format_version: parse_u16_manifest(&form, "format_version")?,
        created_at_unix: parse_u64(
            form.get("created_at_unix").map(String::as_str),
            0,
            "created_at_unix",
        )?,
        artifact_object: required(&form, "artifact_object")?,
        artifact_signature_object: required(&form, "artifact_signature_object")?,
        artifact_bytes: parse_u64(
            form.get("artifact_bytes").map(String::as_str),
            0,
            "artifact_bytes",
        )?,
        artifact_sha256: required(&form, "artifact_sha256")?,
        shard_count,
        entry_count: parse_u64(
            form.get("entry_count").map(String::as_str),
            0,
            "entry_count",
        )?,
        rule_count: parse_u64(form.get("rule_count").map(String::as_str), 0, "rule_count")?,
        max_seq: parse_u64(form.get("max_seq").map(String::as_str), 0, "max_seq")?,
        watermarks,
    };
    manifest.validate()?;
    Ok(manifest)
}

pub fn is_safe_snapshot_object_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.contains('\\')
        && !name.contains("..")
        && !name.contains("//")
        && name.ends_with(".gacl")
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-'))
}

fn parse_u16_manifest(form: &HashMap<String, String>, key: &str) -> Result<u16> {
    let value = parse_u64(form.get(key).map(String::as_str), 0, key)?;
    u16::try_from(value)
        .map_err(|_| GlobAclError::Parse(format!("{key} must fit in u16, got {value}")))
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
    out.push(mutation.delivery_priority.to_u8());
    write_u64(&mut out, mutation.committed_at_unix);
    match &mutation.rule {
        Some(rule) => {
            out.push(1);
            encode_rule_entry(&mut out, rule);
        }
        None => out.push(0),
    }
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

pub fn load_logs_after_watermarks(
    log_dir: impl AsRef<Path>,
    shard_count: u16,
    watermarks: &[u64],
) -> Result<Vec<Mutation>> {
    if watermarks.len() != shard_count as usize {
        return Err(GlobAclError::InvalidData(format!(
            "log replay has {} watermarks for {} shards",
            watermarks.len(),
            shard_count
        )));
    }

    let mut mutations = Vec::new();
    for shard_id in 0..shard_count {
        let compacted_seq = watermarks[shard_id as usize];
        mutations.extend(
            read_shard_log(&log_dir, shard_id)?
                .into_iter()
                .filter(|mutation| mutation.commit_id.seq > compacted_seq),
        );
    }
    Ok(mutations)
}

pub fn compact_logs_to_watermarks(
    log_dir: impl AsRef<Path>,
    shard_count: u16,
    watermarks: &[u64],
) -> Result<()> {
    if watermarks.len() != shard_count as usize {
        return Err(GlobAclError::InvalidData(format!(
            "log compaction has {} watermarks for {} shards",
            watermarks.len(),
            shard_count
        )));
    }

    fs::create_dir_all(&log_dir)?;
    for shard_id in 0..shard_count {
        let compacted_seq = watermarks[shard_id as usize];
        let tail = read_shard_log(&log_dir, shard_id)?
            .into_iter()
            .filter(|mutation| mutation.commit_id.seq > compacted_seq)
            .collect::<Vec<_>>();
        write_shard_log(&log_dir, shard_id, &tail)?;
    }
    Ok(())
}

pub fn shard_log_path(log_dir: impl AsRef<Path>, shard_id: u16) -> PathBuf {
    log_dir.as_ref().join(format!("shard_{shard_id:04}.glog"))
}

fn write_shard_log(log_dir: impl AsRef<Path>, shard_id: u16, mutations: &[Mutation]) -> Result<()> {
    fs::create_dir_all(&log_dir)?;
    let path = shard_log_path(log_dir, shard_id);
    let tmp = path.with_extension("tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        for mutation in mutations {
            let encoded = encode_mutation(mutation);
            file.write_all(&(encoded.len() as u32).to_le_bytes())?;
            file.write_all(&encoded)?;
        }
        file.sync_all()?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

pub fn write_delta_bundle_file(
    bundle_dir: impl AsRef<Path>,
    shard_id: u16,
    from_seq: u64,
    to_seq: u64,
    mutations: &[Mutation],
) -> Result<PathBuf> {
    fs::create_dir_all(&bundle_dir)?;
    let path = delta_bundle_path(bundle_dir, shard_id, from_seq, to_seq);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(&encode_mutation_stream(mutations))?;
        file.sync_all()?;
    }
    fs::rename(tmp, &path)?;
    Ok(path)
}

pub fn read_delta_bundle_file(path: impl AsRef<Path>) -> Result<Vec<Mutation>> {
    decode_mutation_stream(&fs::read(path)?)
}

pub fn delta_bundle_path(
    bundle_dir: impl AsRef<Path>,
    shard_id: u16,
    from_seq: u64,
    to_seq: u64,
) -> PathBuf {
    bundle_dir.as_ref().join(format!(
        "shard_{shard_id:04}/delta_{from_seq:020}_{to_seq:020}.glog"
    ))
}

