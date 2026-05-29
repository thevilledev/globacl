fn persist_mutation(app: &App, mutation: &Mutation) -> Result<()> {
    maybe_inject_test_storage_fault("mutation_log", StorageFault::DiskFull)?;
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

fn maybe_compact_mutation_logs(app: &App, state: &mut SourceOfTruth) -> Result<()> {
    if app.compaction.min_log_entries == 0 || state.mutations_len() < app.compaction.min_log_entries
    {
        return Ok(());
    }
    compact_mutation_logs_locked(app, state)
}

fn compact_mutation_logs(app: &App, force: bool) -> Result<()> {
    let mut state = lock_state(app)?;
    if !force
        && (app.compaction.min_log_entries == 0
            || state.mutations_len() < app.compaction.min_log_entries)
    {
        return Ok(());
    }
    compact_mutation_logs_locked(app, &mut state)
}

fn compact_mutation_logs_locked(app: &App, state: &mut SourceOfTruth) -> Result<()> {
    let snapshot = state.snapshot();
    let compaction_watermarks = compaction_watermarks_for_snapshot(app, state, &snapshot)?;
    persist_latest_snapshot(app, &snapshot)?;
    persist_idempotency_snapshot(&app.idempotency_path, &state.idempotency_mutations())?;
    compact_logs_to_watermarks(&app.log_dir, state.shard_count(), &compaction_watermarks)?;
    state.compact_mutation_history(&compaction_watermarks)?;
    Ok(())
}

fn compaction_watermarks_for_snapshot(
    app: &App,
    state: &SourceOfTruth,
    snapshot: &Snapshot,
) -> Result<Vec<u64>> {
    let mut watermarks = snapshot.watermarks.clone();
    if app.publisher.is_some() {
        let published = lock_publisher_status(app)?.last_published.clone();
        for (shard_id, watermark) in watermarks.iter_mut().enumerate() {
            let published_seq = published.get(shard_id).copied().unwrap_or(0);
            *watermark = (*watermark).min(published_seq);
        }
    }

    for (shard_id, watermark) in watermarks.iter_mut().enumerate() {
        *watermark = (*watermark).max(state.compacted_watermarks()[shard_id]);
    }

    Ok(watermarks)
}

fn persist_idempotency_snapshot(path: &Path, mutations: &[Mutation]) -> Result<()> {
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
        file.write_all(&encode_mutation_stream(mutations))?;
        file.sync_all()?;
    }
    fs::rename(tmp, path)?;
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
        app.object_store.as_ref(),
    )
}

fn write_snapshot_manifest_publication(
    object_dir: &Path,
    manifest_dir: &Path,
    latest_manifest_path: &Path,
    snapshot: &Snapshot,
    signer: &SignatureSigner,
    object_store: Option<&ObjectStoreConfig>,
) -> Result<SnapshotManifest> {
    let payload = encode_snapshot(snapshot);
    let artifact_sha256 = snapshot_artifact_sha256_hex(&payload);
    let artifact_object = immutable_snapshot_object_name(snapshot, &artifact_sha256);
    let artifact_path = object_dir.join(&artifact_object);
    write_signed_payload_file(&artifact_path, &payload, signer)?;
    let artifact_signature_payload = fs::read(signature_path(&artifact_path))?;

    let manifest = SnapshotManifest::for_snapshot(
        snapshot,
        now_unix(),
        artifact_object,
        payload.len() as u64,
        artifact_sha256,
    );
    let manifest_payload = encode_snapshot_manifest(&manifest);
    let immutable_manifest_path = manifest_dir.join(snapshot_manifest_file_name(&manifest));
    write_signed_payload_file(&immutable_manifest_path, &manifest_payload, signer)?;
    let immutable_manifest_signature_payload = fs::read(signature_path(&immutable_manifest_path))?;
    write_signed_payload_file(latest_manifest_path, &manifest_payload, signer)?;
    let latest_manifest_signature_payload = fs::read(signature_path(latest_manifest_path))?;
    publish_snapshot_to_object_store_best_effort(
        object_store,
        &SnapshotPublication {
            manifest: &manifest,
            artifact_payload: &payload,
            artifact_signature_payload: &artifact_signature_payload,
            immutable_manifest_payload: &manifest_payload,
            immutable_manifest_signature_payload: &immutable_manifest_signature_payload,
            latest_manifest_payload: &manifest_payload,
            latest_manifest_signature_payload: &latest_manifest_signature_payload,
        },
    )?;
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
    maybe_inject_test_storage_fault("payload_file", StorageFault::DiskFull)?;
    let tmp = path.as_ref().with_extension("tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(payload)?;
        maybe_inject_test_storage_fault("payload_file", StorageFault::Fsync)?;
        file.sync_all()?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StorageFault {
    DiskFull,
    Fsync,
}

fn maybe_inject_test_storage_fault(operation: &str, fault: StorageFault) -> Result<()> {
    #[cfg(test)]
    {
        if take_test_storage_fault(operation, fault) {
            let message = match fault {
                StorageFault::DiskFull => "simulated disk full",
                StorageFault::Fsync => "simulated fsync failure",
            };
            return Err(GlobAclError::Io(std::io::Error::other(message)));
        }
    }

    let _ = (operation, fault);
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TestStorageFault {
    operation: &'static str,
    fault: StorageFault,
}

#[cfg(test)]
thread_local! {
    static TEST_STORAGE_FAULT: std::cell::RefCell<Option<TestStorageFault>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
struct TestStorageFaultGuard {
    previous: Option<TestStorageFault>,
}

#[cfg(test)]
impl Drop for TestStorageFaultGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        TEST_STORAGE_FAULT.with(|slot| {
            *slot.borrow_mut() = previous;
        });
    }
}

#[cfg(test)]
fn set_test_storage_fault(
    operation: &'static str,
    fault: StorageFault,
) -> TestStorageFaultGuard {
    let previous = TEST_STORAGE_FAULT.with(|slot| slot.borrow_mut().replace(TestStorageFault {
        operation,
        fault,
    }));
    TestStorageFaultGuard { previous }
}

#[cfg(test)]
fn take_test_storage_fault(operation: &str, fault: StorageFault) -> bool {
    TEST_STORAGE_FAULT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .map(|configured| configured.operation == operation && configured.fault == fault)
            .unwrap_or(false)
        {
            *slot = None;
            true
        } else {
            false
        }
    })
}

fn write_pending_mutation(pending_dir: &Path, mutation: &Mutation) -> Result<()> {
    fs::create_dir_all(pending_dir)?;
    let path = pending_mutation_path(pending_dir, mutation);
    if path.exists() {
        let existing = decode_mutation(&fs::read(&path)?)?;
        if existing == *mutation {
            return Ok(());
        }
        if existing.commit_id.epoch < mutation.commit_id.epoch {
            eprintln!(
                "replacing stale pending mutation: shard={} seq={} old_epoch={} new_epoch={}",
                mutation.commit_id.shard_id,
                mutation.commit_id.seq,
                existing.commit_id.epoch,
                mutation.commit_id.epoch
            );
        } else if existing.commit_id.epoch > mutation.commit_id.epoch {
            return Err(GlobAclError::InvalidData(format!(
                "pending mutation at {} has newer epoch {} than incoming epoch {}",
                path.display(),
                existing.commit_id.epoch,
                mutation.commit_id.epoch
            )));
        } else {
            return Err(GlobAclError::InvalidData(format!(
                "pending mutation conflict at {}",
                path.display()
            )));
        }
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

fn load_pending_mutations(pending_dir: &Path) -> Result<Vec<Mutation>> {
    let mut mutations = Vec::new();
    if !pending_dir.exists() {
        return Ok(mutations);
    }
    for entry in fs::read_dir(pending_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("gmut") {
            continue;
        }
        mutations.push(decode_mutation(&fs::read(path)?)?);
    }
    mutations.sort_by_key(|mutation| {
        (
            mutation.commit_id.shard_id,
            mutation.commit_id.seq,
            mutation.commit_id.epoch,
        )
    });
    Ok(mutations)
}

fn ensure_pending_mutation(pending_dir: &Path, mutation: &Mutation) -> Result<()> {
    let path = pending_mutation_path(pending_dir, mutation);
    if !path.exists() {
        return Err(GlobAclError::InvalidData(format!(
            "pending mutation missing at {}",
            path.display()
        )));
    }
    let existing = decode_mutation(&fs::read(&path)?)?;
    if existing != *mutation {
        return Err(GlobAclError::InvalidData(format!(
            "pending mutation at {} does not match commit payload",
            path.display()
        )));
    }
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
    Ok(json!({
        "snapshot_count": names.len(),
        "snapshots": names,
        "manifest_count": manifests.len(),
        "manifests": manifests
    })
    .to_string())
}

fn append_audit(app: &App, event: &str, result: &str, details: JsonValue) -> Result<()> {
    if let Some(parent) = app.audit_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&app.audit_path)?;
    let mut record = json!({
        "ts": now_unix(),
        "event": event,
        "result": result
    });
    if let Some(record) = record.as_object_mut() {
        if let Some(details) = details.as_object() {
            for (key, value) in details {
                record.insert(key.clone(), value.clone());
            }
        } else {
            record.insert("details".to_owned(), details);
        }
    }
    writeln!(file, "{record}")?;
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
