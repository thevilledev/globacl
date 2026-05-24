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
    if app.publisher.is_some() {
        return Ok(());
    }

    let snapshot = state.snapshot();
    persist_latest_snapshot(app, &snapshot)?;
    persist_idempotency_snapshot(&app.idempotency_path, &state.idempotency_mutations())?;
    compact_logs_to_watermarks(&app.log_dir, state.shard_count(), &snapshot.watermarks)?;
    state.compact_mutation_history(&snapshot.watermarks)?;
    Ok(())
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

