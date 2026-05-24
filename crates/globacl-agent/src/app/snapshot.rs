fn load_or_fetch_snapshot(
    relay_addr: &str,
    snapshot_path: &Path,
    signature_verifier: &SignatureVerifier,
) -> Result<globacl_core::Snapshot> {
    if snapshot_path.exists() {
        verify_local_snapshot(snapshot_path, signature_verifier)?;
        return read_snapshot_file(snapshot_path);
    }
    let snapshot = fetch_snapshot(relay_addr, signature_verifier)?;
    write_snapshot_file(snapshot_path, &snapshot)?;
    Ok(snapshot)
}

fn fetch_snapshot(
    relay_addr: &str,
    signature_verifier: &SignatureVerifier,
) -> Result<globacl_core::Snapshot> {
    match fetch_snapshot_from_manifest(relay_addr, signature_verifier) {
        Ok(snapshot) => return Ok(snapshot),
        Err(err) => {
            eprintln!("snapshot manifest fetch failed, falling back to legacy snapshot: {err}")
        }
    }

    let response = http_get(relay_addr, "/v1/snapshot")?;
    if response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "relay returned status {} for snapshot",
            response.status_code
        )));
    }
    verify_remote_payload_signature(
        relay_addr,
        "/v1/snapshot.sig",
        &response.body,
        signature_verifier,
    )?;
    decode_snapshot(&response.body)
}

fn fetch_snapshot_from_manifest(
    relay_addr: &str,
    signature_verifier: &SignatureVerifier,
) -> Result<globacl_core::Snapshot> {
    let manifest_response = http_get(relay_addr, "/v1/snapshot_manifest")?;
    if manifest_response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "relay returned status {} for snapshot manifest",
            manifest_response.status_code
        )));
    }
    verify_required_remote_payload_signature(
        relay_addr,
        "/v1/snapshot_manifest.sig",
        &manifest_response.body,
        signature_verifier,
    )?;
    let manifest = decode_snapshot_manifest(&manifest_response.body)?;

    let artifact_path = format!("/v1/snapshot_artifact?object={}", manifest.artifact_object);
    let artifact_response = http_get(relay_addr, &artifact_path)?;
    if artifact_response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "relay returned status {} for snapshot artifact {}",
            artifact_response.status_code, manifest.artifact_object
        )));
    }
    let artifact_signature_path = format!(
        "/v1/snapshot_artifact.sig?object={}",
        manifest.artifact_object
    );
    verify_required_remote_payload_signature(
        relay_addr,
        &artifact_signature_path,
        &artifact_response.body,
        signature_verifier,
    )?;
    manifest.validate_artifact(&artifact_response.body)?;
    let snapshot = decode_snapshot(&artifact_response.body)?;
    manifest.validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn verify_local_snapshot(path: &Path, signature_verifier: &SignatureVerifier) -> Result<()> {
    let sig_path = signature_path(path);
    if !sig_path.exists() {
        return Ok(());
    }
    let payload = fs::read(path)?;
    let signature = fs::read(sig_path)?;
    verify_snapshot_signature(&payload, &signature, signature_verifier)
}

fn verify_remote_payload_signature(
    relay_addr: &str,
    signature_path: &str,
    payload: &[u8],
    signature_verifier: &SignatureVerifier,
) -> Result<()> {
    let response = http_get(relay_addr, signature_path)?;
    if response.status_code != 200 || response.body.is_empty() {
        return Ok(());
    }
    verify_snapshot_signature(payload, &response.body, signature_verifier)
}

fn verify_required_remote_payload_signature(
    relay_addr: &str,
    signature_path: &str,
    payload: &[u8],
    signature_verifier: &SignatureVerifier,
) -> Result<()> {
    let response = http_get(relay_addr, signature_path)?;
    if response.status_code != 200 || response.body.is_empty() {
        return Err(GlobAclError::InvalidData(format!(
            "required signature missing at {signature_path}"
        )));
    }
    verify_snapshot_signature(payload, &response.body, signature_verifier)
}

fn verify_snapshot_signature(
    payload: &[u8],
    signature_body: &[u8],
    signature_verifier: &SignatureVerifier,
) -> Result<()> {
    verify_payload_signature_with_verifier(signature_verifier, payload, signature_body)
}

fn signature_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sig", path.display()))
}

fn signature_verifier_from_env() -> Result<SignatureVerifier> {
    let min_key_version = env::var("GLOBACL_SIGNATURE_MIN_KEY_VERSION")
        .ok()
        .map(|value| parse_arg_u64(&value, "GLOBACL_SIGNATURE_MIN_KEY_VERSION"))
        .transpose()?
        .unwrap_or(0);

    let mut keys = Vec::new();
    if let Some(public_keys) = env_text_or_file(
        "GLOBACL_SIGNATURE_PUBLIC_KEYS",
        "GLOBACL_SIGNATURE_PUBLIC_KEYS_FILE",
    )? {
        keys.extend(parse_signature_public_keys(&public_keys)?);
    }

    let explicit_public_key = env_text_or_file(
        "GLOBACL_SIGNATURE_PUBLIC_KEY",
        "GLOBACL_SIGNATURE_PUBLIC_KEY_FILE",
    )?;
    if keys.is_empty() || explicit_public_key.is_some() {
        let key_id = env::var("GLOBACL_SIGNATURE_KEY_ID")
            .unwrap_or_else(|_| DEFAULT_SIGNATURE_KEY_ID.to_owned());
        let key_version = env::var("GLOBACL_SIGNATURE_KEY_VERSION")
            .ok()
            .map(|value| parse_arg_u64(&value, "GLOBACL_SIGNATURE_KEY_VERSION"))
            .transpose()?
            .unwrap_or(DEFAULT_SIGNATURE_KEY_VERSION);
        let public_key =
            explicit_public_key.unwrap_or_else(|| DEFAULT_SIGNATURE_PUBLIC_KEY.to_owned());
        if keys.iter().any(|key| key.key_id == key_id) {
            return Err(GlobAclError::InvalidData(format!(
                "duplicate signature key_id {key_id:?} in keyring and single-key configuration"
            )));
        }
        keys.push(SignatureVerificationKey::new(
            key_id,
            key_version,
            public_key.trim().to_owned(),
        ));
    }

    SignatureVerifier::new(keys, min_key_version)
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

