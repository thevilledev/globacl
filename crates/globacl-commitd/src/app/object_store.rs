const LATEST_MANIFEST_OBJECT: &str = "manifests/latest.manifest";
const LATEST_MANIFEST_SIGNATURE_OBJECT: &str = "manifests/latest.manifest.sig";

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObjectStoreConfig {
    endpoint: String,
    region: String,
    bucket: String,
    prefix: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    force_path_style: bool,
    request_timeout_ms: u64,
    allow_empty_bootstrap: bool,
    require_upload: bool,
}

#[derive(Debug)]
struct SignedS3Request {
    url: String,
    host: String,
    x_amz_date: String,
    x_amz_content_sha256: String,
    x_amz_security_token: Option<String>,
    authorization: String,
}

struct SnapshotPublication<'a> {
    manifest: &'a SnapshotManifest,
    artifact_payload: &'a [u8],
    artifact_signature_payload: &'a [u8],
    immutable_manifest_payload: &'a [u8],
    immutable_manifest_signature_payload: &'a [u8],
    latest_manifest_payload: &'a [u8],
    latest_manifest_signature_payload: &'a [u8],
}

fn object_store_config() -> Result<Option<ObjectStoreConfig>> {
    let mode = env::var("GLOBACL_OBJECT_STORE")
        .or_else(|_| env::var("GLOBACL_SNAPSHOT_STORE"))
        .unwrap_or_else(|_| "local".to_owned());
    match mode.trim().to_ascii_lowercase().as_str() {
        "" | "local" | "filesystem" | "fs" | "none" | "off" | "disabled" => Ok(None),
        "s3" | "s3-compatible" | "s3_compatible" => ObjectStoreConfig::from_env().map(Some),
        other => Err(GlobAclError::Parse(format!(
            "unknown GLOBACL_OBJECT_STORE mode {other:?}"
        ))),
    }
}

impl ObjectStoreConfig {
    fn from_env() -> Result<Self> {
        let region = env::var("GLOBACL_S3_REGION")
            .or_else(|_| env::var("AWS_REGION"))
            .or_else(|_| env::var("AWS_DEFAULT_REGION"))
            .unwrap_or_else(|_| "us-east-1".to_owned());
        let endpoint = env::var("GLOBACL_S3_ENDPOINT")
            .unwrap_or_else(|_| format!("https://s3.{region}.amazonaws.com"));
        let bucket = required_env_any(&["GLOBACL_S3_BUCKET", "AWS_S3_BUCKET"])?;
        let prefix = env::var("GLOBACL_S3_PREFIX").unwrap_or_else(|_| "globacl".to_owned());
        let access_key_id =
            required_env_any(&["GLOBACL_S3_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID"])?;
        let secret_access_key =
            required_env_any(&["GLOBACL_S3_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY"])?;
        let session_token = env::var("GLOBACL_S3_SESSION_TOKEN")
            .or_else(|_| env::var("AWS_SESSION_TOKEN"))
            .ok()
            .filter(|value| !value.trim().is_empty());
        let request_timeout_ms = env::var("GLOBACL_S3_TIMEOUT_MS")
            .ok()
            .map(|value| parse_env_u64(&value, "GLOBACL_S3_TIMEOUT_MS"))
            .transpose()?
            .unwrap_or(10_000);

        validate_s3_bucket(&bucket)?;
        let prefix = normalize_object_prefix(&prefix)?;
        if request_timeout_ms == 0 {
            return Err(GlobAclError::InvalidData(
                "GLOBACL_S3_TIMEOUT_MS must be greater than zero".to_owned(),
            ));
        }

        Ok(Self {
            endpoint,
            region,
            bucket,
            prefix,
            access_key_id,
            secret_access_key,
            session_token,
            force_path_style: env_bool("GLOBACL_S3_FORCE_PATH_STYLE", true),
            request_timeout_ms,
            allow_empty_bootstrap: env_bool("GLOBACL_OBJECT_STORE_ALLOW_EMPTY_BOOTSTRAP", false),
            require_upload: env_bool("GLOBACL_OBJECT_STORE_REQUIRE_UPLOAD", false),
        })
    }

    fn put(&self, object: &str, body: &[u8], content_type: &str) -> Result<()> {
        let request = self.sign_request("PUT", object, body)?;
        let client = self.client()?;
        let mut builder = client
            .put(&request.url)
            .header("Host", request.host)
            .header("x-amz-content-sha256", request.x_amz_content_sha256)
            .header("x-amz-date", request.x_amz_date)
            .header("Authorization", request.authorization)
            .header("Content-Type", content_type)
            .body(body.to_vec());
        if let Some(token) = request.x_amz_security_token {
            builder = builder.header("x-amz-security-token", token);
        }
        let response = builder.send().map_err(object_store_request_error)?;
        if !response.status().is_success() {
            return object_store_status_error("PUT", object, response);
        }
        Ok(())
    }

    fn get_optional(&self, object: &str) -> Result<Option<Vec<u8>>> {
        let request = self.sign_request("GET", object, &[])?;
        let client = self.client()?;
        let mut builder = client
            .get(&request.url)
            .header("Host", request.host)
            .header("x-amz-content-sha256", request.x_amz_content_sha256)
            .header("x-amz-date", request.x_amz_date)
            .header("Authorization", request.authorization);
        if let Some(token) = request.x_amz_security_token {
            builder = builder.header("x-amz-security-token", token);
        }
        let response = builder.send().map_err(object_store_request_error)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return object_store_status_error("GET", object, response);
        }
        let bytes = response.bytes().map_err(object_store_request_error)?;
        Ok(Some(bytes.to_vec()))
    }

    fn get(&self, object: &str) -> Result<Vec<u8>> {
        self.get_optional(object)?.ok_or_else(|| {
            GlobAclError::InvalidData(format!("object store object {object:?} was not found"))
        })
    }

    fn client(&self) -> Result<reqwest::blocking::Client> {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(self.request_timeout_ms))
            .build()
            .map_err(object_store_request_error)
    }

    fn sign_request(&self, method: &str, object: &str, body: &[u8]) -> Result<SignedS3Request> {
        let key = self.object_key(object)?;
        let address = self.address_for_key(&key)?;
        let (date, amz_date) = aws_sigv4_dates(SystemTime::now())?;
        let payload_hash = sha256_hex(body);
        let mut canonical_headers = format!(
            "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
            address.host, payload_hash, amz_date
        );
        let mut signed_headers = "host;x-amz-content-sha256;x-amz-date".to_owned();
        if let Some(token) = &self.session_token {
            canonical_headers.push_str(&format!("x-amz-security-token:{}\n", token.trim()));
            signed_headers.push_str(";x-amz-security-token");
        }

        let canonical_request = format!(
            "{method}\n{}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
            address.canonical_uri
        );
        let credential_scope = format!("{date}/{}/s3/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let signature = aws_sigv4_signature(
            self.secret_access_key.as_bytes(),
            &date,
            &self.region,
            string_to_sign.as_bytes(),
        );
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={}",
            self.access_key_id,
            hex_encode_bytes(&signature)
        );

        Ok(SignedS3Request {
            url: address.url,
            host: address.host,
            x_amz_date: amz_date,
            x_amz_content_sha256: payload_hash,
            x_amz_security_token: self.session_token.clone(),
            authorization,
        })
    }

    fn object_key(&self, object: &str) -> Result<String> {
        let object = normalize_object_prefix(object)?;
        if object.is_empty() {
            return Err(GlobAclError::InvalidData(
                "object store object key cannot be empty".to_owned(),
            ));
        }
        if self.prefix.is_empty() {
            Ok(object)
        } else {
            Ok(format!("{}/{}", self.prefix, object))
        }
    }

    fn address_for_key(&self, key: &str) -> Result<S3Address> {
        let endpoint = reqwest::Url::parse(&self.endpoint)
            .map_err(|err| GlobAclError::Parse(format!("invalid GLOBACL_S3_ENDPOINT: {err}")))?;
        if endpoint.scheme() != "http" && endpoint.scheme() != "https" {
            return Err(GlobAclError::Parse(
                "GLOBACL_S3_ENDPOINT must use http or https".to_owned(),
            ));
        }
        if endpoint.path() != "/" && !endpoint.path().is_empty() {
            return Err(GlobAclError::Parse(
                "GLOBACL_S3_ENDPOINT must not include a path".to_owned(),
            ));
        }
        let host = endpoint
            .host_str()
            .ok_or_else(|| GlobAclError::Parse("GLOBACL_S3_ENDPOINT is missing host".to_owned()))?;
        let port = endpoint.port();
        let port_suffix = port.map(|port| format!(":{port}")).unwrap_or_default();
        let encoded_key = percent_encode_s3_path(key);

        if self.force_path_style {
            let host_header = format!("{host}{port_suffix}");
            let canonical_uri = format!("/{}/{}", self.bucket, encoded_key);
            let url = format!(
                "{}://{}{}",
                endpoint.scheme(),
                host_header,
                canonical_uri
            );
            Ok(S3Address {
                url,
                host: host_header,
                canonical_uri,
            })
        } else {
            let virtual_host = format!("{}.{}{}", self.bucket, host, port_suffix);
            let canonical_uri = format!("/{encoded_key}");
            let url = format!("{}://{}{}", endpoint.scheme(), virtual_host, canonical_uri);
            Ok(S3Address {
                url,
                host: virtual_host,
                canonical_uri,
            })
        }
    }
}

#[derive(Debug)]
struct S3Address {
    url: String,
    host: String,
    canonical_uri: String,
}

fn restore_snapshot_before_load(
    object_store: Option<&ObjectStoreConfig>,
    log_dir: &Path,
    object_dir: &Path,
    manifest_dir: &Path,
    snapshot_path: &Path,
    latest_manifest_path: &Path,
) -> Result<()> {
    let Some(object_store) = object_store else {
        return Ok(());
    };

    if local_source_state_exists(snapshot_path, log_dir) {
        return Ok(());
    }

    match restore_latest_snapshot_from_object_store(
        object_store,
        object_dir,
        manifest_dir,
        latest_manifest_path,
        snapshot_path,
    ) {
        Ok(true) => Ok(()),
        Ok(false) if object_store.allow_empty_bootstrap => Ok(()),
        Ok(false) => Err(GlobAclError::InvalidData(
            "object store is configured but no local source state and no latest remote manifest were found; set GLOBACL_OBJECT_STORE_ALLOW_EMPTY_BOOTSTRAP=1 only for first bootstrap".to_owned(),
        )),
        Err(err) => Err(err),
    }
}

fn restore_latest_snapshot_from_object_store(
    object_store: &ObjectStoreConfig,
    object_dir: &Path,
    manifest_dir: &Path,
    latest_manifest_path: &Path,
    snapshot_path: &Path,
) -> Result<bool> {
    let Some(manifest_payload) = object_store.get_optional(LATEST_MANIFEST_OBJECT)? else {
        return Ok(false);
    };
    let manifest = decode_snapshot_manifest(&manifest_payload)?;
    manifest.validate()?;
    let artifact_payload = object_store.get(&manifest.artifact_object)?;
    let artifact_signature_payload = object_store.get(&manifest.artifact_signature_object)?;
    let manifest_signature_payload = object_store.get(LATEST_MANIFEST_SIGNATURE_OBJECT)?;

    manifest.validate_artifact(&artifact_payload)?;
    let snapshot = decode_snapshot(&artifact_payload)?;
    manifest.validate_snapshot(&snapshot)?;

    let artifact_path = object_dir.join(&manifest.artifact_object);
    write_payload_file(&artifact_path, &artifact_payload)?;
    write_payload_file(signature_path(&artifact_path), &artifact_signature_payload)?;

    let immutable_manifest_path = manifest_dir.join(snapshot_manifest_file_name(&manifest));
    write_payload_file(&immutable_manifest_path, &manifest_payload)?;
    write_payload_file(
        signature_path(&immutable_manifest_path),
        &manifest_signature_payload,
    )?;

    write_payload_file(latest_manifest_path, &manifest_payload)?;
    write_payload_file(
        signature_path(latest_manifest_path),
        &manifest_signature_payload,
    )?;
    write_payload_file(snapshot_path, &artifact_payload)?;
    write_payload_file(signature_path(snapshot_path), &artifact_signature_payload)?;
    Ok(true)
}

fn publish_snapshot_to_object_store(
    object_store: Option<&ObjectStoreConfig>,
    publication: &SnapshotPublication<'_>,
) -> Result<()> {
    let Some(object_store) = object_store else {
        return Ok(());
    };
    object_store.put(
        &publication.manifest.artifact_object,
        publication.artifact_payload,
        "application/octet-stream",
    )?;
    object_store.put(
        &publication.manifest.artifact_signature_object,
        publication.artifact_signature_payload,
        "application/json",
    )?;
    let immutable_manifest_object = snapshot_manifest_object_name(publication.manifest);
    object_store.put(
        &immutable_manifest_object,
        publication.immutable_manifest_payload,
        "application/json",
    )?;
    object_store.put(
        &format!("{immutable_manifest_object}.sig"),
        publication.immutable_manifest_signature_payload,
        "application/json",
    )?;
    object_store.put(
        LATEST_MANIFEST_OBJECT,
        publication.latest_manifest_payload,
        "application/json",
    )?;
    object_store.put(
        LATEST_MANIFEST_SIGNATURE_OBJECT,
        publication.latest_manifest_signature_payload,
        "application/json",
    )
}

fn publish_snapshot_to_object_store_best_effort(
    object_store: Option<&ObjectStoreConfig>,
    publication: &SnapshotPublication<'_>,
) -> Result<()> {
    let Some(store) = object_store else {
        return Ok(());
    };
    let result = publish_snapshot_to_object_store(Some(store), publication);
    match result {
        Ok(()) => Ok(()),
        Err(err) if store.require_upload => Err(err),
        Err(err) => {
            eprintln!("object store snapshot publish failed: {err}");
            Ok(())
        }
    }
}

fn read_file_or_object_store(
    path: &Path,
    object_store: Option<&ObjectStoreConfig>,
    object: &str,
) -> Result<Vec<u8>> {
    match fs::read(path) {
        Ok(body) => Ok(body),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let Some(object_store) = object_store else {
                return Err(err.into());
            };
            let body = object_store.get(object)?;
            write_payload_file(path, &body)?;
            Ok(body)
        }
        Err(err) => Err(err.into()),
    }
}

fn snapshot_manifest_object_name(manifest: &SnapshotManifest) -> String {
    format!("manifests/{}", snapshot_manifest_file_name(manifest))
}

fn snapshot_manifest_file_name(manifest: &SnapshotManifest) -> String {
    format!(
        "epoch_{:020}_seq_{:020}_sha256_{}.manifest",
        manifest.created_at_unix,
        manifest.max_seq,
        &manifest.artifact_sha256[..16]
    )
}

fn local_source_state_exists(snapshot_path: &Path, log_dir: &Path) -> bool {
    if snapshot_path.exists() {
        return true;
    }
    if let Ok(entries) = fs::read_dir(log_dir) {
        for entry in entries.flatten() {
            if entry.file_type().map(|kind| kind.is_file()).unwrap_or(false) {
                return true;
            }
        }
    }
    false
}

fn required_env_any(names: &[&str]) -> Result<String> {
    for name in names {
        if let Ok(value) = env::var(name) {
            if !value.trim().is_empty() {
                return Ok(value.trim().to_owned());
            }
        }
    }
    Err(GlobAclError::Parse(format!(
        "missing required environment variable {}",
        names.join(" or ")
    )))
}

fn validate_s3_bucket(bucket: &str) -> Result<()> {
    if bucket.trim().is_empty() {
        return Err(GlobAclError::InvalidData(
            "GLOBACL_S3_BUCKET cannot be empty".to_owned(),
        ));
    }
    if bucket.contains('/') || bucket.contains('\\') || bucket.contains("..") {
        return Err(GlobAclError::InvalidData(format!(
            "invalid GLOBACL_S3_BUCKET {bucket:?}"
        )));
    }
    if !bucket
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
    {
        return Err(GlobAclError::InvalidData(format!(
            "invalid GLOBACL_S3_BUCKET {bucket:?}"
        )));
    }
    Ok(())
}

fn normalize_object_prefix(value: &str) -> Result<String> {
    let normalized = value.trim().trim_matches('/').to_owned();
    if normalized.is_empty() {
        return Ok(normalized);
    }
    if normalized.contains('\\')
        || normalized.contains("//")
        || normalized
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(GlobAclError::InvalidData(format!(
            "unsafe object store key prefix {value:?}"
        )));
    }
    if !normalized
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '-' | '_'))
    {
        return Err(GlobAclError::InvalidData(format!(
            "unsafe object store key prefix {value:?}"
        )));
    }
    Ok(normalized)
}

fn object_store_status_error<T>(
    method: &str,
    object: &str,
    response: reqwest::blocking::Response,
) -> Result<T> {
    let status = response.status();
    let body = response.text().unwrap_or_else(|_| "<unreadable>".to_owned());
    Err(GlobAclError::InvalidData(format!(
        "object store {method} {object:?} failed with HTTP {status}: {body}"
    )))
}

fn object_store_request_error(err: reqwest::Error) -> GlobAclError {
    GlobAclError::InvalidData(format!("object store request failed: {err}"))
}

fn aws_sigv4_dates(now: SystemTime) -> Result<(String, String)> {
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .map_err(|err| GlobAclError::InvalidData(format!("system time before epoch: {err}")))?
        .as_secs() as i64;
    let (year, month, day, hour, minute, second) = unix_utc_components(seconds);
    Ok((
        format!("{year:04}{month:02}{day:02}"),
        format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z"),
    ))
}

fn unix_utc_components(seconds: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400) as u32;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;
    (year, month, day, hour, minute, second)
}

fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;

    hex_encode_bytes(&sha2::Sha256::digest(bytes))
}

fn aws_sigv4_signature(secret: &[u8], date: &str, region: &str, string_to_sign: &[u8]) -> [u8; 32] {
    let mut signing_secret = b"AWS4".to_vec();
    signing_secret.extend_from_slice(secret);
    let date_key = hmac_sha256(&signing_secret, date.as_bytes());
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, b"s3");
    let signing_key = hmac_sha256(&service_key, b"aws4_request");
    hmac_sha256(&signing_key, string_to_sign)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::Digest;

    let mut key_block = [0u8; 64];
    if key.len() > key_block.len() {
        let digest = sha2::Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut outer_pad = [0x5cu8; 64];
    let mut inner_pad = [0x36u8; 64];
    for index in 0..64 {
        outer_pad[index] ^= key_block[index];
        inner_pad[index] ^= key_block[index];
    }

    let mut inner = sha2::Sha256::new();
    inner.update(inner_pad);
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = sha2::Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    let digest = outer.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn percent_encode_s3_path(path: &str) -> String {
    let mut encoded = String::new();
    for byte in path.as_bytes() {
        match *byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'/' => encoded.push(*byte as char),
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

fn hex_encode_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod object_store_tests {
    use super::*;

    fn test_store() -> ObjectStoreConfig {
        ObjectStoreConfig {
            endpoint: "http://minio:9000".to_owned(),
            region: "us-east-1".to_owned(),
            bucket: "globacl-bucket".to_owned(),
            prefix: "prod/globacl".to_owned(),
            access_key_id: "test-access".to_owned(),
            secret_access_key: "test-secret".to_owned(),
            session_token: None,
            force_path_style: true,
            request_timeout_ms: 1000,
            allow_empty_bootstrap: false,
            require_upload: false,
        }
    }

    #[test]
    fn s3_object_key_applies_prefix() {
        let store = test_store();

        assert_eq!(
            store.object_key("snapshots/a.gacl.sig").expect("object key"),
            "prod/globacl/snapshots/a.gacl.sig"
        );
    }

    #[test]
    fn s3_object_key_rejects_parent_traversal() {
        let store = test_store();

        assert!(store.object_key("../latest.manifest").is_err());
    }

    #[test]
    fn path_style_s3_address_contains_bucket_in_path() {
        let store = test_store();
        let key = store
            .object_key("manifests/latest.manifest")
            .expect("object key");
        let address = store.address_for_key(&key).expect("address");

        assert_eq!(address.host, "minio:9000");
        assert_eq!(
            address.canonical_uri,
            "/globacl-bucket/prod/globacl/manifests/latest.manifest"
        );
        assert_eq!(
            address.url,
            "http://minio:9000/globacl-bucket/prod/globacl/manifests/latest.manifest"
        );
    }

    #[test]
    fn virtual_host_s3_address_contains_bucket_in_host() {
        let mut store = test_store();
        store.force_path_style = false;
        let key = store
            .object_key("manifests/latest.manifest")
            .expect("object key");
        let address = store.address_for_key(&key).expect("address");

        assert_eq!(address.host, "globacl-bucket.minio:9000");
        assert_eq!(
            address.canonical_uri,
            "/prod/globacl/manifests/latest.manifest"
        );
        assert_eq!(
            address.url,
            "http://globacl-bucket.minio:9000/prod/globacl/manifests/latest.manifest"
        );
    }

    #[test]
    fn hmac_sha256_matches_known_vector() {
        let digest = hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog");

        assert_eq!(
            hex_encode_bytes(&digest),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn sigv4_utc_dates_are_stable() {
        let (date, amz_date) = aws_sigv4_dates(UNIX_EPOCH).expect("dates");

        assert_eq!(date, "19700101");
        assert_eq!(amz_date, "19700101T000000Z");
    }
}
