
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub shard_count: u16,
    pub watermarks: Vec<u64>,
    pub entries: Vec<DenyEntry>,
    pub rules: Vec<RuleEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotManifest {
    pub manifest_version: u16,
    pub format_version: u16,
    pub created_at_unix: u64,
    pub artifact_object: String,
    pub artifact_signature_object: String,
    pub artifact_bytes: u64,
    pub artifact_sha256: String,
    pub shard_count: u16,
    pub entry_count: u64,
    pub rule_count: u64,
    pub max_seq: u64,
    pub watermarks: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureEnvelope {
    pub algorithm: String,
    pub key_id: String,
    pub key_version: u64,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureVerificationKey {
    pub key_id: String,
    pub key_version: u64,
    pub public_key_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureVerifier {
    keys: HashMap<String, SignatureVerificationKey>,
    min_key_version: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureSigner {
    key_id: String,
    key_version: u64,
    provider: SignatureProvider,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SignatureProvider {
    Ed25519PrivateKey(String),
    ExternalCommand(String),
}

impl Snapshot {
    pub fn validate(&self) -> Result<()> {
        if self.watermarks.len() != self.shard_count as usize {
            return Err(GlobAclError::InvalidData(format!(
                "snapshot has {} watermarks for {} shards",
                self.watermarks.len(),
                self.shard_count
            )));
        }
        for entry in &self.entries {
            if entry.shard_id >= self.shard_count {
                return Err(GlobAclError::InvalidData(format!(
                    "entry shard {} is outside shard_count {}",
                    entry.shard_id, self.shard_count
                )));
            }
        }
        for rule in &self.rules {
            if rule.shard_id >= self.shard_count {
                return Err(GlobAclError::InvalidData(format!(
                    "rule shard {} is outside shard_count {}",
                    rule.shard_id, self.shard_count
                )));
            }
        }
        Ok(())
    }
}

impl SnapshotManifest {
    pub fn for_snapshot(
        snapshot: &Snapshot,
        created_at_unix: u64,
        artifact_object: String,
        artifact_bytes: u64,
        artifact_sha256: String,
    ) -> Self {
        let max_seq = snapshot.watermarks.iter().copied().max().unwrap_or(0);
        Self {
            manifest_version: SNAPSHOT_MANIFEST_VERSION,
            format_version: FORMAT_VERSION,
            created_at_unix,
            artifact_signature_object: format!("{artifact_object}.sig"),
            artifact_object,
            artifact_bytes,
            artifact_sha256,
            shard_count: snapshot.shard_count,
            entry_count: snapshot.entries.len() as u64,
            rule_count: snapshot.rules.len() as u64,
            max_seq,
            watermarks: snapshot.watermarks.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.manifest_version != SNAPSHOT_MANIFEST_VERSION {
            return Err(GlobAclError::InvalidData(format!(
                "unsupported snapshot manifest version {}",
                self.manifest_version
            )));
        }
        if self.format_version != FORMAT_VERSION {
            return Err(GlobAclError::InvalidData(format!(
                "unsupported snapshot format version {}",
                self.format_version
            )));
        }
        if self.watermarks.len() != self.shard_count as usize {
            return Err(GlobAclError::InvalidData(format!(
                "manifest has {} watermarks for {} shards",
                self.watermarks.len(),
                self.shard_count
            )));
        }
        if !is_safe_snapshot_object_name(&self.artifact_object) {
            return Err(GlobAclError::InvalidData(format!(
                "unsafe snapshot artifact object {:?}",
                self.artifact_object
            )));
        }
        if self.artifact_signature_object != format!("{}.sig", self.artifact_object) {
            return Err(GlobAclError::InvalidData(
                "snapshot artifact signature object does not match artifact object".to_owned(),
            ));
        }
        if self.artifact_sha256.len() != 64
            || !self
                .artifact_sha256
                .chars()
                .all(|ch| ch.is_ascii_hexdigit())
        {
            return Err(GlobAclError::InvalidData(
                "snapshot artifact sha256 must be 64 hex characters".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_artifact(&self, artifact: &[u8]) -> Result<()> {
        self.validate()?;
        if artifact.len() as u64 != self.artifact_bytes {
            return Err(GlobAclError::InvalidData(format!(
                "snapshot artifact has {} bytes, manifest expected {}",
                artifact.len(),
                self.artifact_bytes
            )));
        }
        let actual_sha256 = snapshot_artifact_sha256_hex(artifact);
        if actual_sha256 != self.artifact_sha256 {
            return Err(GlobAclError::InvalidData(format!(
                "snapshot artifact sha256 mismatch: expected {}, got {}",
                self.artifact_sha256, actual_sha256
            )));
        }
        Ok(())
    }

    pub fn validate_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        self.validate()?;
        snapshot.validate()?;
        if snapshot.shard_count != self.shard_count {
            return Err(GlobAclError::InvalidData(format!(
                "snapshot shard_count {} does not match manifest {}",
                snapshot.shard_count, self.shard_count
            )));
        }
        if snapshot.entries.len() as u64 != self.entry_count {
            return Err(GlobAclError::InvalidData(format!(
                "snapshot entry_count {} does not match manifest {}",
                snapshot.entries.len(),
                self.entry_count
            )));
        }
        if snapshot.rules.len() as u64 != self.rule_count {
            return Err(GlobAclError::InvalidData(format!(
                "snapshot rule_count {} does not match manifest {}",
                snapshot.rules.len(),
                self.rule_count
            )));
        }
        if snapshot.watermarks != self.watermarks {
            return Err(GlobAclError::InvalidData(
                "snapshot watermarks do not match manifest".to_owned(),
            ));
        }
        Ok(())
    }
}

impl SignatureVerificationKey {
    pub fn new(
        key_id: impl Into<String>,
        key_version: u64,
        public_key_hex: impl Into<String>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            key_version,
            public_key_hex: public_key_hex.into(),
        }
    }
}

impl SignatureVerifier {
    pub fn new(keys: Vec<SignatureVerificationKey>, min_key_version: u64) -> Result<Self> {
        if keys.is_empty() {
            return Err(GlobAclError::InvalidData(
                "signature verifier requires at least one public key".to_owned(),
            ));
        }
        let mut by_id = HashMap::new();
        for key in keys {
            if key.key_id.trim().is_empty() {
                return Err(GlobAclError::InvalidData(
                    "signature key_id cannot be empty".to_owned(),
                ));
            }
            decode_hex_array::<32>(&key.public_key_hex, "ed25519 public key")?;
            if by_id.insert(key.key_id.clone(), key).is_some() {
                return Err(GlobAclError::InvalidData(
                    "duplicate signature key_id in verifier".to_owned(),
                ));
            }
        }
        Ok(Self {
            keys: by_id,
            min_key_version,
        })
    }

    pub fn single(
        key_id: impl Into<String>,
        key_version: u64,
        public_key_hex: impl Into<String>,
        min_key_version: u64,
    ) -> Result<Self> {
        Self::new(
            vec![SignatureVerificationKey::new(
                key_id,
                key_version,
                public_key_hex,
            )],
            min_key_version,
        )
    }

    pub fn min_key_version(&self) -> u64 {
        self.min_key_version
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

impl SignatureSigner {
    pub fn ed25519_private_key(
        key_id: impl Into<String>,
        key_version: u64,
        private_key_hex: impl Into<String>,
    ) -> Result<Self> {
        let private_key_hex = private_key_hex.into();
        decode_hex_array::<32>(&private_key_hex, "ed25519 private key")?;
        Ok(Self {
            key_id: key_id.into(),
            key_version,
            provider: SignatureProvider::Ed25519PrivateKey(private_key_hex),
        })
    }

    pub fn external_command(
        key_id: impl Into<String>,
        key_version: u64,
        command: impl Into<String>,
    ) -> Result<Self> {
        let command = command.into();
        if command.split_whitespace().next().is_none() {
            return Err(GlobAclError::InvalidData(
                "signature external command cannot be empty".to_owned(),
            ));
        }
        Ok(Self {
            key_id: key_id.into(),
            key_version,
            provider: SignatureProvider::ExternalCommand(command),
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn key_version(&self) -> u64 {
        self.key_version
    }

    pub fn sign_payload(&self, payload: &[u8]) -> Result<String> {
        let signature = match &self.provider {
            SignatureProvider::Ed25519PrivateKey(private_key_hex) => {
                payload_signature_hex(private_key_hex, payload)?
            }
            SignatureProvider::ExternalCommand(command) => {
                external_payload_signature_hex(command, &self.key_id, self.key_version, payload)?
            }
        };
        format_payload_signature_from_hex(&self.key_id, self.key_version, &signature)
    }
}
