use arc_swap::ArcSwap;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const DEFAULT_SHARD_COUNT: u16 = 4096;
pub const SNAPSHOT_MAGIC: &[u8; 4] = b"GACL";
pub const MUTATION_MAGIC: &[u8; 4] = b"GMUT";
pub const MUTATION_STREAM_MAGIC: &[u8; 4] = b"GLOG";
pub const FORMAT_VERSION: u16 = 1;
pub const SNAPSHOT_MANIFEST_VERSION: u16 = 1;
pub const MAX_HTTP_BODY_BYTES: usize = 1024 * 1024;
pub const SIGNATURE_ALGORITHM: &str = "ed25519";
pub const DEFAULT_SIGNATURE_KEY_ID: &str = "dev-ed25519";
pub const DEFAULT_SIGNATURE_PRIVATE_KEY: &str =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
pub const DEFAULT_SIGNATURE_PUBLIC_KEY: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
pub const NEGATIVE_FILTER_BITS_PER_ENTRY: usize = 20;
pub const NEGATIVE_FILTER_HASHES: usize = 8;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryPriority {
    P0,
    P1,
    P2,
}

impl DeliveryPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            DeliveryPriority::P0 => "p0",
            DeliveryPriority::P1 => "p1",
            DeliveryPriority::P2 => "p2",
        }
    }

    pub fn from_name(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "p0" | "emergency" | "emergency_deny" => Ok(DeliveryPriority::P0),
            "p1" | "normal" | "mutation" => Ok(DeliveryPriority::P1),
            "p2" | "repair" | "snapshot" => Ok(DeliveryPriority::P2),
            other => Err(GlobAclError::Parse(format!(
                "unknown delivery priority {other:?}"
            ))),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            DeliveryPriority::P0 => 0,
            DeliveryPriority::P1 => 1,
            DeliveryPriority::P2 => 2,
        }
    }

    fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(DeliveryPriority::P0),
            1 => Ok(DeliveryPriority::P1),
            2 => Ok(DeliveryPriority::P2),
            _ => Err(GlobAclError::InvalidData(format!(
                "unknown delivery priority tag {value}"
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RuleKind {
    Ipv4Cidr,
    DomainSuffix,
}

impl RuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RuleKind::Ipv4Cidr => "ipv4_cidr",
            RuleKind::DomainSuffix => "domain_suffix",
        }
    }

    pub fn from_name(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ip" | "ipv4" | "cidr" | "ipv4_cidr" => Ok(RuleKind::Ipv4Cidr),
            "domain" | "domain_suffix" | "suffix" => Ok(RuleKind::DomainSuffix),
            other => Err(GlobAclError::Parse(format!("unknown rule kind {other:?}"))),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            RuleKind::Ipv4Cidr => 1,
            RuleKind::DomainSuffix => 2,
        }
    }

    fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(RuleKind::Ipv4Cidr),
            2 => Ok(RuleKind::DomainSuffix),
            _ => Err(GlobAclError::InvalidData(format!(
                "unknown rule kind tag {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct RuleKey {
    tenant_id: String,
    kind: RuleKind,
    rule_hash: u64,
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
    pub delivery_priority: DeliveryPriority,
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
        let delivery_priority = form
            .get("delivery_priority")
            .or_else(|| form.get("channel"))
            .or_else(|| form.get("stream"))
            .map(|value| DeliveryPriority::from_name(value))
            .transpose()?
            .unwrap_or(DeliveryPriority::P1);

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
            delivery_priority,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleRequest {
    pub op_id: String,
    pub tenant_id: String,
    pub kind: RuleKind,
    pub pattern: String,
    pub action: Action,
    pub priority: u32,
    pub reason_code: String,
    pub expires_at: u64,
    pub created_by: String,
    pub delivery_priority: DeliveryPriority,
}

impl RuleRequest {
    pub fn from_form(form: &HashMap<String, String>) -> Result<Self> {
        let op_id = required(form, "op_id")?;
        let tenant_id = required(form, "tenant_id")?;
        let kind = RuleKind::from_name(
            form.get("kind")
                .or_else(|| form.get("rule_kind"))
                .map(String::as_str)
                .unwrap_or("ipv4_cidr"),
        )?;
        let pattern = required(form, "pattern")?;
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
        let delivery_priority = form
            .get("delivery_priority")
            .or_else(|| form.get("channel"))
            .or_else(|| form.get("stream"))
            .map(|value| DeliveryPriority::from_name(value))
            .transpose()?
            .unwrap_or(DeliveryPriority::P1);

        Ok(Self {
            op_id,
            tenant_id,
            kind,
            pattern,
            action,
            priority,
            reason_code,
            expires_at,
            created_by,
            delivery_priority,
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
pub struct RuleEntry {
    pub tenant_id: String,
    pub kind: RuleKind,
    pub pattern: String,
    pub rule_hash: u64,
    pub action: Action,
    pub priority: u32,
    pub reason_code: String,
    pub expires_at: u64,
    pub created_by: String,
    pub commit_seq: u64,
    pub shard_id: u16,
    pub ipv4_network: u32,
    pub ipv4_prefix_len: u8,
    pub domain_suffix: String,
}

impl RuleEntry {
    fn rule_key(&self) -> RuleKey {
        RuleKey {
            tenant_id: self.tenant_id.clone(),
            kind: self.kind,
            rule_hash: self.rule_hash,
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
    pub rule: Option<RuleEntry>,
    pub delivery_priority: DeliveryPriority,
    pub committed_at_unix: u64,
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
    rules: HashMap<RuleKey, RuleEntry>,
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
            rules: HashMap::new(),
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
        let outcome = self.prepare_commit(request)?;
        if !outcome.duplicate {
            self.apply_replicated_mutation(outcome.mutation.clone())?;
        }

        Ok(outcome)
    }

    pub fn commit_rule(&mut self, request: RuleRequest) -> Result<CommitOutcome> {
        let outcome = self.prepare_rule_commit(request)?;
        if !outcome.duplicate {
            self.apply_replicated_mutation(outcome.mutation.clone())?;
        }

        Ok(outcome)
    }

    pub fn prepare_commit(&self, request: DenyRequest) -> Result<CommitOutcome> {
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
            rule: None,
            delivery_priority: request.delivery_priority,
            committed_at_unix: now_unix(),
        };

        Ok(CommitOutcome {
            mutation,
            duplicate: false,
        })
    }

    pub fn prepare_rule_commit(&self, request: RuleRequest) -> Result<CommitOutcome> {
        if request.op_id.trim().is_empty() {
            return Err(GlobAclError::Parse("op_id must not be empty".to_owned()));
        }

        if let Some(existing) = self.op_index.get(&request.op_id) {
            return Ok(CommitOutcome {
                mutation: existing.clone(),
                duplicate: true,
            });
        }

        let compiled = compile_rule_pattern(request.kind, &request.pattern)?;
        let rule_hash = stable_key_hash(
            &request.tenant_id,
            request.kind.as_str(),
            &compiled.canonical_pattern,
        );
        let shard_id = shard_for_hash(rule_hash, self.shard_count);
        let seq = self.watermarks[shard_id as usize] + 1;
        let commit_id = CommitId {
            shard_id,
            seq,
            epoch: self.epoch,
            source_region: self.source_region.clone(),
        };
        let entry = DenyEntry {
            tenant_id: request.tenant_id.clone(),
            namespace: format!("__rule:{}", request.kind.as_str()),
            key_hash: rule_hash,
            action: request.action,
            priority: request.priority,
            reason_code: request.reason_code.clone(),
            expires_at: request.expires_at,
            created_by: request.created_by.clone(),
            commit_seq: seq,
            shard_id,
        };
        let rule = RuleEntry {
            tenant_id: request.tenant_id,
            kind: request.kind,
            pattern: compiled.canonical_pattern,
            rule_hash,
            action: request.action,
            priority: request.priority,
            reason_code: request.reason_code,
            expires_at: request.expires_at,
            created_by: request.created_by,
            commit_seq: seq,
            shard_id,
            ipv4_network: compiled.ipv4_network,
            ipv4_prefix_len: compiled.ipv4_prefix_len,
            domain_suffix: compiled.domain_suffix,
        };
        let mutation = Mutation {
            op_id: request.op_id,
            commit_id,
            entry,
            rule: Some(rule),
            delivery_priority: request.delivery_priority,
            committed_at_unix: now_unix(),
        };

        Ok(CommitOutcome {
            mutation,
            duplicate: false,
        })
    }

    pub fn apply_replicated_mutation(&mut self, mutation: Mutation) -> Result<ApplyStatus> {
        if let Some(existing) = self.op_index.get(&mutation.op_id) {
            if existing == &mutation {
                return Ok(ApplyStatus::DuplicateOrOld);
            }
            return Err(GlobAclError::InvalidData(format!(
                "op_id {} already exists with a different mutation",
                mutation.op_id
            )));
        }

        let shard_id = mutation.commit_id.shard_id;
        if shard_id >= self.shard_count {
            return Err(GlobAclError::InvalidData(format!(
                "shard {shard_id} is outside shard_count {}",
                self.shard_count
            )));
        }

        let current_seq = self.watermarks[shard_id as usize];
        if mutation.commit_id.seq <= current_seq {
            let already_applied = self.mutations.iter().any(|existing| {
                existing.commit_id.shard_id == shard_id
                    && existing.commit_id.seq == mutation.commit_id.seq
                    && existing == &mutation
            });
            if already_applied {
                return Ok(ApplyStatus::DuplicateOrOld);
            }
            return Err(GlobAclError::InvalidData(format!(
                "stale or conflicting mutation for shard {shard_id} seq {}",
                mutation.commit_id.seq
            )));
        }

        self.apply_committed_mutation(&mutation)?;
        self.op_index
            .insert(mutation.op_id.clone(), mutation.clone());
        self.mutations.push(mutation);

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

    pub fn check(
        &self,
        tenant_id: &str,
        namespace: &str,
        raw_value: &str,
        now_unix: u64,
    ) -> Decision {
        let point = self.lookup(tenant_id, namespace, raw_value, now_unix);
        if point.is_denied() {
            return point;
        }

        let mut best = RuleMatch::default();
        for rule in self.rules.values() {
            if rule.tenant_id == tenant_id && rule_matches_namespace(rule, namespace, raw_value) {
                best.consider(rule, now_unix);
            }
        }
        best.into_decision()
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

    pub fn restore_snapshot(
        &mut self,
        snapshot: Snapshot,
        op_prefix: &str,
    ) -> Result<Vec<Mutation>> {
        if snapshot.shard_count != self.shard_count {
            return Err(GlobAclError::InvalidData(format!(
                "rollback snapshot has shard_count {}, expected {}",
                snapshot.shard_count, self.shard_count
            )));
        }
        snapshot.validate()?;

        let mut target_entries = HashMap::new();
        for entry in snapshot.entries {
            target_entries.insert(entry.acl_key(), entry);
        }
        let mut target_rules = HashMap::new();
        for rule in snapshot.rules {
            target_rules.insert(rule.rule_key(), rule);
        }

        let mut mutations = Vec::new();
        let mut current_entries = self.entries.values().cloned().collect::<Vec<_>>();
        current_entries.sort_by(compare_entries_by_key);
        for entry in current_entries {
            if !target_entries.contains_key(&entry.acl_key()) {
                let mut delete = entry;
                delete.action = Action::Delete;
                delete.reason_code = "rollback_delete".to_owned();
                delete.expires_at = 0;
                delete.created_by = "globacl-rollback".to_owned();
                mutations.push(self.commit_entry_direct(
                    next_restore_op_id(&self.op_index, op_prefix, mutations.len()),
                    delete,
                )?);
            }
        }

        let mut target_entry_values = target_entries.values().cloned().collect::<Vec<_>>();
        target_entry_values.sort_by(compare_entries_by_key);
        for entry in target_entry_values {
            let key = entry.acl_key();
            if self
                .entries
                .get(&key)
                .map(|current| !entry_semantically_equal(current, &entry))
                .unwrap_or(true)
            {
                mutations.push(self.commit_entry_direct(
                    next_restore_op_id(&self.op_index, op_prefix, mutations.len()),
                    entry,
                )?);
            }
        }

        let mut current_rules = self.rules.values().cloned().collect::<Vec<_>>();
        current_rules.sort_by(compare_rules_by_key);
        for rule in current_rules {
            if !target_rules.contains_key(&rule.rule_key()) {
                let mut delete = rule;
                delete.action = Action::Delete;
                delete.reason_code = "rollback_delete".to_owned();
                delete.expires_at = 0;
                delete.created_by = "globacl-rollback".to_owned();
                mutations.push(self.commit_rule_direct(
                    next_restore_op_id(&self.op_index, op_prefix, mutations.len()),
                    delete,
                )?);
            }
        }

        let mut target_rule_values = target_rules.values().cloned().collect::<Vec<_>>();
        target_rule_values.sort_by(compare_rules_by_key);
        for rule in target_rule_values {
            let key = rule.rule_key();
            if self
                .rules
                .get(&key)
                .map(|current| !rule_semantically_equal(current, &rule))
                .unwrap_or(true)
            {
                mutations.push(self.commit_rule_direct(
                    next_restore_op_id(&self.op_index, op_prefix, mutations.len()),
                    rule,
                )?);
            }
        }

        Ok(mutations)
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            shard_count: self.shard_count,
            watermarks: self.watermarks.clone(),
            entries: self.entries.values().cloned().collect(),
            rules: self.rules.values().cloned().collect(),
        }
    }

    pub fn shard_count(&self) -> u16 {
        self.shard_count
    }

    pub fn watermarks(&self) -> &[u64] {
        &self.watermarks
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch.max(1);
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

        if let Some(rule) = &mutation.rule {
            let key = rule.rule_key();
            match rule.action {
                Action::Delete => {
                    self.rules.remove(&key);
                }
                Action::Deny | Action::AllowOverride => {
                    self.rules.insert(key, rule.clone());
                }
            }
        } else {
            let key = mutation.entry.acl_key();
            match mutation.entry.action {
                Action::Delete => {
                    self.entries.remove(&key);
                }
                Action::Deny | Action::AllowOverride => {
                    self.entries.insert(key, mutation.entry.clone());
                }
            }
        }
        self.watermarks[shard_id as usize] = mutation.commit_id.seq;
        Ok(())
    }

    fn commit_entry_direct(&mut self, op_id: String, mut entry: DenyEntry) -> Result<Mutation> {
        let shard_id = shard_for_hash(entry.key_hash, self.shard_count);
        let seq = self.watermarks[shard_id as usize] + 1;
        entry.shard_id = shard_id;
        entry.commit_seq = seq;
        let mutation = Mutation {
            op_id,
            commit_id: CommitId {
                shard_id,
                seq,
                epoch: self.epoch,
                source_region: self.source_region.clone(),
            },
            entry,
            rule: None,
            delivery_priority: DeliveryPriority::P0,
            committed_at_unix: now_unix(),
        };
        self.apply_committed_mutation(&mutation)?;
        self.op_index
            .insert(mutation.op_id.clone(), mutation.clone());
        self.mutations.push(mutation.clone());
        Ok(mutation)
    }

    fn commit_rule_direct(&mut self, op_id: String, mut rule: RuleEntry) -> Result<Mutation> {
        let shard_id = shard_for_hash(rule.rule_hash, self.shard_count);
        let seq = self.watermarks[shard_id as usize] + 1;
        rule.shard_id = shard_id;
        rule.commit_seq = seq;
        let entry = DenyEntry {
            tenant_id: rule.tenant_id.clone(),
            namespace: format!("__rule:{}", rule.kind.as_str()),
            key_hash: rule.rule_hash,
            action: rule.action,
            priority: rule.priority,
            reason_code: rule.reason_code.clone(),
            expires_at: rule.expires_at,
            created_by: rule.created_by.clone(),
            commit_seq: seq,
            shard_id,
        };
        let mutation = Mutation {
            op_id,
            commit_id: CommitId {
                shard_id,
                seq,
                epoch: self.epoch,
                source_region: self.source_region.clone(),
            },
            entry,
            rule: Some(rule),
            delivery_priority: DeliveryPriority::P0,
            committed_at_unix: now_unix(),
        };
        self.apply_committed_mutation(&mutation)?;
        self.op_index
            .insert(mutation.op_id.clone(), mutation.clone());
        self.mutations.push(mutation.clone());
        Ok(mutation)
    }
}

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

#[derive(Clone, Debug)]
pub struct ActiveState {
    shard_count: u16,
    base: Arc<ImmutableBase>,
    delta_adds: HashMap<AclKey, DenyEntry>,
    delta_removes: HashMap<AclKey, u64>,
    rule_base: Arc<CompiledRules>,
    delta_rule_adds: HashMap<RuleKey, RuleEntry>,
    delta_rule_removes: HashMap<RuleKey, u64>,
    watermarks: Vec<u64>,
}

pub struct ActiveStateHandle {
    state: ArcSwap<ActiveState>,
}

#[derive(Clone, Debug)]
struct ImmutableBase {
    entries: Vec<CompactDenyEntry>,
    symbols: SymbolTable,
    filter: NegativeFilter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompactDenyEntry {
    key_hash: u64,
    expires_at: u64,
    commit_seq: u64,
    priority: u32,
    tenant_id: u32,
    namespace: u32,
    reason_code: u32,
    created_by: u32,
    shard_id: u16,
    action: Action,
}

#[derive(Clone, Debug, Default)]
struct SymbolTable {
    values: Vec<String>,
    ids: HashMap<String, u32>,
}

#[derive(Clone, Debug)]
struct NegativeFilter {
    bits: Vec<u64>,
    bit_len: usize,
}

#[derive(Clone, Debug, Default)]
struct CompiledRules {
    ipv4_by_prefix: Vec<HashMap<(String, u32), Vec<RuleEntry>>>,
    domain_suffixes: HashMap<(String, String), Vec<RuleEntry>>,
    rules_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveStateStats {
    pub base_entries: usize,
    pub delta_adds: usize,
    pub delta_removes: usize,
    pub base_rules: usize,
    pub delta_rule_adds: usize,
    pub delta_rule_removes: usize,
    pub filter_bits: usize,
    pub filter_hashes: usize,
    pub estimated_bytes: usize,
}

impl ActiveStateHandle {
    pub fn new(state: ActiveState) -> Self {
        Self {
            state: ArcSwap::from_pointee(state),
        }
    }

    pub fn from_snapshot(snapshot: Snapshot) -> Result<Self> {
        Ok(Self::new(ActiveState::from_snapshot(snapshot)?))
    }

    pub fn load(&self) -> Arc<ActiveState> {
        self.state.load_full()
    }

    pub fn store(&self, state: ActiveState) {
        self.state.store(Arc::new(state));
    }
}

impl ActiveState {
    pub fn new(shard_count: u16) -> Self {
        let shard_count = shard_count.max(1);
        Self {
            shard_count,
            base: Arc::new(ImmutableBase::from_entries(Vec::new())),
            delta_adds: HashMap::new(),
            delta_removes: HashMap::new(),
            rule_base: Arc::new(CompiledRules::from_rules(Vec::new())),
            delta_rule_adds: HashMap::new(),
            delta_rule_removes: HashMap::new(),
            watermarks: vec![0; shard_count as usize],
        }
    }

    pub fn from_snapshot(snapshot: Snapshot) -> Result<Self> {
        snapshot.validate()?;

        Ok(Self {
            shard_count: snapshot.shard_count,
            base: Arc::new(ImmutableBase::from_entries(snapshot.entries)),
            delta_adds: HashMap::new(),
            delta_removes: HashMap::new(),
            rule_base: Arc::new(CompiledRules::from_rules(snapshot.rules)),
            delta_rule_adds: HashMap::new(),
            delta_rule_removes: HashMap::new(),
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

        if let Some(rule) = &mutation.rule {
            let key = rule.rule_key();
            match rule.action {
                Action::Delete => {
                    self.delta_rule_adds.remove(&key);
                    self.delta_rule_removes.insert(key, mutation.commit_id.seq);
                }
                Action::Deny | Action::AllowOverride => {
                    self.delta_rule_removes.remove(&key);
                    self.delta_rule_adds.insert(key, rule.clone());
                }
            }
        } else {
            let key = mutation.entry.acl_key();
            match mutation.entry.action {
                Action::Delete => {
                    self.delta_adds.remove(&key);
                    self.delta_removes.insert(key, mutation.commit_id.seq);
                }
                Action::Deny | Action::AllowOverride => {
                    self.delta_removes.remove(&key);
                    self.delta_adds.insert(key, mutation.entry.clone());
                }
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
        let key_hash = stable_key_hash(tenant_id, namespace, raw_key);

        if !self.delta_adds.is_empty() || !self.delta_removes.is_empty() {
            let key = AclKey {
                tenant_id: tenant_id.to_owned(),
                namespace: namespace.to_owned(),
                key_hash,
            };
            if let Some(entry) = self.delta_adds.get(&key) {
                return decision_for_entry(Some(entry), now_unix);
            }

            if self.delta_removes.contains_key(&key) {
                return Decision::Allow;
            }
        }

        self.base
            .decision_for_parts(tenant_id, namespace, key_hash, now_unix)
    }

    pub fn check(
        &self,
        tenant_id: &str,
        namespace: &str,
        raw_value: &str,
        now_unix: u64,
    ) -> Decision {
        let point = self.lookup(tenant_id, namespace, raw_value, now_unix);
        if point.is_denied() {
            return point;
        }

        let mut best = RuleMatch::default();
        self.consider_delta_rules(tenant_id, namespace, raw_value, now_unix, &mut best);
        self.rule_base.consider_matches(
            tenant_id,
            namespace,
            raw_value,
            now_unix,
            &self.delta_rule_removes,
            &mut best,
        );
        best.into_decision()
    }

    pub fn snapshot(&self) -> Snapshot {
        let entries = self.materialized_entries();
        let rules = self.materialized_rules();
        Snapshot {
            shard_count: self.shard_count,
            watermarks: self.watermarks.clone(),
            entries,
            rules,
        }
    }

    pub fn shard_count(&self) -> u16 {
        self.shard_count
    }

    pub fn entries_len(&self) -> usize {
        let mut len = self.base.len();
        for key in self.delta_removes.keys() {
            if self.base.contains_key(key) && !self.delta_adds.contains_key(key) {
                len = len.saturating_sub(1);
            }
        }
        for key in self.delta_adds.keys() {
            if !self.base.contains_key(key) {
                len += 1;
            }
        }
        len
    }

    pub fn watermarks(&self) -> &[u64] {
        &self.watermarks
    }

    pub fn stats(&self) -> ActiveStateStats {
        let base_bytes = self.base.estimated_bytes();
        let overlay_bytes = (self.delta_adds.len() * std::mem::size_of::<(AclKey, DenyEntry)>())
            + (self.delta_removes.len() * std::mem::size_of::<(AclKey, u64)>());
        let rule_bytes = self.rule_base.rules_len * std::mem::size_of::<RuleEntry>()
            + (self.delta_rule_adds.len() * std::mem::size_of::<(RuleKey, RuleEntry)>())
            + (self.delta_rule_removes.len() * std::mem::size_of::<(RuleKey, u64)>());

        ActiveStateStats {
            base_entries: self.base.len(),
            delta_adds: self.delta_adds.len(),
            delta_removes: self.delta_removes.len(),
            base_rules: self.rule_base.rules_len,
            delta_rule_adds: self.delta_rule_adds.len(),
            delta_rule_removes: self.delta_rule_removes.len(),
            filter_bits: self.base.filter.bit_len,
            filter_hashes: NEGATIVE_FILTER_HASHES,
            estimated_bytes: base_bytes + overlay_bytes + rule_bytes,
        }
    }

    /// Benchmark/observability probe for the immutable base negative filter.
    ///
    /// A `true` result is approximate and must never be treated as a deny decision
    /// without the exact lookup verification performed by [`Self::lookup`].
    pub fn base_filter_may_contain(&self, tenant_id: &str, namespace: &str, raw_key: &str) -> bool {
        self.base.filter.may_contain_parts(
            tenant_id,
            namespace,
            stable_key_hash(tenant_id, namespace, raw_key),
        )
    }

    pub fn delta_entries_len(&self) -> usize {
        self.delta_adds.len()
            + self.delta_removes.len()
            + self.delta_rule_adds.len()
            + self.delta_rule_removes.len()
    }

    pub fn compact_delta_overlay(&mut self) {
        if self.delta_adds.is_empty()
            && self.delta_removes.is_empty()
            && self.delta_rule_adds.is_empty()
            && self.delta_rule_removes.is_empty()
        {
            return;
        }
        let entries = self.materialized_entries();
        self.base = Arc::new(ImmutableBase::from_entries(entries));
        let rules = self.materialized_rules();
        self.rule_base = Arc::new(CompiledRules::from_rules(rules));
        self.delta_adds.clear();
        self.delta_removes.clear();
        self.delta_rule_adds.clear();
        self.delta_rule_removes.clear();
    }

    fn materialized_entries(&self) -> Vec<DenyEntry> {
        let mut entries = Vec::with_capacity(self.entries_len());
        for entry in self.base.materialized_entries() {
            let key = entry.acl_key();
            if self.delta_removes.contains_key(&key) {
                continue;
            }
            if self.delta_adds.contains_key(&key) {
                continue;
            }
            entries.push(entry);
        }
        entries.extend(self.delta_adds.values().cloned());
        entries
    }

    fn materialized_rules(&self) -> Vec<RuleEntry> {
        let mut rules = self.rule_base.all_rules();
        rules.retain(|rule| {
            let key = rule.rule_key();
            !self.delta_rule_removes.contains_key(&key) && !self.delta_rule_adds.contains_key(&key)
        });
        rules.extend(self.delta_rule_adds.values().cloned());
        rules
    }

    fn consider_delta_rules(
        &self,
        tenant_id: &str,
        namespace: &str,
        raw_value: &str,
        now_unix: u64,
        best: &mut RuleMatch,
    ) {
        for rule in self.delta_rule_adds.values() {
            if rule.tenant_id == tenant_id && rule_matches_namespace(rule, namespace, raw_value) {
                best.consider(rule, now_unix);
            }
        }
    }
}

impl ImmutableBase {
    fn from_entries(mut entries: Vec<DenyEntry>) -> Self {
        entries.sort_by(compare_entries_by_key);

        let mut deduped: Vec<DenyEntry> = Vec::with_capacity(entries.len());
        for entry in entries {
            match deduped.last_mut() {
                Some(last) if same_entry_key(last, &entry) => {
                    if entry.commit_seq >= last.commit_seq {
                        *last = entry;
                    }
                }
                _ => deduped.push(entry),
            }
        }

        let mut symbols = SymbolTable::default();
        let mut compact_entries = Vec::with_capacity(deduped.len());
        for entry in deduped {
            compact_entries.push(CompactDenyEntry::from_entry(entry, &mut symbols));
        }
        compact_entries.sort_by(compare_compact_entries_by_key);

        let filter = NegativeFilter::from_compact_entries(&compact_entries, &symbols);
        Self {
            entries: compact_entries,
            symbols,
            filter,
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn decision_for_parts(
        &self,
        tenant_id: &str,
        namespace: &str,
        key_hash: u64,
        now_unix: u64,
    ) -> Decision {
        let Some(entry) = self.lookup_parts(tenant_id, namespace, key_hash) else {
            return Decision::Allow;
        };
        if entry.is_expired(now_unix) {
            return Decision::Allow;
        }
        match entry.action {
            Action::Deny => Decision::Deny {
                reason_code: self.symbols.get(entry.reason_code).to_owned(),
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

    fn lookup_parts(
        &self,
        tenant_id: &str,
        namespace: &str,
        key_hash: u64,
    ) -> Option<&CompactDenyEntry> {
        if !self
            .filter
            .may_contain_parts(tenant_id, namespace, key_hash)
        {
            return None;
        }
        self.lookup_exact_parts(tenant_id, namespace, key_hash)
    }

    fn lookup_exact_parts(
        &self,
        tenant_id: &str,
        namespace: &str,
        key_hash: u64,
    ) -> Option<&CompactDenyEntry> {
        let tenant_id = self.symbols.id(tenant_id)?;
        let namespace = self.symbols.id(namespace)?;
        self.entries
            .binary_search_by(|entry| {
                compare_compact_entry_to_key(entry, tenant_id, namespace, key_hash)
            })
            .ok()
            .map(|index| &self.entries[index])
    }

    fn contains_key(&self, key: &AclKey) -> bool {
        self.lookup_exact_parts(&key.tenant_id, &key.namespace, key.key_hash)
            .is_some()
    }

    fn materialized_entries(&self) -> Vec<DenyEntry> {
        self.entries
            .iter()
            .map(|entry| entry.to_deny_entry(&self.symbols))
            .collect()
    }

    fn estimated_bytes(&self) -> usize {
        (self.entries.len() * std::mem::size_of::<CompactDenyEntry>())
            + (self.filter.bits.len() * std::mem::size_of::<u64>())
            + self.symbols.estimated_bytes()
    }
}

impl CompactDenyEntry {
    fn from_entry(entry: DenyEntry, symbols: &mut SymbolTable) -> Self {
        Self {
            key_hash: entry.key_hash,
            expires_at: entry.expires_at,
            commit_seq: entry.commit_seq,
            priority: entry.priority,
            tenant_id: symbols.intern(entry.tenant_id),
            namespace: symbols.intern(entry.namespace),
            reason_code: symbols.intern(entry.reason_code),
            created_by: symbols.intern(entry.created_by),
            shard_id: entry.shard_id,
            action: entry.action,
        }
    }

    fn is_expired(self, now_unix: u64) -> bool {
        self.expires_at != 0 && self.expires_at <= now_unix
    }

    fn to_deny_entry(self, symbols: &SymbolTable) -> DenyEntry {
        DenyEntry {
            tenant_id: symbols.get(self.tenant_id).to_owned(),
            namespace: symbols.get(self.namespace).to_owned(),
            key_hash: self.key_hash,
            action: self.action,
            priority: self.priority,
            reason_code: symbols.get(self.reason_code).to_owned(),
            expires_at: self.expires_at,
            created_by: symbols.get(self.created_by).to_owned(),
            commit_seq: self.commit_seq,
            shard_id: self.shard_id,
        }
    }
}

impl SymbolTable {
    fn intern(&mut self, value: String) -> u32 {
        if let Some(id) = self.ids.get(value.as_str()) {
            return *id;
        }
        let id = self.values.len();
        let id = u32::try_from(id).expect("symbol table exceeded u32::MAX entries");
        self.values.push(value.clone());
        self.ids.insert(value, id);
        id
    }

    fn id(&self, value: &str) -> Option<u32> {
        self.ids.get(value).copied()
    }

    fn get(&self, id: u32) -> &str {
        &self.values[id as usize]
    }

    fn estimated_bytes(&self) -> usize {
        let value_bytes = self
            .values
            .iter()
            .map(|value| std::mem::size_of::<String>() + value.capacity())
            .sum::<usize>();
        let index_bytes = self
            .ids
            .keys()
            .map(|value| {
                std::mem::size_of::<String>() + value.capacity() + std::mem::size_of::<u32>()
            })
            .sum::<usize>();
        value_bytes + index_bytes
    }
}

impl NegativeFilter {
    fn from_compact_entries(entries: &[CompactDenyEntry], symbols: &SymbolTable) -> Self {
        if entries.is_empty() {
            return Self {
                bits: Vec::new(),
                bit_len: 0,
            };
        }

        let desired_bits = entries
            .len()
            .saturating_mul(NEGATIVE_FILTER_BITS_PER_ENTRY)
            .max(64);
        let words = desired_bits.div_ceil(64);
        let bit_len = words * 64;
        let mut filter = Self {
            bits: vec![0; words],
            bit_len,
        };

        for entry in entries {
            filter.insert_parts(
                symbols.get(entry.tenant_id),
                symbols.get(entry.namespace),
                entry.key_hash,
            );
        }

        filter
    }

    fn insert_parts(&mut self, tenant_id: &str, namespace: &str, key_hash: u64) {
        let (first, second) = self.hash_pair_parts(tenant_id, namespace, key_hash);
        for index in 0..NEGATIVE_FILTER_HASHES {
            let bit_index = self.bit_index(first, second, index);
            self.bits[bit_index / 64] |= 1u64 << (bit_index % 64);
        }
    }

    fn may_contain_parts(&self, tenant_id: &str, namespace: &str, key_hash: u64) -> bool {
        if self.bit_len == 0 {
            return false;
        }
        let (first, second) = self.hash_pair_parts(tenant_id, namespace, key_hash);
        for index in 0..NEGATIVE_FILTER_HASHES {
            let bit_index = self.bit_index(first, second, index);
            if (self.bits[bit_index / 64] & (1u64 << (bit_index % 64))) == 0 {
                return false;
            }
        }
        true
    }

    fn hash_pair_parts(&self, tenant_id: &str, namespace: &str, key_hash: u64) -> (u64, u64) {
        let seed = fingerprint_acl_key_parts(tenant_id, namespace, key_hash);
        let first = splitmix64(seed);
        let second = splitmix64(seed ^ 0x9e3779b97f4a7c15) | 1;
        (first, second)
    }

    fn bit_index(&self, first: u64, second: u64, index: usize) -> usize {
        let index = index as u64;
        let hash = first
            .wrapping_add(index.wrapping_mul(second))
            .wrapping_add(index.wrapping_mul(index));
        (hash as usize) % self.bit_len
    }
}

impl CompiledRules {
    fn from_rules(rules: Vec<RuleEntry>) -> Self {
        let mut compiled = Self {
            ipv4_by_prefix: vec![HashMap::new(); 33],
            domain_suffixes: HashMap::new(),
            rules_len: 0,
        };

        for rule in rules {
            if rule.action == Action::Delete {
                continue;
            }
            compiled.rules_len += 1;
            match rule.kind {
                RuleKind::Ipv4Cidr => {
                    let key = (rule.tenant_id.clone(), rule.ipv4_network);
                    compiled.ipv4_by_prefix[rule.ipv4_prefix_len as usize]
                        .entry(key)
                        .or_default()
                        .push(rule);
                }
                RuleKind::DomainSuffix => {
                    let key = (rule.tenant_id.clone(), rule.domain_suffix.clone());
                    compiled.domain_suffixes.entry(key).or_default().push(rule);
                }
            }
        }

        for prefix_bucket in &mut compiled.ipv4_by_prefix {
            for rules in prefix_bucket.values_mut() {
                rules.sort_by(compare_rules_for_match);
            }
        }
        for rules in compiled.domain_suffixes.values_mut() {
            rules.sort_by(compare_rules_for_match);
        }

        compiled
    }

    fn consider_matches(
        &self,
        tenant_id: &str,
        namespace: &str,
        raw_value: &str,
        now_unix: u64,
        removed: &HashMap<RuleKey, u64>,
        best: &mut RuleMatch,
    ) {
        match rule_kind_for_namespace(namespace) {
            Some(RuleKind::Ipv4Cidr) => {
                if let Ok(ip) = parse_ipv4_addr(raw_value) {
                    for prefix_len in (0..=32u8).rev() {
                        let network = mask_ipv4(ip, prefix_len);
                        let key = (tenant_id.to_owned(), network);
                        if let Some(rules) = self.ipv4_by_prefix[prefix_len as usize].get(&key) {
                            for rule in rules {
                                if !removed.contains_key(&rule.rule_key()) {
                                    best.consider(rule, now_unix);
                                }
                            }
                        }
                    }
                }
            }
            Some(RuleKind::DomainSuffix) => {
                let Ok(domain) = canonicalize_domain(raw_value) else {
                    return;
                };
                for suffix in domain_suffix_candidates(&domain) {
                    let key = (tenant_id.to_owned(), suffix);
                    if let Some(rules) = self.domain_suffixes.get(&key) {
                        for rule in rules {
                            if !removed.contains_key(&rule.rule_key()) {
                                best.consider(rule, now_unix);
                            }
                        }
                    }
                }
            }
            None => {}
        }
    }

    fn all_rules(&self) -> Vec<RuleEntry> {
        let mut rules = Vec::with_capacity(self.rules_len);
        for prefix_bucket in &self.ipv4_by_prefix {
            for bucket in prefix_bucket.values() {
                rules.extend(bucket.iter().cloned());
            }
        }
        for bucket in self.domain_suffixes.values() {
            rules.extend(bucket.iter().cloned());
        }
        rules
    }
}

#[derive(Default)]
struct RuleMatch {
    rule: Option<RuleEntry>,
}

impl RuleMatch {
    fn consider(&mut self, rule: &RuleEntry, now_unix: u64) {
        if rule.is_expired(now_unix) {
            return;
        }
        match &self.rule {
            Some(current) if compare_rules_for_match(rule, current) != Ordering::Less => {}
            _ => self.rule = Some(rule.clone()),
        }
    }

    fn into_decision(self) -> Decision {
        let Some(rule) = self.rule else {
            return Decision::Allow;
        };

        match rule.action {
            Action::Deny => Decision::Deny {
                reason_code: rule.reason_code,
                priority: rule.priority,
                commit_id: CommitId {
                    shard_id: rule.shard_id,
                    seq: rule.commit_seq,
                    epoch: 1,
                    source_region: String::new(),
                },
            },
            Action::AllowOverride | Action::Delete => Decision::Allow,
        }
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

pub fn payload_signature_hex(private_key_hex: &str, payload: &[u8]) -> Result<String> {
    let private_key = decode_hex_array::<32>(private_key_hex, "ed25519 private key")?;
    let signing_key = SigningKey::from_bytes(&private_key);
    let signature: Signature = signing_key.sign(payload);
    Ok(hex_encode(&signature.to_bytes()))
}

pub fn format_payload_signature(
    key_id: &str,
    private_key_hex: &str,
    payload: &[u8],
) -> Result<String> {
    Ok(format!(
        "algorithm={SIGNATURE_ALGORITHM}\nkey_id={}\nsignature={}\n",
        key_id,
        payload_signature_hex(private_key_hex, payload)?
    ))
}

pub fn verify_payload_signature(
    public_key_hex: &str,
    payload: &[u8],
    signature_hex: &str,
) -> Result<bool> {
    let public_key = decode_hex_array::<32>(public_key_hex, "ed25519 public key")?;
    let signature = decode_hex_array::<64>(signature_hex.trim(), "ed25519 signature")?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|err| GlobAclError::InvalidData(format!("invalid ed25519 public key: {err}")))?;
    let signature = Signature::from_bytes(&signature);
    Ok(verifying_key.verify_strict(payload, &signature).is_ok())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex_array<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
    let trimmed = value
        .trim()
        .strip_prefix("hex:")
        .unwrap_or_else(|| value.trim());
    if trimmed.len() != N * 2 {
        return Err(GlobAclError::Parse(format!(
            "{field} must be {} hex characters, got {}",
            N * 2,
            trimmed.len()
        )));
    }
    let mut out = [0u8; N];
    for (index, slot) in out.iter_mut().enumerate() {
        let offset = index * 2;
        let high = hex_nibble(trimmed.as_bytes()[offset], field)?;
        let low = hex_nibble(trimmed.as_bytes()[offset + 1], field)?;
        *slot = (high << 4) | low;
    }
    Ok(out)
}

fn hex_nibble(byte: u8, field: &str) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(GlobAclError::Parse(format!(
            "{field} contains non-hex byte 0x{byte:02x}"
        ))),
    }
}

pub fn deny_requires_blast_radius_override(request: &DenyRequest) -> bool {
    if request.action != Action::Deny {
        return false;
    }

    let namespace = request.namespace.trim().to_ascii_lowercase();
    let key = request.key.trim().to_ascii_lowercase();
    matches!(namespace.as_str(), "*" | "all" | "global" | "tenant")
        || matches!(key.as_str(), "*" | "all")
}

pub fn rule_requires_blast_radius_override(request: &RuleRequest) -> bool {
    if request.action != Action::Deny {
        return false;
    }

    match request.kind {
        RuleKind::Ipv4Cidr => parse_ipv4_cidr(&request.pattern)
            .map(|(_, prefix_len, _)| prefix_len == 0)
            .unwrap_or(true),
        RuleKind::DomainSuffix => canonicalize_domain(&request.pattern)
            .map(|domain| domain.split('.').count() < 2)
            .unwrap_or(true),
    }
}

fn fingerprint_acl_key_parts(tenant_id: &str, namespace: &str, key_hash: u64) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for chunk in [
        tenant_id.as_bytes(),
        namespace.as_bytes(),
        &key_hash.to_le_bytes(),
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

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    value ^ (value >> 31)
}

fn compare_entries_by_key(left: &DenyEntry, right: &DenyEntry) -> Ordering {
    left.tenant_id
        .cmp(&right.tenant_id)
        .then_with(|| left.namespace.cmp(&right.namespace))
        .then_with(|| left.key_hash.cmp(&right.key_hash))
}

fn same_entry_key(left: &DenyEntry, right: &DenyEntry) -> bool {
    left.tenant_id == right.tenant_id
        && left.namespace == right.namespace
        && left.key_hash == right.key_hash
}

fn compare_compact_entries_by_key(left: &CompactDenyEntry, right: &CompactDenyEntry) -> Ordering {
    left.tenant_id
        .cmp(&right.tenant_id)
        .then_with(|| left.namespace.cmp(&right.namespace))
        .then_with(|| left.key_hash.cmp(&right.key_hash))
}

fn compare_compact_entry_to_key(
    entry: &CompactDenyEntry,
    tenant_id: u32,
    namespace: u32,
    key_hash: u64,
) -> Ordering {
    entry
        .tenant_id
        .cmp(&tenant_id)
        .then_with(|| entry.namespace.cmp(&namespace))
        .then_with(|| entry.key_hash.cmp(&key_hash))
}

struct CompiledRulePattern {
    canonical_pattern: String,
    ipv4_network: u32,
    ipv4_prefix_len: u8,
    domain_suffix: String,
}

fn compile_rule_pattern(kind: RuleKind, pattern: &str) -> Result<CompiledRulePattern> {
    match kind {
        RuleKind::Ipv4Cidr => {
            let (network, prefix_len, canonical) = parse_ipv4_cidr(pattern)?;
            Ok(CompiledRulePattern {
                canonical_pattern: canonical,
                ipv4_network: network,
                ipv4_prefix_len: prefix_len,
                domain_suffix: String::new(),
            })
        }
        RuleKind::DomainSuffix => {
            let suffix = canonicalize_domain(pattern)?;
            Ok(CompiledRulePattern {
                canonical_pattern: suffix.clone(),
                ipv4_network: 0,
                ipv4_prefix_len: 0,
                domain_suffix: suffix,
            })
        }
    }
}

fn parse_ipv4_cidr(pattern: &str) -> Result<(u32, u8, String)> {
    let trimmed = pattern.trim();
    let (addr, prefix) = trimmed.split_once('/').unwrap_or((trimmed, "32"));
    let prefix_len = prefix
        .parse::<u8>()
        .map_err(|err| GlobAclError::Parse(format!("invalid IPv4 CIDR prefix: {err}")))?;
    if prefix_len > 32 {
        return Err(GlobAclError::Parse(format!(
            "IPv4 CIDR prefix {prefix_len} is greater than 32"
        )));
    }
    let ip = parse_ipv4_addr(addr)?;
    let network = mask_ipv4(ip, prefix_len);
    Ok((
        network,
        prefix_len,
        format!("{}/{}", format_ipv4(network), prefix_len),
    ))
}

fn parse_ipv4_addr(value: &str) -> Result<u32> {
    let mut octets = [0u8; 4];
    let mut count = 0usize;
    for part in value.trim().split('.') {
        if count >= 4 {
            return Err(GlobAclError::Parse(format!(
                "invalid IPv4 address {value:?}"
            )));
        }
        octets[count] = part
            .parse::<u8>()
            .map_err(|err| GlobAclError::Parse(format!("invalid IPv4 address {value:?}: {err}")))?;
        count += 1;
    }
    if count != 4 {
        return Err(GlobAclError::Parse(format!(
            "invalid IPv4 address {value:?}"
        )));
    }
    Ok(u32::from_be_bytes(octets))
}

fn format_ipv4(value: u32) -> String {
    let octets = value.to_be_bytes();
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

fn mask_ipv4(value: u32, prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        value & (!0u32 << (32 - prefix_len))
    }
}

fn canonicalize_domain(value: &str) -> Result<String> {
    let mut domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(stripped) = domain.strip_prefix("*.") {
        domain = stripped.to_owned();
    }
    if domain.is_empty() || domain.split('.').any(|label| label.is_empty()) {
        return Err(GlobAclError::Parse(format!(
            "invalid domain suffix {value:?}"
        )));
    }
    Ok(domain)
}

fn domain_suffix_candidates(domain: &str) -> Vec<String> {
    let labels = domain.split('.').collect::<Vec<_>>();
    let mut suffixes = Vec::with_capacity(labels.len());
    for index in 0..labels.len() {
        suffixes.push(labels[index..].join("."));
    }
    suffixes
}

fn rule_kind_for_namespace(namespace: &str) -> Option<RuleKind> {
    match namespace.trim().to_ascii_lowercase().as_str() {
        "ip" | "ipv4" | "ipv4_cidr" => Some(RuleKind::Ipv4Cidr),
        "domain" | "host" | "hostname" | "dns" => Some(RuleKind::DomainSuffix),
        _ => None,
    }
}

fn rule_matches_namespace(rule: &RuleEntry, namespace: &str, raw_value: &str) -> bool {
    if rule_kind_for_namespace(namespace) != Some(rule.kind) {
        return false;
    }

    match rule.kind {
        RuleKind::Ipv4Cidr => parse_ipv4_addr(raw_value)
            .map(|ip| mask_ipv4(ip, rule.ipv4_prefix_len) == rule.ipv4_network)
            .unwrap_or(false),
        RuleKind::DomainSuffix => canonicalize_domain(raw_value)
            .map(|domain| domain_suffix_candidates(&domain).contains(&rule.domain_suffix))
            .unwrap_or(false),
    }
}

fn compare_rules_for_match(left: &RuleEntry, right: &RuleEntry) -> Ordering {
    right
        .priority
        .cmp(&left.priority)
        .then_with(|| action_rank(right.action).cmp(&action_rank(left.action)))
        .then_with(|| right.commit_seq.cmp(&left.commit_seq))
}

fn compare_rules_by_key(left: &RuleEntry, right: &RuleEntry) -> Ordering {
    left.tenant_id
        .cmp(&right.tenant_id)
        .then_with(|| left.kind.as_str().cmp(right.kind.as_str()))
        .then_with(|| left.rule_hash.cmp(&right.rule_hash))
}

fn entry_semantically_equal(left: &DenyEntry, right: &DenyEntry) -> bool {
    left.tenant_id == right.tenant_id
        && left.namespace == right.namespace
        && left.key_hash == right.key_hash
        && left.action == right.action
        && left.priority == right.priority
        && left.reason_code == right.reason_code
        && left.expires_at == right.expires_at
        && left.created_by == right.created_by
}

fn rule_semantically_equal(left: &RuleEntry, right: &RuleEntry) -> bool {
    left.tenant_id == right.tenant_id
        && left.kind == right.kind
        && left.pattern == right.pattern
        && left.rule_hash == right.rule_hash
        && left.action == right.action
        && left.priority == right.priority
        && left.reason_code == right.reason_code
        && left.expires_at == right.expires_at
        && left.created_by == right.created_by
        && left.ipv4_network == right.ipv4_network
        && left.ipv4_prefix_len == right.ipv4_prefix_len
        && left.domain_suffix == right.domain_suffix
}

fn next_restore_op_id(
    op_index: &HashMap<String, Mutation>,
    op_prefix: &str,
    start_index: usize,
) -> String {
    let mut index = start_index;
    loop {
        let candidate = format!("{op_prefix}-{index:06}");
        if !op_index.contains_key(&candidate) {
            return candidate;
        }
        index += 1;
    }
}

fn action_rank(action: Action) -> u8 {
    match action {
        Action::Deny => 2,
        Action::AllowOverride => 1,
        Action::Delete => 0,
    }
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
    let mut out = String::new();
    out.push_str(&format!("manifest_version={}\n", manifest.manifest_version));
    out.push_str(&format!("format_version={}\n", manifest.format_version));
    out.push_str(&format!("created_at_unix={}\n", manifest.created_at_unix));
    out.push_str(&format!("artifact_object={}\n", manifest.artifact_object));
    out.push_str(&format!(
        "artifact_signature_object={}\n",
        manifest.artifact_signature_object
    ));
    out.push_str(&format!("artifact_bytes={}\n", manifest.artifact_bytes));
    out.push_str(&format!("artifact_sha256={}\n", manifest.artifact_sha256));
    out.push_str(&format!("shard_count={}\n", manifest.shard_count));
    out.push_str(&format!("entry_count={}\n", manifest.entry_count));
    out.push_str(&format!("rule_count={}\n", manifest.rule_count));
    out.push_str(&format!("max_seq={}\n", manifest.max_seq));
    for (shard_id, seq) in manifest.watermarks.iter().enumerate() {
        out.push_str(&format!("shard_{shard_id:04}={seq}\n"));
    }
    out.into_bytes()
}

pub fn decode_snapshot_manifest(bytes: &[u8]) -> Result<SnapshotManifest> {
    let form = parse_form_lines(bytes)?;
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

pub fn shard_log_path(log_dir: impl AsRef<Path>, shard_id: u16) -> PathBuf {
    log_dir.as_ref().join(format!("shard_{shard_id:04}.glog"))
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

#[derive(Clone, Debug)]
pub struct NatsMessage {
    pub subject: String,
    pub reply_to: Option<String>,
    pub payload: Vec<u8>,
    pub status: Option<u16>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JetStreamConsumerInfo {
    pub num_pending: u64,
    pub num_ack_pending: u64,
    pub num_redelivered: u64,
    pub num_waiting: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PopAck {
    pub agent_id: String,
    pub shard_id: u16,
    pub seq: u64,
    pub entries: usize,
    pub applied_at_unix: u64,
}

impl PopAck {
    pub fn from_form(form: &HashMap<String, String>) -> Result<Self> {
        Ok(Self {
            agent_id: required(form, "agent_id")?,
            shard_id: parse_u16(
                form.get("shard_id")
                    .or_else(|| form.get("shard"))
                    .map(String::as_str),
                "shard_id",
            )?,
            seq: parse_u64(
                form.get("seq")
                    .or_else(|| form.get("watermark"))
                    .map(String::as_str),
                0,
                "seq",
            )?,
            entries: parse_usize(form.get("entries").map(String::as_str), 0, "entries")?,
            applied_at_unix: parse_u64(
                form.get("applied_at_unix").map(String::as_str),
                now_unix(),
                "applied_at_unix",
            )?,
        })
    }

    pub fn to_form_body(&self) -> String {
        format!(
            "agent_id={}\nshard_id={}\nseq={}\nentries={}\napplied_at_unix={}\n",
            self.agent_id, self.shard_id, self.seq, self.entries, self.applied_at_unix
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropagationAck {
    pub relay_id: String,
    pub location: String,
    pub agent_id: String,
    pub shard_id: u16,
    pub seq: u64,
    pub entries: usize,
    pub applied_at_unix: u64,
    pub relay_received_at_unix: u64,
}

impl PropagationAck {
    pub fn from_pop_ack(
        relay_id: &str,
        location: &str,
        ack: PopAck,
        relay_received_at_unix: u64,
    ) -> Self {
        Self {
            relay_id: relay_id.to_owned(),
            location: location.to_owned(),
            agent_id: ack.agent_id,
            shard_id: ack.shard_id,
            seq: ack.seq,
            entries: ack.entries,
            applied_at_unix: ack.applied_at_unix,
            relay_received_at_unix,
        }
    }

    pub fn from_form(form: &HashMap<String, String>) -> Result<Self> {
        Ok(Self {
            relay_id: required(form, "relay_id")?,
            location: required(form, "location")?,
            agent_id: required(form, "agent_id")?,
            shard_id: parse_u16(
                form.get("shard_id")
                    .or_else(|| form.get("shard"))
                    .map(String::as_str),
                "shard_id",
            )?,
            seq: parse_u64(
                form.get("seq")
                    .or_else(|| form.get("watermark"))
                    .map(String::as_str),
                0,
                "seq",
            )?,
            entries: parse_usize(form.get("entries").map(String::as_str), 0, "entries")?,
            applied_at_unix: parse_u64(
                form.get("applied_at_unix").map(String::as_str),
                now_unix(),
                "applied_at_unix",
            )?,
            relay_received_at_unix: parse_u64(
                form.get("relay_received_at_unix").map(String::as_str),
                now_unix(),
                "relay_received_at_unix",
            )?,
        })
    }

    pub fn key(&self) -> String {
        format!("{}:{}:{}", self.relay_id, self.agent_id, self.shard_id)
    }

    pub fn to_form_body(&self) -> String {
        format!(
            "relay_id={}\nlocation={}\nagent_id={}\nshard_id={}\nseq={}\nentries={}\napplied_at_unix={}\nrelay_received_at_unix={}\n",
            self.relay_id,
            self.location,
            self.agent_id,
            self.shard_id,
            self.seq,
            self.entries,
            self.applied_at_unix,
            self.relay_received_at_unix
        )
    }
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
    if content_length > MAX_HTTP_BODY_BYTES {
        return Err(GlobAclError::Parse(format!(
            "http body too large: {content_length} bytes exceeds {MAX_HTTP_BODY_BYTES}"
        )));
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
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        405 => "Method Not Allowed",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
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

pub fn nats_jetstream_publish(addr: &str, subject: &str, payload: &[u8]) -> Result<()> {
    let inbox = nats_inbox("puback");
    let mut client = NatsConnection::connect(addr)?;
    client.subscribe(&inbox, 1)?;
    client.publish_with_reply(subject, &inbox, payload)?;
    client.flush()?;

    let message = client.read_message_for(&inbox, 5_000)?.ok_or_else(|| {
        GlobAclError::InvalidData(format!(
            "timed out waiting for JetStream publish ack on {subject}"
        ))
    })?;
    let ack = String::from_utf8_lossy(&message.payload);
    if ack.contains("\"error\"") {
        return Err(GlobAclError::InvalidData(format!(
            "JetStream publish ack returned error: {ack}"
        )));
    }
    Ok(())
}

pub fn nats_jetstream_ensure_stream(addr: &str, stream: &str, subjects: &[String]) -> Result<()> {
    let info_subject = format!("$JS.API.STREAM.INFO.{stream}");
    if let Ok(messages) = nats_request(addr, &info_subject, b"", 1, 5_000) {
        if messages
            .first()
            .map(|message| !json_payload_has_error(&message.payload))
            .unwrap_or(false)
        {
            return Ok(());
        }
    }

    let subject_list = subjects
        .iter()
        .map(|subject| format!("\"{}\"", json_escape(subject)))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(
        "{{\"name\":\"{}\",\"subjects\":[{}],\"retention\":\"limits\",\"storage\":\"file\"}}",
        json_escape(stream),
        subject_list
    );
    let create_subject = format!("$JS.API.STREAM.CREATE.{stream}");
    let messages = nats_request(addr, &create_subject, body.as_bytes(), 1, 5_000)?;
    if let Some(message) = messages.first() {
        let payload = String::from_utf8_lossy(&message.payload);
        if json_payload_has_error(&message.payload) && !payload.contains("already") {
            return Err(GlobAclError::InvalidData(format!(
                "JetStream stream create failed: {payload}"
            )));
        }
    }
    Ok(())
}

pub fn nats_jetstream_ensure_consumer(
    addr: &str,
    stream: &str,
    durable: &str,
    filter_subject: &str,
) -> Result<()> {
    let info_subject = format!("$JS.API.CONSUMER.INFO.{stream}.{durable}");
    if let Ok(messages) = nats_request(addr, &info_subject, b"", 1, 5_000) {
        if messages
            .first()
            .map(|message| !json_payload_has_error(&message.payload))
            .unwrap_or(false)
        {
            return Ok(());
        }
    }

    let body = format!(
        "{{\"stream_name\":\"{}\",\"config\":{{\"durable_name\":\"{}\",\"ack_policy\":\"explicit\",\"deliver_policy\":\"all\",\"filter_subject\":\"{}\"}}}}",
        json_escape(stream),
        json_escape(durable),
        json_escape(filter_subject)
    );
    let create_subject = format!("$JS.API.CONSUMER.DURABLE.CREATE.{stream}.{durable}");
    let messages = nats_request(addr, &create_subject, body.as_bytes(), 1, 5_000)?;
    if let Some(message) = messages.first() {
        let payload = String::from_utf8_lossy(&message.payload);
        if json_payload_has_error(&message.payload) && !payload.contains("already") {
            return Err(GlobAclError::InvalidData(format!(
                "JetStream consumer create failed: {payload}"
            )));
        }
    }
    Ok(())
}

pub fn nats_jetstream_consumer_info(
    addr: &str,
    stream: &str,
    durable: &str,
) -> Result<JetStreamConsumerInfo> {
    let info_subject = format!("$JS.API.CONSUMER.INFO.{stream}.{durable}");
    let messages = nats_request(addr, &info_subject, b"", 1, 5_000)?;
    let message = messages.first().ok_or_else(|| {
        GlobAclError::InvalidData(format!(
            "JetStream consumer info returned no response: {stream}.{durable}"
        ))
    })?;
    if json_payload_has_error(&message.payload) {
        return Err(GlobAclError::InvalidData(format!(
            "JetStream consumer info failed: {}",
            String::from_utf8_lossy(&message.payload)
        )));
    }
    Ok(JetStreamConsumerInfo {
        num_pending: json_u64_field(&message.payload, "num_pending").unwrap_or(0),
        num_ack_pending: json_u64_field(&message.payload, "num_ack_pending").unwrap_or(0),
        num_redelivered: json_u64_field(&message.payload, "num_redelivered").unwrap_or(0),
        num_waiting: json_u64_field(&message.payload, "num_waiting").unwrap_or(0),
    })
}

pub fn nats_jetstream_pull(
    addr: &str,
    stream: &str,
    durable: &str,
    batch: usize,
    expires_ms: u64,
) -> Result<Vec<NatsMessage>> {
    let subject = format!("$JS.API.CONSUMER.MSG.NEXT.{stream}.{durable}");
    let expires_ns = expires_ms.saturating_mul(1_000_000).max(1);
    let body = format!("{{\"batch\":{},\"expires\":{expires_ns}}}", batch.max(1));
    let messages = nats_request(
        addr,
        &subject,
        body.as_bytes(),
        batch.max(1),
        expires_ms.saturating_add(1_000).max(2_000),
    )?;
    Ok(messages
        .into_iter()
        .filter(|message| !matches!(message.status, Some(404 | 408 | 409 | 503)))
        .filter(|message| !message.payload.is_empty())
        .collect())
}

pub fn nats_ack(addr: &str, ack_subject: &str) -> Result<()> {
    let mut client = NatsConnection::connect(addr)?;
    client.publish(ack_subject, b"")?;
    client.flush()
}

pub fn nats_request(
    addr: &str,
    subject: &str,
    payload: &[u8],
    max_messages: usize,
    timeout_ms: u64,
) -> Result<Vec<NatsMessage>> {
    let inbox = nats_inbox("req");
    let mut client = NatsConnection::connect(addr)?;
    client.subscribe(&inbox, 1)?;
    client.publish_with_reply(subject, &inbox, payload)?;
    client.flush()?;
    client.read_messages_for(&inbox, max_messages.max(1), timeout_ms)
}

pub fn format_commit_outcome(outcome: &CommitOutcome) -> String {
    let entries_changed = if outcome.duplicate { 0 } else { 1 };
    let mut body = format!(
        "duplicate={}\nshard_id={}\nseq={}\nepoch={}\naction={}\nkey_hash={}\ndelivery_priority={}\ncommitted_at_unix={}\nentries_changed={entries_changed}\n",
        outcome.duplicate,
        outcome.mutation.commit_id.shard_id,
        outcome.mutation.commit_id.seq,
        outcome.mutation.commit_id.epoch,
        outcome.mutation.entry.action.as_str(),
        outcome.mutation.entry.key_hash,
        outcome.mutation.delivery_priority.as_str(),
        outcome.mutation.committed_at_unix
    );
    if let Some(rule) = &outcome.mutation.rule {
        body.push_str(&format!(
            "rule_kind={}\npattern={}\nrule_hash={}\n",
            rule.kind.as_str(),
            rule.pattern,
            rule.rule_hash
        ));
    }
    body
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

pub fn format_watermarks(watermarks: &[u64]) -> String {
    let mut body = format!("shard_count={}\n", watermarks.len());
    for (shard_id, seq) in watermarks.iter().enumerate() {
        body.push_str(&format!("shard_{shard_id:04}={seq}\n"));
    }
    body
}

pub fn parse_watermarks(body: &[u8]) -> Result<Vec<u64>> {
    let form = parse_form_lines(body)?;
    let shard_count = parse_usize(
        form.get("shard_count").map(String::as_str),
        0,
        "shard_count",
    )?;
    let mut watermarks = Vec::with_capacity(shard_count);
    for shard_id in 0..shard_count {
        let key = format!("shard_{shard_id:04}");
        let seq = parse_u64(form.get(&key).map(String::as_str), 0, &key)?;
        watermarks.push(seq);
    }
    Ok(watermarks)
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

enum NatsOp {
    Message(NatsMessage),
    Pong,
    Ok,
}

struct NatsConnection {
    stream: TcpStream,
}

impl NatsConnection {
    fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(normalize_nats_addr(addr))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut client = Self { stream };
        let info = client.read_line()?;
        if !info.starts_with("INFO ") {
            return Err(GlobAclError::Parse(format!(
                "expected NATS INFO line, got {info:?}"
            )));
        }
        client.stream.write_all(
            b"CONNECT {\"verbose\":false,\"pedantic\":false,\"name\":\"globacl\"}\r\nPING\r\n",
        )?;
        client.flush()?;
        loop {
            if matches!(client.read_op()?, NatsOp::Pong) {
                break;
            }
        }
        Ok(client)
    }

    fn subscribe(&mut self, subject: &str, sid: u64) -> Result<()> {
        self.stream
            .write_all(format!("SUB {subject} {sid}\r\n").as_bytes())?;
        self.flush()
    }

    fn publish(&mut self, subject: &str, payload: &[u8]) -> Result<()> {
        self.stream
            .write_all(format!("PUB {subject} {}\r\n", payload.len()).as_bytes())?;
        self.stream.write_all(payload)?;
        self.stream.write_all(b"\r\n")?;
        Ok(())
    }

    fn publish_with_reply(&mut self, subject: &str, reply: &str, payload: &[u8]) -> Result<()> {
        self.stream
            .write_all(format!("PUB {subject} {reply} {}\r\n", payload.len()).as_bytes())?;
        self.stream.write_all(payload)?;
        self.stream.write_all(b"\r\n")?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.stream.write_all(b"PING\r\n")?;
        self.stream.flush()?;
        Ok(())
    }

    fn read_messages_for(
        &mut self,
        subject: &str,
        max_messages: usize,
        timeout_ms: u64,
    ) -> Result<Vec<NatsMessage>> {
        let started = now_unix_millis_for_nats();
        let timeout_ms = timeout_ms.max(1);
        let mut messages = Vec::new();
        while messages.len() < max_messages
            && now_unix_millis_for_nats().saturating_sub(started) <= timeout_ms
        {
            if let Some(message) = self.read_message_for(subject, timeout_ms)? {
                if matches!(message.status, Some(404 | 408 | 409 | 503)) {
                    break;
                }
                messages.push(message);
            } else {
                break;
            }
        }
        Ok(messages)
    }

    fn read_message_for(&mut self, _subject: &str, timeout_ms: u64) -> Result<Option<NatsMessage>> {
        let started = now_unix_millis_for_nats();
        let timeout_ms = timeout_ms.max(1);
        loop {
            if now_unix_millis_for_nats().saturating_sub(started) > timeout_ms {
                return Ok(None);
            }
            match self.read_op() {
                Err(GlobAclError::Io(err))
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None);
                }
                Err(err) => return Err(err),
                Ok(NatsOp::Message(message)) => return Ok(Some(message)),
                Ok(NatsOp::Pong | NatsOp::Ok) => {}
            }
        }
    }

    fn read_op(&mut self) -> Result<NatsOp> {
        loop {
            let line = self.read_line()?;
            if line.is_empty() || line.starts_with("INFO ") {
                continue;
            }
            if line == "+OK" {
                return Ok(NatsOp::Ok);
            }
            if line == "PING" {
                self.stream.write_all(b"PONG\r\n")?;
                self.stream.flush()?;
                continue;
            }
            if line == "PONG" {
                return Ok(NatsOp::Pong);
            }
            if line.starts_with("-ERR") {
                return Err(GlobAclError::InvalidData(format!("NATS error: {line}")));
            }
            if line.starts_with("MSG ") {
                return self.read_msg(&line).map(NatsOp::Message);
            }
            if line.starts_with("HMSG ") {
                return self.read_hmsg(&line).map(NatsOp::Message);
            }
            return Err(GlobAclError::Parse(format!(
                "unsupported NATS protocol line {line:?}"
            )));
        }
    }

    fn read_msg(&mut self, line: &str) -> Result<NatsMessage> {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() != 4 && parts.len() != 5 {
            return Err(GlobAclError::Parse(format!(
                "invalid NATS MSG line {line:?}"
            )));
        }
        let subject = parts[1].to_owned();
        let (reply_to, size_index) = if parts.len() == 5 {
            (Some(parts[3].to_owned()), 4)
        } else {
            (None, 3)
        };
        let size = parts[size_index]
            .parse::<usize>()
            .map_err(|err| GlobAclError::Parse(format!("invalid NATS MSG size: {err}")))?;
        let payload = self.read_payload(size)?;
        Ok(NatsMessage {
            subject,
            reply_to,
            payload,
            status: None,
        })
    }

    fn read_hmsg(&mut self, line: &str) -> Result<NatsMessage> {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() != 5 && parts.len() != 6 {
            return Err(GlobAclError::Parse(format!(
                "invalid NATS HMSG line {line:?}"
            )));
        }
        let subject = parts[1].to_owned();
        let (reply_to, header_index, total_index) = if parts.len() == 6 {
            (Some(parts[3].to_owned()), 4, 5)
        } else {
            (None, 3, 4)
        };
        let header_len = parts[header_index]
            .parse::<usize>()
            .map_err(|err| GlobAclError::Parse(format!("invalid NATS HMSG header size: {err}")))?;
        let total_len = parts[total_index]
            .parse::<usize>()
            .map_err(|err| GlobAclError::Parse(format!("invalid NATS HMSG total size: {err}")))?;
        if header_len > total_len {
            return Err(GlobAclError::Parse(format!(
                "NATS HMSG header size {header_len} exceeds total size {total_len}"
            )));
        }
        let bytes = self.read_payload(total_len)?;
        let status = parse_nats_header_status(&bytes[..header_len]);
        Ok(NatsMessage {
            subject,
            reply_to,
            payload: bytes[header_len..].to_vec(),
            status,
        })
    }

    fn read_payload(&mut self, size: usize) -> Result<Vec<u8>> {
        let mut payload = vec![0u8; size];
        self.stream.read_exact(&mut payload)?;
        let mut crlf = [0u8; 2];
        self.stream.read_exact(&mut crlf)?;
        if crlf != *b"\r\n" {
            return Err(GlobAclError::Parse(
                "NATS payload was not terminated by CRLF".to_owned(),
            ));
        }
        Ok(payload)
    }

    fn read_line(&mut self) -> Result<String> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            self.stream.read_exact(&mut byte)?;
            line.push(byte[0]);
            if line.ends_with(b"\r\n") {
                line.truncate(line.len().saturating_sub(2));
                return String::from_utf8(line)
                    .map_err(|err| GlobAclError::Parse(format!("NATS line is not utf8: {err}")));
            }
            if line.len() > 64 * 1024 {
                return Err(GlobAclError::Parse(
                    "NATS protocol line too large".to_owned(),
                ));
            }
        }
    }
}

fn normalize_nats_addr(addr: &str) -> String {
    addr.trim()
        .strip_prefix("nats://")
        .unwrap_or(addr.trim())
        .split('/')
        .next()
        .unwrap_or(addr.trim())
        .to_owned()
}

fn nats_inbox(kind: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("_INBOX.GLOBACL.{kind}.{}.{nanos}", std::process::id())
}

fn parse_nats_header_status(headers: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(headers).ok()?;
    text.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
}

fn json_payload_has_error(payload: &[u8]) -> bool {
    String::from_utf8_lossy(payload).contains("\"error\"")
}

fn json_u64_field(payload: &[u8], field: &str) -> Option<u64> {
    let text = std::str::from_utf8(payload).ok()?;
    let needle = format!("\"{field}\"");
    let start = text.find(&needle)? + needle.len();
    let rest = text[start..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let digit_count = rest
        .as_bytes()
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digit_count == 0 {
        return None;
    }
    rest[..digit_count].parse::<u64>().ok()
}

fn json_escape(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

fn now_unix_millis_for_nats() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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

fn parse_u16(value: Option<&str>, field: &str) -> Result<u16> {
    match value {
        Some(value) if !value.trim().is_empty() => value
            .trim()
            .parse::<u16>()
            .map_err(|err| GlobAclError::Parse(format!("invalid {field}: {err}"))),
        _ => Err(GlobAclError::Parse(format!(
            "missing required field {field}"
        ))),
    }
}

fn parse_usize(value: Option<&str>, default: usize, field: &str) -> Result<usize> {
    match value {
        Some(value) if !value.trim().is_empty() => value
            .trim()
            .parse::<usize>()
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

fn encode_rule_entry(out: &mut Vec<u8>, rule: &RuleEntry) {
    write_string(out, &rule.tenant_id);
    out.push(rule.kind.to_u8());
    write_string(out, &rule.pattern);
    write_u64(out, rule.rule_hash);
    out.push(rule.action.to_u8());
    write_u32(out, rule.priority);
    write_string(out, &rule.reason_code);
    write_u64(out, rule.expires_at);
    write_string(out, &rule.created_by);
    write_u64(out, rule.commit_seq);
    write_u16(out, rule.shard_id);
    write_u32(out, rule.ipv4_network);
    out.push(rule.ipv4_prefix_len);
    write_string(out, &rule.domain_suffix);
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

fn decode_rule_entry(cursor: &mut Cursor<&[u8]>) -> Result<RuleEntry> {
    Ok(RuleEntry {
        tenant_id: read_string(cursor)?,
        kind: RuleKind::from_u8(read_u8(cursor)?)?,
        pattern: read_string(cursor)?,
        rule_hash: read_u64(cursor)?,
        action: Action::from_u8(read_u8(cursor)?)?,
        priority: read_u32(cursor)?,
        reason_code: read_string(cursor)?,
        expires_at: read_u64(cursor)?,
        created_by: read_string(cursor)?,
        commit_seq: read_u64(cursor)?,
        shard_id: read_u16(cursor)?,
        ipv4_network: read_u32(cursor)?,
        ipv4_prefix_len: read_u8(cursor)?,
        domain_suffix: read_string(cursor)?,
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
    let delivery_priority = if cursor_remaining(cursor) >= 1 {
        DeliveryPriority::from_u8(read_u8(cursor)?)?
    } else {
        DeliveryPriority::P1
    };
    let committed_at_unix = if cursor_remaining(cursor) >= 8 {
        read_u64(cursor)?
    } else {
        0
    };
    let rule = if cursor_remaining(cursor) >= 1 {
        match read_u8(cursor)? {
            0 => None,
            1 => Some(decode_rule_entry(cursor)?),
            value => {
                return Err(GlobAclError::InvalidData(format!(
                    "unknown mutation rule tag {value}"
                )))
            }
        }
    } else {
        None
    };
    Ok(Mutation {
        op_id,
        commit_id: CommitId {
            shard_id,
            seq,
            epoch,
            source_region,
        },
        entry,
        rule,
        delivery_priority,
        committed_at_unix,
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

fn cursor_remaining(cursor: &Cursor<&[u8]>) -> usize {
    cursor
        .get_ref()
        .len()
        .saturating_sub(cursor.position() as usize)
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
            delivery_priority: DeliveryPriority::P1,
        }
    }

    fn rule_request(op_id: &str, kind: RuleKind, pattern: &str, action: Action) -> RuleRequest {
        RuleRequest {
            op_id: op_id.to_owned(),
            tenant_id: "tenant-a".to_owned(),
            kind,
            pattern: pattern.to_owned(),
            action,
            priority: 50,
            reason_code: "rule-test".to_owned(),
            expires_at: 0,
            created_by: "unit-test".to_owned(),
            delivery_priority: DeliveryPriority::P1,
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
    fn prepared_commit_is_not_visible_until_applied() {
        let mut source = SourceOfTruth::new(16, "local");
        let prepared = source
            .prepare_commit(request("op-1", "u1", Action::Deny))
            .unwrap();

        assert_eq!(source.mutations_len(), 0);
        assert_eq!(
            source.lookup("tenant-a", "user", "u1", now_unix()),
            Decision::Allow
        );

        let status = source
            .apply_replicated_mutation(prepared.mutation.clone())
            .unwrap();
        assert_eq!(status, ApplyStatus::Applied);
        assert!(source
            .lookup("tenant-a", "user", "u1", now_unix())
            .is_denied());

        let duplicate = source
            .apply_replicated_mutation(prepared.mutation.clone())
            .unwrap();
        assert_eq!(duplicate, ApplyStatus::DuplicateOrOld);
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
    fn active_state_uses_base_and_delta_overlay() {
        let mut source = SourceOfTruth::new(16, "local");
        source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let mut active = ActiveState::from_snapshot(source.snapshot()).unwrap();

        assert_eq!(active.stats().base_entries, 1);
        assert_eq!(active.stats().delta_adds, 0);
        assert!(active
            .lookup("tenant-a", "user", "u1", now_unix())
            .is_denied());

        let add = source.commit(request("op-2", "u2", Action::Deny)).unwrap();
        active.apply_mutation(&add.mutation).unwrap();

        assert_eq!(active.stats().base_entries, 1);
        assert_eq!(active.stats().delta_adds, 1);
        assert!(active
            .lookup("tenant-a", "user", "u2", now_unix())
            .is_denied());

        active.compact_delta_overlay();
        assert_eq!(active.stats().base_entries, 2);
        assert_eq!(active.stats().delta_adds, 0);
        assert!(active
            .lookup("tenant-a", "user", "u2", now_unix())
            .is_denied());
    }

    #[test]
    fn active_state_exposes_base_filter_probe_for_benchmarks() {
        let mut source = SourceOfTruth::new(16, "local");
        source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let active = ActiveState::from_snapshot(source.snapshot()).unwrap();

        assert_eq!(active.stats().filter_hashes, NEGATIVE_FILTER_HASHES);
        assert!(active.base_filter_may_contain("tenant-a", "user", "u1"));
    }

    #[test]
    fn active_state_handle_loads_and_swaps_rcu_style() {
        let mut source = SourceOfTruth::new(16, "local");
        source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let handle = ActiveStateHandle::from_snapshot(source.snapshot()).unwrap();

        let old_reader = handle.load();
        assert!(old_reader
            .lookup("tenant-a", "user", "u1", now_unix())
            .is_denied());

        handle.store(ActiveState::new(16));

        assert!(old_reader
            .lookup("tenant-a", "user", "u1", now_unix())
            .is_denied());
        assert_eq!(
            handle.load().lookup("tenant-a", "user", "u1", now_unix()),
            Decision::Allow
        );
    }

    #[test]
    fn snapshot_round_trips() {
        let mut source = SourceOfTruth::new(16, "local");
        source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        source.commit(request("op-2", "u2", Action::Deny)).unwrap();
        source
            .commit_rule(rule_request(
                "rule-1",
                RuleKind::Ipv4Cidr,
                "10.0.0.0/8",
                Action::Deny,
            ))
            .unwrap();

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
        assert!(active
            .check("tenant-a", "ip", "10.1.2.3", now_unix())
            .is_denied());
    }

    #[test]
    fn snapshot_manifest_round_trips_and_validates_artifact() {
        let mut source = SourceOfTruth::new(16, "local");
        source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let snapshot = source.snapshot();
        let payload = encode_snapshot(&snapshot);
        let sha256 = snapshot_artifact_sha256_hex(&payload);
        let object = immutable_snapshot_object_name(&snapshot, &sha256);
        let manifest = SnapshotManifest::for_snapshot(
            &snapshot,
            1234,
            object.clone(),
            payload.len() as u64,
            sha256,
        );

        assert!(is_safe_snapshot_object_name(&object));
        let decoded = decode_snapshot_manifest(&encode_snapshot_manifest(&manifest)).unwrap();

        assert_eq!(decoded, manifest);
        decoded.validate_artifact(&payload).unwrap();
        decoded.validate_snapshot(&snapshot).unwrap();
        assert!(decoded.validate_artifact(b"changed").is_err());
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
    fn mutation_priority_round_trips() {
        let mut source = SourceOfTruth::new(16, "local");
        let mut request = request("op-1", "u1", Action::Deny);
        request.delivery_priority = DeliveryPriority::P0;
        let outcome = source.commit(request).unwrap();

        let decoded = decode_mutation(&encode_mutation(&outcome.mutation)).unwrap();

        assert_eq!(decoded.delivery_priority, DeliveryPriority::P0);
        assert_ne!(decoded.committed_at_unix, 0);
    }

    #[test]
    fn ipv4_rule_matches_source_and_active_state() {
        let mut source = SourceOfTruth::new(16, "local");
        let outcome = source
            .commit_rule(rule_request(
                "rule-1",
                RuleKind::Ipv4Cidr,
                "192.168.0.0/16",
                Action::Deny,
            ))
            .unwrap();

        assert!(source
            .check("tenant-a", "ip", "192.168.10.20", now_unix())
            .is_denied());
        assert_eq!(
            source.check("tenant-a", "ip", "192.169.10.20", now_unix()),
            Decision::Allow
        );

        let decoded = decode_mutation(&encode_mutation(&outcome.mutation)).unwrap();
        assert!(decoded.rule.is_some());

        let active = ActiveState::from_snapshot(source.snapshot()).unwrap();
        assert!(active
            .check("tenant-a", "ipv4", "192.168.1.1", now_unix())
            .is_denied());
    }

    #[test]
    fn domain_suffix_rule_matches_subdomains() {
        let mut source = SourceOfTruth::new(16, "local");
        source
            .commit_rule(rule_request(
                "rule-1",
                RuleKind::DomainSuffix,
                "*.Example.COM.",
                Action::Deny,
            ))
            .unwrap();

        let active = ActiveState::from_snapshot(source.snapshot()).unwrap();
        assert!(active
            .check("tenant-a", "domain", "api.example.com", now_unix())
            .is_denied());
        assert!(active
            .check("tenant-a", "domain", "example.com", now_unix())
            .is_denied());
        assert_eq!(
            active.check("tenant-a", "domain", "example.org", now_unix()),
            Decision::Allow
        );
    }

    #[test]
    fn rule_delete_removes_base_rule_through_overlay() {
        let mut source = SourceOfTruth::new(16, "local");
        source
            .commit_rule(rule_request(
                "rule-1",
                RuleKind::Ipv4Cidr,
                "10.0.0.0/8",
                Action::Deny,
            ))
            .unwrap();
        let mut active = ActiveState::from_snapshot(source.snapshot()).unwrap();
        let delete = source
            .commit_rule(rule_request(
                "rule-2",
                RuleKind::Ipv4Cidr,
                "10.0.0.0/8",
                Action::Delete,
            ))
            .unwrap();

        active.apply_mutation(&delete.mutation).unwrap();
        assert_eq!(
            active.check("tenant-a", "ip", "10.1.2.3", now_unix()),
            Decision::Allow
        );
        assert_eq!(active.stats().delta_rule_removes, 1);
    }

    #[test]
    fn blast_radius_helpers_flag_broad_denies() {
        let broad_point = DenyRequest {
            namespace: "tenant".to_owned(),
            key: "*".to_owned(),
            ..request("op-1", "u1", Action::Deny)
        };
        assert!(deny_requires_blast_radius_override(&broad_point));
        assert!(!deny_requires_blast_radius_override(&request(
            "op-2",
            "u1",
            Action::Deny
        )));

        assert!(rule_requires_blast_radius_override(&rule_request(
            "rule-1",
            RuleKind::Ipv4Cidr,
            "0.0.0.0/0",
            Action::Deny,
        )));
        assert!(!rule_requires_blast_radius_override(&rule_request(
            "rule-2",
            RuleKind::Ipv4Cidr,
            "10.0.0.0/8",
            Action::Deny,
        )));
        assert!(rule_requires_blast_radius_override(&rule_request(
            "rule-3",
            RuleKind::DomainSuffix,
            "com",
            Action::Deny,
        )));
        assert!(!rule_requires_blast_radius_override(&rule_request(
            "rule-4",
            RuleKind::DomainSuffix,
            "example.com",
            Action::Deny,
        )));
    }

    #[test]
    fn restore_snapshot_generates_forward_rollback_mutations() {
        let mut source = SourceOfTruth::new(16, "local");
        source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let empty = SourceOfTruth::new(16, "local").snapshot();

        let mutations = source.restore_snapshot(empty, "rollback-test").unwrap();

        assert_eq!(mutations.len(), 1);
        assert_eq!(mutations[0].entry.action, Action::Delete);
        assert_eq!(
            source.lookup("tenant-a", "user", "u1", now_unix()),
            Decision::Allow
        );
        assert_eq!(source.mutations_len(), 2);
    }

    #[test]
    fn payload_signature_verifies_exact_bytes() {
        let payload = b"snapshot-bytes";
        let signature = payload_signature_hex(DEFAULT_SIGNATURE_PRIVATE_KEY, payload).unwrap();

        assert!(
            verify_payload_signature(DEFAULT_SIGNATURE_PUBLIC_KEY, payload, &signature).unwrap()
        );
        assert!(
            !verify_payload_signature(DEFAULT_SIGNATURE_PUBLIC_KEY, b"changed", &signature)
                .unwrap()
        );

        let formatted = format_payload_signature(
            DEFAULT_SIGNATURE_KEY_ID,
            DEFAULT_SIGNATURE_PRIVATE_KEY,
            payload,
        )
        .unwrap();
        assert!(formatted.contains("algorithm=ed25519"));
        assert!(formatted.contains("key_id=dev-ed25519"));
    }

    #[test]
    fn payload_signature_accepts_non_default_keypair() {
        // RFC 8032 Ed25519 test vector 2.
        let private_key = "hex:4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
        let public_key = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
        let payload = [0x72];
        let expected_signature = concat!(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        );

        let signature = payload_signature_hex(private_key, &payload).unwrap();
        assert_eq!(signature, expected_signature);
        assert!(verify_payload_signature(public_key, &payload, &signature).unwrap());
        assert!(
            !verify_payload_signature(DEFAULT_SIGNATURE_PUBLIC_KEY, &payload, &signature).unwrap()
        );

        let formatted = format_payload_signature("custom-ed25519", private_key, &payload).unwrap();
        assert!(formatted.contains("algorithm=ed25519"));
        assert!(formatted.contains("key_id=custom-ed25519"));
        assert!(formatted.contains(expected_signature));
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

    #[test]
    fn delta_bundle_file_round_trips() {
        let root = std::env::temp_dir().join(format!(
            "globacl-core-bundle-test-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let bundle_dir = root.join("bundles");

        let mut source = SourceOfTruth::new(16, "local");
        let one = source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let path = write_delta_bundle_file(
            &bundle_dir,
            one.mutation.commit_id.shard_id,
            one.mutation.commit_id.seq,
            one.mutation.commit_id.seq,
            std::slice::from_ref(&one.mutation),
        )
        .unwrap();

        let decoded = read_delta_bundle_file(path).unwrap();
        assert_eq!(decoded, vec![one.mutation]);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pop_ack_parses_and_formats() {
        let form = parse_form_lines(
            b"agent_id=pop-a\nshard_id=7\nseq=42\nentries=12\napplied_at_unix=1000\n",
        )
        .unwrap();
        let ack = PopAck::from_form(&form).unwrap();

        assert_eq!(ack.agent_id, "pop-a");
        assert_eq!(ack.shard_id, 7);
        assert_eq!(ack.seq, 42);
        assert!(ack.to_form_body().contains("agent_id=pop-a"));
    }

    #[test]
    fn propagation_ack_parses_and_formats() {
        let form = parse_form_lines(
            b"relay_id=relay-a\nlocation=region-a\nagent_id=pop-a\nshard_id=7\nseq=42\nentries=12\napplied_at_unix=1000\nrelay_received_at_unix=1001\n",
        )
        .unwrap();
        let ack = PropagationAck::from_form(&form).unwrap();

        assert_eq!(ack.relay_id, "relay-a");
        assert_eq!(ack.location, "region-a");
        assert_eq!(ack.agent_id, "pop-a");
        assert_eq!(ack.shard_id, 7);
        assert_eq!(ack.seq, 42);
        assert_eq!(ack.key(), "relay-a:pop-a:7");
        assert!(ack.to_form_body().contains("relay_id=relay-a"));
    }

    #[test]
    fn json_u64_field_parses_jetstream_counters() {
        let payload = br#"{"type":"io.nats.jetstream.api.v1.consumer_info_response","num_ack_pending":2,"num_pending":17,"num_redelivered":1,"num_waiting":0}"#;

        assert_eq!(json_u64_field(payload, "num_pending"), Some(17));
        assert_eq!(json_u64_field(payload, "num_ack_pending"), Some(2));
        assert_eq!(json_u64_field(payload, "num_redelivered"), Some(1));
        assert_eq!(json_u64_field(payload, "num_waiting"), Some(0));
        assert_eq!(json_u64_field(payload, "missing"), None);
    }

    #[test]
    fn watermarks_round_trip() {
        let watermarks = vec![0, 7, 42];
        let decoded = parse_watermarks(format_watermarks(&watermarks).as_bytes()).unwrap();
        assert_eq!(decoded, watermarks);
    }
}
