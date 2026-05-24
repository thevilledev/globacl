use arc_swap::ArcSwap;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
pub use serde_json::Value as JsonValue;
use serde_json::{Map as JsonMap, Number as JsonNumber, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
pub const DEFAULT_SIGNATURE_KEY_VERSION: u64 = 1;
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

impl From<serde_json::Error> for GlobAclError {
    fn from(value: serde_json::Error) -> Self {
        GlobAclError::Parse(format!("json error: {value}"))
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

