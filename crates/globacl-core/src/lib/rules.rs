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
    format_payload_signature_with_version(
        key_id,
        DEFAULT_SIGNATURE_KEY_VERSION,
        private_key_hex,
        payload,
    )
}

pub fn format_payload_signature_with_version(
    key_id: &str,
    key_version: u64,
    private_key_hex: &str,
    payload: &[u8],
) -> Result<String> {
    let signature = payload_signature_hex(private_key_hex, payload)?;
    format_payload_signature_from_hex(key_id, key_version, &signature)
}

pub fn format_payload_signature_from_hex(
    key_id: &str,
    key_version: u64,
    signature_hex: &str,
) -> Result<String> {
    let signature = hex_encode(&decode_hex_array::<64>(signature_hex, "ed25519 signature")?);
    Ok(format!(
        "algorithm={SIGNATURE_ALGORITHM}\nkey_id={key_id}\nkey_version={key_version}\nsignature={signature}\n"
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

pub fn parse_payload_signature(body: &[u8]) -> Result<SignatureEnvelope> {
    let form = parse_form_lines(body)?;
    let algorithm = required(&form, "algorithm")?;
    let key_id = required(&form, "key_id")?;
    let key_version = parse_u64(
        form.get("key_version").map(String::as_str),
        0,
        "key_version",
    )?;
    let signature = required(&form, "signature")?;
    Ok(SignatureEnvelope {
        algorithm,
        key_id,
        key_version,
        signature,
    })
}

pub fn verify_payload_signature_with_verifier(
    verifier: &SignatureVerifier,
    payload: &[u8],
    signature_body: &[u8],
) -> Result<()> {
    let envelope = parse_payload_signature(signature_body)?;
    if envelope.algorithm != SIGNATURE_ALGORITHM {
        return Err(GlobAclError::InvalidData(format!(
            "signature algorithm {:?} is not supported",
            envelope.algorithm
        )));
    }
    if envelope.key_version < verifier.min_key_version {
        return Err(GlobAclError::InvalidData(format!(
            "signature key version {} is below required minimum {}",
            envelope.key_version, verifier.min_key_version
        )));
    }
    let key = verifier.keys.get(&envelope.key_id).ok_or_else(|| {
        GlobAclError::InvalidData(format!(
            "signature key_id {:?} is not trusted",
            envelope.key_id
        ))
    })?;
    if envelope.key_version != 0 && key.key_version != 0 && envelope.key_version != key.key_version
    {
        return Err(GlobAclError::InvalidData(format!(
            "signature key version {} does not match trusted key {} version {}",
            envelope.key_version, key.key_id, key.key_version
        )));
    }
    if !verify_payload_signature(&key.public_key_hex, payload, &envelope.signature)? {
        return Err(GlobAclError::InvalidData(
            "payload signature verification failed".to_owned(),
        ));
    }
    Ok(())
}

pub fn parse_signature_public_keys(value: &str) -> Result<Vec<SignatureVerificationKey>> {
    let mut keys = Vec::new();
    for raw_part in value
        .split([',', ';', '\n'])
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let (key_id, rest) = raw_part.split_once(':').ok_or_else(|| {
            GlobAclError::Parse(format!(
                "signature public key entry must be key_id:public_key or key_id:key_version:public_key, got {raw_part:?}"
            ))
        })?;
        let (key_version, public_key) =
            if let Some((maybe_version, public_key)) = rest.split_once(':') {
                match maybe_version.parse::<u64>() {
                    Ok(key_version) => (key_version, public_key),
                    Err(_) => (DEFAULT_SIGNATURE_KEY_VERSION, rest),
                }
            } else {
                (DEFAULT_SIGNATURE_KEY_VERSION, rest)
            };
        let key =
            SignatureVerificationKey::new(key_id.to_owned(), key_version, public_key.to_owned());
        keys.push(key);
    }
    Ok(keys)
}

fn external_payload_signature_hex(
    command: &str,
    key_id: &str,
    key_version: u64,
    payload: &[u8],
) -> Result<String> {
    let mut parts = command.split_whitespace();
    let program = parts.next().ok_or_else(|| {
        GlobAclError::InvalidData("signature external command cannot be empty".to_owned())
    })?;
    let args = parts.collect::<Vec<_>>();
    let mut child = Command::new(program)
        .args(args)
        .env("GLOBACL_SIGNATURE_ALGORITHM", SIGNATURE_ALGORITHM)
        .env("GLOBACL_SIGNATURE_KEY_ID", key_id)
        .env("GLOBACL_SIGNATURE_KEY_VERSION", key_version.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|err| {
            GlobAclError::Io(io::Error::new(
                err.kind(),
                format!("failed to spawn signature external command {program:?}: {err}"),
            ))
        })?;
    child
        .stdin
        .take()
        .ok_or_else(|| {
            GlobAclError::InvalidData("signature external command stdin unavailable".to_owned())
        })?
        .write_all(payload)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(GlobAclError::InvalidData(format!(
            "signature external command exited with status {}",
            output.status
        )));
    }
    let stdout = String::from_utf8(output.stdout).map_err(|err| {
        GlobAclError::InvalidData(format!(
            "signature external command output is not utf8: {err}"
        ))
    })?;
    let signature = stdout.split_whitespace().next().ok_or_else(|| {
        GlobAclError::InvalidData(
            "signature external command did not return a signature".to_owned(),
        )
    })?;
    Ok(hex_encode(&decode_hex_array::<64>(
        signature,
        "ed25519 signature",
    )?))
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

