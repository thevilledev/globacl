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

