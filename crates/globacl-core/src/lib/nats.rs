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

