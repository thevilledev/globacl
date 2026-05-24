pub fn parse_form_lines(body: &[u8]) -> Result<HashMap<String, String>> {
    let text = std::str::from_utf8(body)
        .map_err(|err| GlobAclError::Parse(format!("request body is not utf8: {err}")))?;
    let trimmed = text.trim();
    if trimmed.starts_with('{') {
        return json_object_to_string_map(serde_json::from_str(trimmed)?);
    }

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

fn json_object_to_string_map(value: Value) -> Result<HashMap<String, String>> {
    let object = value
        .as_object()
        .ok_or_else(|| GlobAclError::Parse("expected JSON object body".to_owned()))?;
    let mut form = HashMap::new();
    for (key, value) in object {
        form.insert(key.clone(), json_field_to_string(value)?);
    }
    Ok(form)
}

fn json_field_to_string(value: &Value) -> Result<String> {
    Ok(match value {
        Value::Null => String::new(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(value)?,
    })
}

pub fn parse_json_body(body: &[u8]) -> Result<Value> {
    Ok(serde_json::from_slice(body)?)
}

pub fn key_value_body_to_json(body: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(body)
        .map_err(|err| GlobAclError::Parse(format!("response body is not utf8: {err}")))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Value::Object(JsonMap::new()));
    }
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return Ok(serde_json::from_str(trimmed)?);
    }

    let mut root = JsonMap::new();
    let mut items = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((kind, fields)) = parse_key_value_tokens(line) else {
            push_json_array_item(&mut root, "messages", Value::String(line.to_owned()));
            continue;
        };
        if let Some(kind) = kind {
            if kind == "ack" {
                push_json_array_item(&mut root, "acks", Value::Object(fields));
            } else {
                let mut item = fields;
                item.insert("type".to_owned(), Value::String(kind));
                items.push(Value::Object(item));
            }
        } else if fields.len() == 1 {
            for (key, value) in fields {
                insert_json_field(&mut root, key, value);
            }
        } else {
            items.push(Value::Object(fields));
        }
    }
    if !items.is_empty() {
        root.insert("items".to_owned(), Value::Array(items));
    }
    Ok(Value::Object(root))
}

fn parse_key_value_tokens(line: &str) -> Option<(Option<String>, JsonMap<String, Value>)> {
    let mut kind = None;
    let mut fields = JsonMap::new();
    for token in line.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            fields.insert(key.to_owned(), json_scalar(value));
        } else if kind.is_none() && fields.is_empty() {
            kind = Some(token.to_owned());
        } else {
            return None;
        }
    }
    if fields.is_empty() {
        None
    } else {
        Some((kind, fields))
    }
}

fn json_scalar(value: &str) -> Value {
    let trimmed = value.trim();
    match trimmed {
        "true" => return Value::Bool(true),
        "false" => return Value::Bool(false),
        "null" => return Value::Null,
        _ => {}
    }
    if let Ok(value) = trimmed.parse::<u64>() {
        return Value::Number(JsonNumber::from(value));
    }
    if let Ok(value) = trimmed.parse::<i64>() {
        return Value::Number(JsonNumber::from(value));
    }
    Value::String(trimmed.to_owned())
}

fn insert_json_field(root: &mut JsonMap<String, Value>, key: String, value: Value) {
    if let Some(existing) = root.get_mut(&key) {
        match existing {
            Value::Array(values) => values.push(value),
            current => {
                let old = std::mem::replace(current, Value::Null);
                *current = Value::Array(vec![old, value]);
            }
        }
    } else {
        root.insert(key, value);
    }
}

fn push_json_array_item(root: &mut JsonMap<String, Value>, key: &str, value: Value) {
    match root.get_mut(key) {
        Some(Value::Array(values)) => values.push(value),
        Some(existing) => {
            let old = std::mem::replace(existing, Value::Null);
            *existing = Value::Array(vec![old, value]);
        }
        None => {
            root.insert(key.to_owned(), Value::Array(vec![value]));
        }
    }
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

pub fn http_post_json(addr: &str, path: &str, body: &[u8]) -> Result<HttpResponse> {
    http_post_with_content_type(addr, path, "application/json", body)
}

pub fn http_post_with_content_type(
    addr: &str,
    path: &str,
    content_type: &str,
    body: &[u8],
) -> Result<HttpResponse> {
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
    if content_type == "text/plain" {
        let value = key_value_body_to_json(body)?;
        return write_json_response(stream, status_code, &value);
    }
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

pub fn write_json_response(stream: &mut TcpStream, status_code: u16, value: &Value) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    write_http_response(stream, status_code, "application/json", &body)
}

pub fn write_json_response_from_text(
    stream: &mut TcpStream,
    status_code: u16,
    body: &[u8],
) -> Result<()> {
    let value = key_value_body_to_json(body)?;
    write_json_response(stream, status_code, &value)
}

