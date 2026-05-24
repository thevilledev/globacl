pub fn parse_json_fields(body: &[u8]) -> Result<HashMap<String, String>> {
    let text = std::str::from_utf8(body)
        .map_err(|err| GlobAclError::Parse(format!("request body is not utf8: {err}")))?;
    let trimmed = text.trim();
    if !trimmed.starts_with('{') {
        return Err(GlobAclError::Parse("expected JSON object body".to_owned()));
    }
    json_object_to_string_map(serde_json::from_str(trimmed)?)
}

pub fn json_object_to_string_map(value: Value) -> Result<HashMap<String, String>> {
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
    http_get_with_headers(addr, path, &[])
}

pub fn http_get_with_headers(
    addr: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<HttpResponse> {
    let extra_headers = format_extra_headers(headers)?;
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{extra_headers}Connection: close\r\n\r\n");
    send_http(addr, request.as_bytes())
}

pub fn http_post(addr: &str, path: &str, body: &[u8]) -> Result<HttpResponse> {
    http_post_with_headers(addr, path, body, &[])
}

pub fn http_post_with_headers(
    addr: &str,
    path: &str,
    body: &[u8],
    headers: &[(&str, &str)],
) -> Result<HttpResponse> {
    let extra_headers = format_extra_headers(headers)?;
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n",
        body.len(),
        extra_headers
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
    http_post_with_content_type_and_headers(addr, path, content_type, body, &[])
}

pub fn http_post_with_content_type_and_headers(
    addr: &str,
    path: &str,
    content_type: &str,
    body: &[u8],
    headers: &[(&str, &str)],
) -> Result<HttpResponse> {
    let extra_headers = format_extra_headers(headers)?;
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n",
        body.len(),
        extra_headers
    )
    .into_bytes();
    request.extend_from_slice(body);
    send_http(addr, &request)
}

fn format_extra_headers(headers: &[(&str, &str)]) -> Result<String> {
    let mut out = String::new();
    for (name, value) in headers {
        if name.contains('\r')
            || name.contains('\n')
            || name.contains(':')
            || value.contains('\r')
            || value.contains('\n')
        {
            return Err(GlobAclError::Parse(
                "invalid HTTP header name or value".to_owned(),
            ));
        }
        out.push_str(name.trim());
        out.push_str(": ");
        out.push_str(value.trim());
        out.push_str("\r\n");
    }
    Ok(out)
}

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    pub fn bearer_token(&self) -> Option<&str> {
        let value = self.header("authorization")?.trim();
        value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("bearer "))
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn authorization_forward_header(&self) -> Option<(&'static str, &str)> {
        self.header("authorization")
            .map(|value| ("Authorization", value))
    }
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
    pub fn from_json_fields(fields: &HashMap<String, String>) -> Result<Self> {
        Ok(Self {
            agent_id: required(fields, "agent_id")?,
            shard_id: parse_u16(
                fields
                    .get("shard_id")
                    .or_else(|| fields.get("shard"))
                    .map(String::as_str),
                "shard_id",
            )?,
            seq: parse_u64(
                fields
                    .get("seq")
                    .or_else(|| fields.get("watermark"))
                    .map(String::as_str),
                0,
                "seq",
            )?,
            entries: parse_usize(fields.get("entries").map(String::as_str), 0, "entries")?,
            applied_at_unix: parse_u64(
                fields.get("applied_at_unix").map(String::as_str),
                now_unix(),
                "applied_at_unix",
            )?,
        })
    }

    pub fn to_json_body(&self) -> String {
        json!({
            "agent_id": self.agent_id.as_str(),
            "shard_id": self.shard_id,
            "seq": self.seq,
            "entries": self.entries,
            "applied_at_unix": self.applied_at_unix
        })
        .to_string()
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

    pub fn from_json_fields(fields: &HashMap<String, String>) -> Result<Self> {
        Ok(Self {
            relay_id: required(fields, "relay_id")?,
            location: required(fields, "location")?,
            agent_id: required(fields, "agent_id")?,
            shard_id: parse_u16(
                fields
                    .get("shard_id")
                    .or_else(|| fields.get("shard"))
                    .map(String::as_str),
                "shard_id",
            )?,
            seq: parse_u64(
                fields
                    .get("seq")
                    .or_else(|| fields.get("watermark"))
                    .map(String::as_str),
                0,
                "seq",
            )?,
            entries: parse_usize(fields.get("entries").map(String::as_str), 0, "entries")?,
            applied_at_unix: parse_u64(
                fields.get("applied_at_unix").map(String::as_str),
                now_unix(),
                "applied_at_unix",
            )?,
            relay_received_at_unix: parse_u64(
                fields.get("relay_received_at_unix").map(String::as_str),
                now_unix(),
                "relay_received_at_unix",
            )?,
        })
    }

    pub fn key(&self) -> String {
        format!("{}:{}:{}", self.relay_id, self.agent_id, self.shard_id)
    }

    pub fn to_json_body(&self) -> String {
        json!({
            "relay_id": self.relay_id.as_str(),
            "location": self.location.as_str(),
            "agent_id": self.agent_id.as_str(),
            "shard_id": self.shard_id,
            "seq": self.seq,
            "entries": self.entries,
            "applied_at_unix": self.applied_at_unix,
            "relay_received_at_unix": self.relay_received_at_unix
        })
        .to_string()
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
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
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
        headers,
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
        401 => "Unauthorized",
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
