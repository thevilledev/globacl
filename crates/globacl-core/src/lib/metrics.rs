pub const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

pub fn metrics_bind_addr_from_env(env_key: &str, default_addr: &str) -> Option<String> {
    let value = std::env::var(env_key).unwrap_or_else(|_| default_addr.to_owned());
    let trimmed = value.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "" | "off" | "false" | "disabled" | "none" => None,
        _ => Some(trimmed.to_owned()),
    }
}

pub fn spawn_prometheus_metrics_listener<F>(
    bind_addr: Option<String>,
    format_metrics: F,
) -> Result<()>
where
    F: Fn() -> Result<String> + Send + Sync + 'static,
{
    let Some(bind_addr) = bind_addr else {
        return Ok(());
    };
    let listener = std::net::TcpListener::bind(&bind_addr)?;
    let formatter = std::sync::Arc::new(format_metrics);
    eprintln!("prometheus metrics listening on {bind_addr}");

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if let Err(err) =
                        handle_prometheus_metrics_connection(stream, formatter.as_ref())
                    {
                        eprintln!("metrics request failed: {err}");
                    }
                }
                Err(err) => eprintln!("metrics accept failed: {err}"),
            }
        }
    });

    Ok(())
}

fn handle_prometheus_metrics_connection(
    mut stream: TcpStream,
    format_metrics: &(dyn Fn() -> Result<String> + Send + Sync),
) -> Result<()> {
    let request = read_http_request(&mut stream)?;
    let (route, _) = parse_query_path(&request.path);
    if request.method == "GET" && route == "/metrics" {
        let body = format_metrics()?;
        write_prometheus_response(&mut stream, &body)?;
    } else {
        write_http_response(&mut stream, 404, PROMETHEUS_CONTENT_TYPE, b"not found\n")?;
    }
    Ok(())
}

pub fn write_prometheus_response(stream: &mut TcpStream, body: &str) -> Result<()> {
    write_http_response(stream, 200, PROMETHEUS_CONTENT_TYPE, body.as_bytes())
}

pub fn append_prometheus_metric(
    out: &mut String,
    name: &str,
    help: &str,
    metric_type: &str,
    labels: &[(&str, &str)],
    value: impl std::fmt::Display,
) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push(' ');
    out.push_str(metric_type);
    out.push('\n');
    out.push_str(name);
    out.push_str(&prometheus_labels(labels));
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

pub fn prometheus_bool(value: bool) -> u8 {
    if value {
        1
    } else {
        0
    }
}

pub fn prometheus_labels(labels: &[(&str, &str)]) -> String {
    if labels.is_empty() {
        return String::new();
    }

    let mut out = String::from("{");
    for (idx, (name, value)) in labels.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(name);
        out.push_str("=\"");
        out.push_str(&prometheus_label_value(value));
        out.push('"');
    }
    out.push('}');
    out
}

pub fn prometheus_label_value(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}
