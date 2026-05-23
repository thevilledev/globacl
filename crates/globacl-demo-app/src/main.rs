use globacl_core::{
    http_get, parse_form_lines, parse_query_path, read_http_request, write_http_response,
    GlobAclError, Result,
};
use std::env;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

struct App {
    agent_addr: String,
}

fn main() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    let agent_addr = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:7002".to_owned());
    let bind_addr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:8080");
    let app = Arc::new(App { agent_addr });

    let listener = TcpListener::bind(bind_addr)?;
    eprintln!(
        "globacl-demo-app listening on {bind_addr}; agent_addr={}",
        app.agent_addr
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let app = Arc::clone(&app);
                thread::spawn(move || {
                    if let Err(err) = handle_connection(stream, app) {
                        eprintln!("request failed: {err}");
                    }
                });
            }
            Err(err) => eprintln!("accept failed: {err}"),
        }
    }

    Ok(())
}

fn handle_connection(mut stream: TcpStream, app: Arc<App>) -> Result<()> {
    let request = read_http_request(&mut stream)?;
    let (route, query) = parse_query_path(&request.path);

    match (request.method.as_str(), route.as_str()) {
        ("GET", "/health") => {
            let body = format!("status=ok\nagent_addr={}\n", app.agent_addr);
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        ("GET", "/access") => {
            let tenant_id = required_query(&query, "tenant_id")?;
            let namespace = required_query(&query, "namespace")?;
            let key = required_query(&query, "key")?;
            let agent_path = format!(
                "/v1/lookup?tenant_id={}&namespace={}&key={}",
                percent_encode(tenant_id),
                percent_encode(namespace),
                percent_encode(key)
            );
            proxy_acl_decision(&mut stream, &app.agent_addr, &agent_path)?;
        }
        ("GET", "/check") => {
            let tenant_id = required_query(&query, "tenant_id")?;
            let namespace = required_query(&query, "namespace")?;
            let value = query
                .get("value")
                .or_else(|| query.get("key"))
                .map(String::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| GlobAclError::Parse("missing query parameter value".to_owned()))?;
            let agent_path = format!(
                "/v1/check?tenant_id={}&namespace={}&value={}",
                percent_encode(tenant_id),
                percent_encode(namespace),
                percent_encode(value)
            );
            proxy_acl_decision(&mut stream, &app.agent_addr, &agent_path)?;
        }
        _ => {
            write_http_response(&mut stream, 404, "text/plain", b"not found\n")?;
        }
    }

    Ok(())
}

fn proxy_acl_decision(stream: &mut TcpStream, agent_addr: &str, agent_path: &str) -> Result<()> {
    let response = http_get(agent_addr, agent_path)?;
    if response.status_code != 200 {
        let body = format!("access=error\nagent_status={}\n", response.status_code);
        write_http_response(stream, 502, "text/plain", body.as_bytes())?;
        return Ok(());
    }

    let form = parse_form_lines(&response.body)?;
    let denied = form.get("decision").map(String::as_str) == Some("deny");
    let status = if denied { 403 } else { 200 };
    let access = if denied { "denied" } else { "allowed" };
    let mut body = format!("access={access}\n");
    body.push_str(&String::from_utf8_lossy(&response.body));
    write_http_response(stream, status, "text/plain", body.as_bytes())?;
    Ok(())
}

fn required_query<'a>(
    query: &'a std::collections::HashMap<String, String>,
    key: &str,
) -> Result<&'a str> {
    query
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| GlobAclError::Parse(format!("missing query parameter {key}")))
}

fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
