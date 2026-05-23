use globacl_core::{
    deny_requires_blast_radius_override, http_get, http_post, parse_form_lines, parse_query_path,
    read_http_request, rule_requires_blast_radius_override, write_http_response, DenyRequest,
    GlobAclError, Result, RuleRequest,
};
use std::env;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

struct App {
    commit_addr: String,
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let commit_addr = args
        .get(1)
        .cloned()
        .or_else(|| env::var("GLOBACL_COMMITD_ADDR").ok())
        .unwrap_or_else(|| "127.0.0.1:7003".to_owned());
    let bind_addr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:7000");
    let app = Arc::new(App { commit_addr });

    let listener = TcpListener::bind(bind_addr)?;
    eprintln!(
        "globacl-control listening on {bind_addr}; commit_addr={}",
        app.commit_addr
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
    let (route, _) = parse_query_path(&request.path);

    match (request.method.as_str(), route.as_str()) {
        ("GET", "/health") => {
            let (status_code, body) = match http_get(&app.commit_addr, "/health") {
                Ok(response) if response.status_code == 200 => {
                    (200, format!(
                        "status=ok\nrole=control\ncommitd=ok\ncommit_addr={}\n",
                        app.commit_addr
                    ))
                }
                Ok(response) => {
                    (503, format!(
                        "status=degraded\nrole=control\ncommitd=bad\ncommit_addr={}\ncommit_status={}\n",
                        app.commit_addr, response.status_code
                    ))
                }
                Err(err) => {
                    (503, format!(
                        "status=degraded\nrole=control\ncommitd=unreachable\ncommit_addr={}\nerror={err}\n",
                        app.commit_addr
                    ))
                }
            };
            write_http_response(&mut stream, status_code, "text/plain", body.as_bytes())?;
        }
        ("POST", "/v1/deny") | ("POST", "/v1/mutation") => {
            let form = parse_form_lines(&request.body)?;
            let deny_request = DenyRequest::from_form(&form)?;
            if deny_requires_blast_radius_override(&deny_request)
                && !blast_radius_override_enabled(&form)
            {
                write_http_response(
                    &mut stream,
                    400,
                    "text/plain",
                    b"status=rejected\nreason=blast_radius_override_required\n",
                )?;
                return Ok(());
            }
            proxy_post(&mut stream, &app, &request.path, &request.body)?;
        }
        ("POST", "/v1/rule") => {
            let form = parse_form_lines(&request.body)?;
            let rule_request = RuleRequest::from_form(&form)?;
            if rule_requires_blast_radius_override(&rule_request)
                && !blast_radius_override_enabled(&form)
            {
                write_http_response(
                    &mut stream,
                    400,
                    "text/plain",
                    b"status=rejected\nreason=blast_radius_override_required\n",
                )?;
                return Ok(());
            }
            proxy_post(&mut stream, &app, &request.path, &request.body)?;
        }
        ("GET", _) => proxy_get(&mut stream, &app, &request.path)?,
        ("POST", _) => proxy_post(&mut stream, &app, &request.path, &request.body)?,
        (method, _) => {
            return Err(GlobAclError::Parse(format!(
                "unsupported control method {method}"
            )));
        }
    }

    Ok(())
}

fn proxy_get(stream: &mut TcpStream, app: &App, path: &str) -> Result<()> {
    match http_get(&app.commit_addr, path) {
        Ok(response) => write_http_response(
            stream,
            response.status_code,
            content_type_for(path),
            &response.body,
        ),
        Err(err) => write_proxy_error(stream, err),
    }
}

fn proxy_post(stream: &mut TcpStream, app: &App, path: &str, body: &[u8]) -> Result<()> {
    match http_post(&app.commit_addr, path, body) {
        Ok(response) => write_http_response(
            stream,
            response.status_code,
            content_type_for(path),
            &response.body,
        ),
        Err(err) => write_proxy_error(stream, err),
    }
}

fn write_proxy_error(stream: &mut TcpStream, err: GlobAclError) -> Result<()> {
    let body = format!("status=unavailable\nreason=commitd_proxy_failed\nerror={err}\n");
    write_http_response(stream, 503, "text/plain", body.as_bytes())
}

fn content_type_for(path: &str) -> &'static str {
    if path.ends_with(".sig") {
        "text/plain"
    } else if path.starts_with("/v1/mutations")
        || path.starts_with("/v1/snapshot")
        || path.starts_with("/v1/delta_bundle")
    {
        "application/octet-stream"
    } else {
        "text/plain"
    }
}

fn blast_radius_override_enabled(form: &std::collections::HashMap<String, String>) -> bool {
    form.get("override_blast_radius")
        .or_else(|| form.get("blast_radius_override"))
        .or_else(|| form.get("two_person_approved"))
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}
