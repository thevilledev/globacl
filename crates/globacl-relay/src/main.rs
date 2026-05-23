use globacl_core::{
    http_get, http_post, read_http_request, write_http_response, GlobAclError, Result,
};
use std::env;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

struct App {
    control_addr: String,
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let control_addr = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:7000".to_owned());
    let bind_addr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:7001");
    let app = Arc::new(App { control_addr });

    let listener = TcpListener::bind(bind_addr)?;
    eprintln!(
        "globacl-relay listening on {bind_addr}; control_addr={}",
        app.control_addr
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
    let content_type =
        if request.path.starts_with("/v1/mutations") || request.path.starts_with("/v1/snapshot") {
            "application/octet-stream"
        } else {
            "text/plain"
        };

    match request.method.as_str() {
        "GET" if request.path == "/health" => {
            let upstream = http_get(&app.control_addr, "/health")?;
            let status = if upstream.status_code == 200 {
                "status=ok\nrole=relay\nupstream=ok\n"
            } else {
                "status=degraded\nrole=relay\nupstream=bad\n"
            };
            write_http_response(&mut stream, 200, "text/plain", status.as_bytes())?;
        }
        "GET" => {
            let upstream = http_get(&app.control_addr, &request.path)?;
            write_http_response(
                &mut stream,
                upstream.status_code,
                content_type,
                &upstream.body,
            )?;
        }
        "POST" => {
            let upstream = http_post(&app.control_addr, &request.path, &request.body)?;
            write_http_response(
                &mut stream,
                upstream.status_code,
                content_type,
                &upstream.body,
            )?;
        }
        method => {
            return Err(GlobAclError::Parse(format!(
                "unsupported relay method {method}"
            )));
        }
    }

    Ok(())
}
