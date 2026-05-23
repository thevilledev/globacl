use globacl_core::{
    http_get, http_post, now_unix, parse_form_lines, read_http_request, write_http_response,
    GlobAclError, PopAck, Result,
};
use std::collections::HashMap;
use std::env;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

struct App {
    control_addr: String,
    relay_id: String,
    location: String,
    acks: Mutex<HashMap<String, PopAck>>,
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let control_addr = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:7000".to_owned());
    let bind_addr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:7001");
    let relay_id = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "relay-local".to_owned());
    let location = args.get(4).cloned().unwrap_or_else(|| "local".to_owned());
    let app = Arc::new(App {
        control_addr,
        relay_id,
        location,
        acks: Mutex::new(HashMap::new()),
    });

    let listener = TcpListener::bind(bind_addr)?;
    eprintln!(
        "globacl-relay listening on {bind_addr}; relay_id={}; location={}; upstream={}",
        app.relay_id, app.location, app.control_addr
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
    let content_type = if request.path.starts_with("/v1/mutations")
        || request.path.starts_with("/v1/snapshot")
        || request.path.starts_with("/v1/delta_bundle")
    {
        "application/octet-stream"
    } else {
        "text/plain"
    };

    match request.method.as_str() {
        "GET" if request.path == "/health" => {
            let upstream = http_get(&app.control_addr, "/health")?;
            let ack_count = lock_acks(&app)?.len();
            let status = if upstream.status_code == 200 {
                format!(
                    "status=ok\nrole=relay\nrelay_id={}\nlocation={}\nupstream=ok\nack_count={ack_count}\n",
                    app.relay_id, app.location
                )
            } else {
                format!(
                    "status=degraded\nrole=relay\nrelay_id={}\nlocation={}\nupstream=bad\nack_count={ack_count}\n",
                    app.relay_id, app.location
                )
            };
            write_http_response(&mut stream, 200, "text/plain", status.as_bytes())?;
        }
        "GET" if request.path == "/v1/acks" => {
            let body = format_acks(&app)?;
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        "POST" if request.path == "/v1/ack" => {
            let form = parse_form_lines(&request.body)?;
            let ack = PopAck::from_form(&form)?;
            let key = format!("{}:{}", ack.agent_id, ack.shard_id);
            lock_acks(&app)?.insert(key, ack);
            write_http_response(&mut stream, 200, "text/plain", b"status=ok\n")?;
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

fn lock_acks(app: &App) -> Result<std::sync::MutexGuard<'_, HashMap<String, PopAck>>> {
    app.acks
        .lock()
        .map_err(|_| GlobAclError::InvalidData("ack lock poisoned".to_owned()))
}

fn format_acks(app: &App) -> Result<String> {
    let now = now_unix();
    let mut acks = lock_acks(app)?.values().cloned().collect::<Vec<_>>();
    acks.sort_by(|left, right| {
        left.agent_id
            .cmp(&right.agent_id)
            .then(left.shard_id.cmp(&right.shard_id))
    });

    let mut body = format!(
        "relay_id={}\nlocation={}\nack_count={}\n",
        app.relay_id,
        app.location,
        acks.len()
    );
    for ack in acks {
        let lag_secs = now.saturating_sub(ack.applied_at_unix);
        body.push_str(&format!(
            "ack agent_id={} shard_id={} seq={} entries={} applied_at_unix={} lag_secs={}\n",
            ack.agent_id, ack.shard_id, ack.seq, ack.entries, ack.applied_at_unix, lag_secs
        ));
    }
    Ok(body)
}
