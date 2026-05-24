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

pub(crate) fn run() -> Result<()> {
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

