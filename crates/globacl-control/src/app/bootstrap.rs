use globacl_core::{
    append_prometheus_metric, auth_config_from_env_var, deny_requires_blast_radius_override,
    http_get, http_get_with_headers, http_post_with_headers, json, metrics_bind_addr_from_env,
    parse_json_fields, parse_query_path, prometheus_bool, read_http_request,
    rule_requires_blast_radius_override, spawn_prometheus_metrics_listener,
    write_auth_failure_response, write_http_response, write_json_response, AuthConfig,
    AuthPrincipal, DenyRequest, GlobAclError, HttpRequest, Result, RuleRequest,
};
use std::env;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

struct App {
    commit_addr: String,
    auth: AuthConfig,
}

pub(crate) fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let commit_addr = args
        .get(1)
        .cloned()
        .or_else(|| env::var("GLOBACL_COMMITD_ADDR").ok())
        .unwrap_or_else(|| "127.0.0.1:7003".to_owned());
    let bind_addr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:7000");
    let auth = auth_config_from_env_var("GLOBACL_AUTH_TOKENS")?;
    let app = Arc::new(App { commit_addr, auth });

    {
        let app = Arc::clone(&app);
        spawn_prometheus_metrics_listener(
            metrics_bind_addr_from_env("GLOBACL_CONTROL_METRICS_ADDR", "127.0.0.1:9100"),
            move || Ok(format_control_metrics(&app)),
        )?;
    }

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
