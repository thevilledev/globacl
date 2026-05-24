use globacl_agent::{start_embedded, AgentConfig, AgentHandle};
use globacl_core::{
    append_prometheus_metric, format_decision, http_get, metrics_bind_addr_from_env, now_unix,
    parse_form_lines, parse_query_path, read_http_request, spawn_prometheus_metrics_listener,
    write_http_response, Decision, GlobAclError, Result,
};
use std::env;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

struct App {
    lookup: LookupMode,
}

enum LookupMode {
    Http { agent_addr: String },
    Embedded { agent: AgentHandle },
}

pub(crate) fn run() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    let upstream_addr = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:7002".to_owned());
    let bind_addr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:8080");
    let lookup = lookup_mode(upstream_addr)?;
    let app = Arc::new(App { lookup });

    {
        let app = Arc::clone(&app);
        spawn_prometheus_metrics_listener(
            metrics_bind_addr_from_env("GLOBACL_DEMO_METRICS_ADDR", "127.0.0.1:9180"),
            move || format_demo_metrics(&app),
        )?;
    }

    let listener = TcpListener::bind(bind_addr)?;
    eprintln!("globacl-demo-app listening on {bind_addr}; {}", app.lookup.description());

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

fn lookup_mode(upstream_addr: String) -> Result<LookupMode> {
    let mode = env::var("GLOBACL_DEMO_LOOKUP_MODE").unwrap_or_else(|_| "http".to_owned());
    match mode.trim().to_ascii_lowercase().as_str() {
        "" | "http" | "sidecar" => Ok(LookupMode::Http {
            agent_addr: upstream_addr,
        }),
        "embedded" | "in_process" | "in-process" => {
            let snapshot_path = PathBuf::from(
                env::var("GLOBACL_DEMO_SNAPSHOT_PATH")
                    .unwrap_or_else(|_| "data/demo-agent/latest.gacl".to_owned()),
            );
            let poll_ms = env::var("GLOBACL_DEMO_POLL_MS")
                .ok()
                .map(|value| parse_env_u64(&value, "GLOBACL_DEMO_POLL_MS"))
                .transpose()?
                .unwrap_or(1000);
            let stale_after_secs = env::var("GLOBACL_DEMO_STALE_AFTER_SECS")
                .ok()
                .map(|value| parse_env_u64(&value, "GLOBACL_DEMO_STALE_AFTER_SECS"))
                .transpose()?
                .unwrap_or(60);
            let agent_id =
                env::var("GLOBACL_DEMO_AGENT_ID").unwrap_or_else(|_| "demo-embedded".to_owned());
            let config = AgentConfig::new(upstream_addr, snapshot_path)?
                .with_agent_id(agent_id)
                .with_poll_interval(Duration::from_millis(poll_ms))
                .with_stale_after(Duration::from_secs(stale_after_secs));
            Ok(LookupMode::Embedded {
                agent: start_embedded(config)?,
            })
        }
        other => Err(GlobAclError::Parse(format!(
            "unknown GLOBACL_DEMO_LOOKUP_MODE {other:?}"
        ))),
    }
}

impl LookupMode {
    fn description(&self) -> String {
        match self {
            Self::Http { agent_addr } => format!("lookup_mode=http agent_addr={agent_addr}"),
            Self::Embedded { .. } => "lookup_mode=embedded".to_owned(),
        }
    }

    fn mode_name(&self) -> &'static str {
        match self {
            Self::Http { .. } => "http",
            Self::Embedded { .. } => "embedded",
        }
    }
}

fn parse_env_u64(value: &str, field: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|err| GlobAclError::Parse(format!("invalid {field}: {err}")))
}
