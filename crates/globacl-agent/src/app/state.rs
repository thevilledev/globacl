fn current_state(app: &App) -> Arc<ActiveState> {
    app.state.load()
}

fn swap_state(app: &App, next: ActiveState) {
    app.state.store(next);
}

fn lock_metrics(app: &App) -> Result<std::sync::MutexGuard<'_, AgentMetrics>> {
    app.metrics
        .lock()
        .map_err(|_| GlobAclError::InvalidData("agent metrics lock poisoned".to_owned()))
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

fn parse_arg_u64(value: &str, field: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|err| GlobAclError::Parse(format!("invalid {field}: {err}")))
}
