fn jetstream_pull_loop(source: Arc<JetStreamSource>) {
    loop {
        match source.pull_once() {
            Ok(0) => thread::sleep(Duration::from_millis(100)),
            Ok(_) => {}
            Err(err) => {
                eprintln!("JetStream relay pull failed: {err}");
                if let Ok(mut status) = lock_jetstream_status(&source) {
                    status.errors += 1;
                }
                thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

fn ack_forward_loop(app: Arc<App>, interval: Duration) {
    loop {
        if let Err(err) = forward_all_acks(&app) {
            eprintln!("central ack forward loop failed: {err}");
            if let Ok(mut status) = lock_ack_forward_status(&app) {
                status.ack_forward_errors += 1;
            }
        }
        thread::sleep(interval);
    }
}

fn forward_all_acks(app: &App) -> Result<()> {
    let acks = lock_acks(app)?.values().cloned().collect::<Vec<_>>();
    for ack in acks {
        forward_ack(app, &ack)?;
    }
    Ok(())
}

fn forward_ack(app: &App, ack: &PropagationAck) -> Result<()> {
    let response = http_post(
        app.source.upstream_addr(),
        "/v1/ack",
        ack.to_json_body().as_bytes(),
    )?;
    if response.status_code != 200 {
        return Err(GlobAclError::InvalidData(format!(
            "upstream returned status {} for propagation ack",
            response.status_code
        )));
    }
    let mut status = lock_ack_forward_status(app)?;
    status.last_ack_forward_unix = now_unix();
    Ok(())
}

fn propagation_ack_from_json_fields(app: &App, form: &HashMap<String, String>) -> Result<PropagationAck> {
    if form.contains_key("relay_id") {
        return PropagationAck::from_json_fields(form);
    }
    let ack = PopAck::from_json_fields(form)?;
    Ok(PropagationAck::from_pop_ack(
        &app.relay_id,
        &app.location,
        ack,
        now_unix(),
    ))
}

fn bootstrap_cache(bootstrap_addr: &str) -> Result<RelayCache> {
    let snapshot_response = http_get(bootstrap_addr, "/v1/snapshot");
    if let Ok(response) = snapshot_response {
        if response.status_code == 200 {
            let snapshot = decode_snapshot(&response.body)?;
            return Ok(RelayCache::new(snapshot.watermarks));
        }
    }

    let watermarks_response = http_get(bootstrap_addr, "/v1/watermarks");
    if let Ok(response) = watermarks_response {
        if response.status_code == 200 {
            return Ok(RelayCache::new(parse_watermarks(&response.body)?));
        }
    }

    let shard_count = env::var("GLOBACL_SHARD_COUNT")
        .ok()
        .map(|value| parse_env_u16(&value, "GLOBACL_SHARD_COUNT"))
        .transpose()?
        .unwrap_or(DEFAULT_SHARD_COUNT);
    Ok(RelayCache::new(vec![0; shard_count as usize]))
}

