fn handle_connection(mut stream: TcpStream, app: Arc<App>) -> Result<()> {
    let request = read_http_request(&mut stream)?;

    match request.method.as_str() {
        "GET" if request.path == "/health" => {
            let health = app.source.health()?;
            let ack_count = lock_acks(&app)?.len();
            let ack_forward_status = lock_ack_forward_status(&app)?.clone();
            let status = if health.ok { "ok" } else { "degraded" };
            let upstream = if health.ok { "ok" } else { "bad" };
            let body = format!(
                "status={status}\nrole=relay\nrelay_id={}\nlocation={}\nsource={}\nupstream={upstream}\nupstream_addr={}\nack_count={ack_count}\nlast_ack_forward_unix={}\nack_forward_errors={}\n{}\n",
                app.relay_id,
                app.location,
                app.source.kind(),
                app.source.upstream_addr(),
                ack_forward_status.last_ack_forward_unix,
                ack_forward_status.ack_forward_errors,
                health.details.trim_end()
            );
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        "GET" if request.path == "/v1/acks" => {
            let body = format_acks(&app)?;
            write_http_response(&mut stream, 200, "text/plain", body.as_bytes())?;
        }
        "POST" if request.path == "/v1/ack" => {
            let form = parse_form_lines(&request.body)?;
            let ack = propagation_ack_from_form(&app, &form)?;
            lock_acks(&app)?.insert(ack.key(), ack.clone());
            if let Err(err) = forward_ack(&app, &ack) {
                eprintln!("central ack forward failed: {err}");
                lock_ack_forward_status(&app)?.ack_forward_errors += 1;
            }
            write_http_response(&mut stream, 200, "text/plain", b"status=ok\n")?;
        }
        "GET" => {
            let upstream = app.source.get(&request.path)?;
            write_http_response(
                &mut stream,
                upstream.status_code,
                content_type_for(&request.path),
                &upstream.body,
            )?;
        }
        "POST" => {
            let upstream = app.source.post(&request.path, &request.body)?;
            write_http_response(
                &mut stream,
                upstream.status_code,
                "text/plain",
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

