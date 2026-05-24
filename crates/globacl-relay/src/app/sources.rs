impl RelaySource for HttpPullSource {
    fn kind(&self) -> &'static str {
        "http_pull"
    }

    fn upstream_addr(&self) -> &str {
        &self.upstream_addr
    }

    fn health(&self) -> Result<SourceHealth> {
        let upstream = http_get(&self.upstream_addr, "/health")?;
        Ok(SourceHealth {
            ok: upstream.status_code == 200,
            details: json!({"http_status": upstream.status_code}).to_string(),
        })
    }

    fn get(&self, path: &str) -> Result<HttpResponse> {
        http_get(&self.upstream_addr, path)
    }

    fn post(&self, path: &str, body: &[u8]) -> Result<HttpResponse> {
        http_post(&self.upstream_addr, path, body)
    }
}

impl JetStreamSource {
    fn new(bootstrap_addr: String, relay_id: &str) -> Result<Self> {
        let nats_addr = env::var("GLOBACL_NATS_ADDR")
            .or_else(|_| env::var("GLOBACL_NATS_URL"))
            .unwrap_or_else(|_| "127.0.0.1:4222".to_owned());
        let stream = env::var("GLOBACL_NATS_STREAM").unwrap_or_else(|_| "GLOBACL".to_owned());
        let subject_prefix =
            env::var("GLOBACL_NATS_SUBJECT_PREFIX").unwrap_or_else(|_| "globacl".to_owned());
        let filter_subject = env::var("GLOBACL_NATS_SUBJECT_FILTER")
            .unwrap_or_else(|_| format!("{subject_prefix}.>"));
        let durable =
            env::var("GLOBACL_NATS_CONSUMER").unwrap_or_else(|_| sanitize_nats_name(relay_id));
        let batch = env::var("GLOBACL_NATS_BATCH")
            .ok()
            .map(|value| parse_env_usize(&value, "GLOBACL_NATS_BATCH"))
            .transpose()?
            .unwrap_or(128);
        if env_bool("GLOBACL_NATS_AUTOCREATE", true) {
            nats_jetstream_ensure_stream(
                &nats_addr,
                &stream,
                std::slice::from_ref(&filter_subject),
            )?;
            nats_jetstream_ensure_consumer(&nats_addr, &stream, &durable, &filter_subject)?;
        }
        let signature_signer = signature_signer_from_env()?;
        let cache = bootstrap_cache(&bootstrap_addr)?;
        Ok(Self {
            bootstrap_addr,
            nats_addr,
            stream,
            durable,
            batch,
            signature_signer,
            cache: Mutex::new(cache),
            status: Mutex::new(JetStreamStatus {
                last_pull_unix: 0,
                applied_messages: 0,
                duplicate_messages: 0,
                gap_repairs: 0,
                errors: 0,
                source_lag_max: 0,
                source_lag_sum: 0,
                lagging_shards: 0,
                consumer_num_pending: 0,
                consumer_num_ack_pending: 0,
                consumer_num_redelivered: 0,
                consumer_num_waiting: 0,
            }),
        })
    }

    fn pull_once(&self) -> Result<usize> {
        let messages = nats_jetstream_pull(
            &self.nats_addr,
            &self.stream,
            &self.durable,
            self.batch,
            1_000,
        )?;
        let count = messages.len();
        for message in messages {
            let mutation = decode_mutation(&message.payload)?;
            let applied = self.apply_or_repair(mutation)?;
            if applied {
                lock_jetstream_status(self)?.applied_messages += 1;
            } else {
                lock_jetstream_status(self)?.duplicate_messages += 1;
            }
            if let Some(reply_to) = message.reply_to {
                nats_ack(&self.nats_addr, &reply_to)?;
            }
        }
        if count > 0 {
            lock_jetstream_status(self)?.last_pull_unix = now_unix();
        }
        if let Err(err) = self.refresh_source_lag() {
            eprintln!("JetStream source lag refresh failed: {err}");
        }
        Ok(count)
    }

    fn apply_or_repair(&self, mutation: Mutation) -> Result<bool> {
        match self.apply_to_cache(mutation.clone()) {
            Ok(applied) => Ok(applied),
            Err(GlobAclError::Gap {
                shard_id,
                expected_seq,
                received_seq,
            }) => {
                self.repair_gap(shard_id, expected_seq.saturating_sub(1), received_seq)?;
                lock_jetstream_status(self)?.gap_repairs += 1;
                self.apply_to_cache(mutation)
            }
            Err(err) => Err(err),
        }
    }

    fn apply_to_cache(&self, mutation: Mutation) -> Result<bool> {
        let mut cache = lock_cache(self)?;
        cache.apply(mutation)
    }

    fn repair_gap(&self, shard_id: u16, from_seq: u64, to_seq: u64) -> Result<()> {
        let path = format!("/v1/delta_bundle?shard={shard_id}&from_seq={from_seq}&to_seq={to_seq}");
        let response = http_get(&self.bootstrap_addr, &path)?;
        if response.status_code != 200 {
            return self.rebuild_cache_from_snapshot();
        }
        let mutations = decode_mutation_stream(&response.body)?;
        let mut cache = lock_cache(self)?;
        for mutation in mutations {
            cache.apply(mutation)?;
        }
        Ok(())
    }

    fn rebuild_cache_from_snapshot(&self) -> Result<()> {
        let response = http_get(&self.bootstrap_addr, "/v1/snapshot")?;
        if response.status_code != 200 {
            return Err(GlobAclError::InvalidData(format!(
                "bootstrap returned status {} for snapshot repair",
                response.status_code
            )));
        }
        let snapshot = decode_snapshot(&response.body)?;
        let mut cache = lock_cache(self)?;
        *cache = RelayCache::new(snapshot.watermarks);
        Ok(())
    }

    fn local_mutations_for_path(&self, path: &str) -> Result<Option<Vec<Mutation>>> {
        let (route, query) = parse_query_path(path);
        let shard_id = required_query_u16(&query, "shard")?;
        let from_seq = query
            .get("from_seq")
            .or_else(|| query.get("from"))
            .map(|value| parse_query_u64(value, "from_seq"))
            .transpose()?
            .unwrap_or(0);
        let priority_filter = query
            .get("delivery_priority")
            .or_else(|| query.get("channel"))
            .map(|value| DeliveryPriority::from_name(value))
            .transpose()?;
        let cache = lock_cache(self)?;
        if route == "/v1/mutations" || route == "/v1/mutations.sig" {
            return cache.mutations_for_shard(shard_id, from_seq, priority_filter);
        }
        let to_seq = query
            .get("to_seq")
            .or_else(|| query.get("to"))
            .map(|value| parse_query_u64(value, "to_seq"))
            .transpose()?
            .unwrap_or(u64::MAX);
        cache.delta_bundle(shard_id, from_seq, to_seq)
    }

    fn signed_stream_response(&self, mutations: Vec<Mutation>) -> Result<HttpResponse> {
        let payload = encode_mutation_stream(&mutations);
        Ok(HttpResponse {
            status_code: 200,
            body: self.signature_signer.sign_payload(&payload)?.into_bytes(),
        })
    }

    fn refresh_source_lag(&self) -> Result<()> {
        let response = http_get(&self.bootstrap_addr, "/v1/watermarks")?;
        if response.status_code != 200 {
            return Err(GlobAclError::InvalidData(format!(
                "bootstrap returned status {} for watermarks",
                response.status_code
            )));
        }
        let source_watermarks = parse_watermarks(&response.body)?;
        let cache = lock_cache(self)?;
        let mut source_lag_max = 0u64;
        let mut source_lag_sum = 0u64;
        let mut lagging_shards = 0usize;
        for (shard_id, source_seq) in source_watermarks.iter().copied().enumerate() {
            let local_seq = cache.watermarks.get(shard_id).copied().unwrap_or(0);
            let lag = source_seq.saturating_sub(local_seq);
            if lag > 0 {
                lagging_shards += 1;
                source_lag_sum = source_lag_sum.saturating_add(lag);
                source_lag_max = source_lag_max.max(lag);
            }
        }
        drop(cache);

        let mut status = lock_jetstream_status(self)?;
        status.source_lag_max = source_lag_max;
        status.source_lag_sum = source_lag_sum;
        status.lagging_shards = lagging_shards;
        Ok(())
    }

    fn refresh_consumer_lag(&self) -> Result<()> {
        let info = nats_jetstream_consumer_info(&self.nats_addr, &self.stream, &self.durable)?;
        let mut status = lock_jetstream_status(self)?;
        status.consumer_num_pending = info.num_pending;
        status.consumer_num_ack_pending = info.num_ack_pending;
        status.consumer_num_redelivered = info.num_redelivered;
        status.consumer_num_waiting = info.num_waiting;
        Ok(())
    }
}

impl RelaySource for JetStreamSource {
    fn kind(&self) -> &'static str {
        "jetstream"
    }

    fn upstream_addr(&self) -> &str {
        &self.bootstrap_addr
    }

    fn health(&self) -> Result<SourceHealth> {
        if let Err(err) = self.refresh_source_lag() {
            eprintln!("JetStream source lag refresh failed: {err}");
        }
        if let Err(err) = self.refresh_consumer_lag() {
            eprintln!("JetStream consumer lag refresh failed: {err}");
        }
        let status = lock_jetstream_status(self)?.clone();
        let bootstrap_status = http_get(&self.bootstrap_addr, "/health")
            .map(|response| response.status_code)
            .unwrap_or(503);
        let cache = lock_cache(self)?;
        let max_cached_seq = cache.watermarks.iter().copied().max().unwrap_or(0);
        let cached_mutations = cache.mutations.iter().map(Vec::len).sum::<usize>();
        let shard_count = cache.watermarks.len();
        drop(cache);
        Ok(SourceHealth {
            ok: status.errors == 0 || status.last_pull_unix > 0,
            details: json!({
                "nats_addr": self.nats_addr.as_str(),
                "stream": self.stream.as_str(),
                "consumer": self.durable.as_str(),
                "bootstrap_status": bootstrap_status,
                "shard_count": shard_count,
                "max_cached_seq": max_cached_seq,
                "cached_mutations": cached_mutations,
                "source_lag_max": status.source_lag_max,
                "source_lag_sum": status.source_lag_sum,
                "lagging_shards": status.lagging_shards,
                "consumer_num_pending": status.consumer_num_pending,
                "consumer_num_ack_pending": status.consumer_num_ack_pending,
                "consumer_num_redelivered": status.consumer_num_redelivered,
                "consumer_num_waiting": status.consumer_num_waiting,
                "last_pull_unix": status.last_pull_unix,
                "applied_messages": status.applied_messages,
                "duplicate_messages": status.duplicate_messages,
                "gap_repairs": status.gap_repairs,
                "jetstream_errors": status.errors
            })
            .to_string(),
        })
    }

    fn get(&self, path: &str) -> Result<HttpResponse> {
        let (route, _) = parse_query_path(path);
        match route.as_str() {
            "/v1/watermarks" => {
                let cache = lock_cache(self)?;
                Ok(HttpResponse {
                    status_code: 200,
                    body: format_watermarks(&cache.watermarks).into_bytes(),
                })
            }
            "/v1/mutations" | "/v1/delta_bundle" => {
                if let Some(mutations) = self.local_mutations_for_path(path)? {
                    Ok(HttpResponse {
                        status_code: 200,
                        body: encode_mutation_stream(&mutations),
                    })
                } else {
                    http_get(&self.bootstrap_addr, path)
                }
            }
            "/v1/mutations.sig" | "/v1/delta_bundle.sig" => {
                if let Some(mutations) = self.local_mutations_for_path(path)? {
                    self.signed_stream_response(mutations)
                } else {
                    http_get(&self.bootstrap_addr, path)
                }
            }
            _ => http_get(&self.bootstrap_addr, path),
        }
    }

    fn post(&self, path: &str, body: &[u8]) -> Result<HttpResponse> {
        http_post(&self.bootstrap_addr, path, body)
    }
}

impl RelayCache {
    fn new(base_watermarks: Vec<u64>) -> Self {
        let shard_count = base_watermarks.len().max(1);
        Self {
            base_watermarks: base_watermarks.clone(),
            watermarks: base_watermarks,
            mutations: vec![Vec::new(); shard_count],
        }
    }

    fn apply(&mut self, mutation: Mutation) -> Result<bool> {
        let shard_id = mutation.commit_id.shard_id as usize;
        if shard_id >= self.watermarks.len() {
            return Err(GlobAclError::InvalidData(format!(
                "shard {} is outside relay shard_count {}",
                mutation.commit_id.shard_id,
                self.watermarks.len()
            )));
        }
        let current_seq = self.watermarks[shard_id];
        if mutation.commit_id.seq <= current_seq {
            return Ok(false);
        }
        let expected_seq = current_seq + 1;
        if mutation.commit_id.seq != expected_seq {
            return Err(GlobAclError::Gap {
                shard_id: mutation.commit_id.shard_id,
                expected_seq,
                received_seq: mutation.commit_id.seq,
            });
        }
        self.watermarks[shard_id] = mutation.commit_id.seq;
        self.mutations[shard_id].push(mutation);
        Ok(true)
    }

    fn mutations_for_shard(
        &self,
        shard_id: u16,
        from_seq: u64,
        priority_filter: Option<DeliveryPriority>,
    ) -> Result<Option<Vec<Mutation>>> {
        let shard_index = shard_id as usize;
        if shard_index >= self.watermarks.len() {
            return Err(GlobAclError::InvalidData(format!(
                "shard {shard_id} is outside relay shard_count {}",
                self.watermarks.len()
            )));
        }
        if from_seq < self.base_watermarks[shard_index] {
            return Ok(None);
        }
        Ok(Some(
            self.mutations[shard_index]
                .iter()
                .filter(|mutation| mutation.commit_id.seq > from_seq)
                .filter(|mutation| {
                    priority_filter
                        .map(|priority| mutation.delivery_priority == priority)
                        .unwrap_or(true)
                })
                .cloned()
                .collect(),
        ))
    }

    fn delta_bundle(
        &self,
        shard_id: u16,
        from_seq: u64,
        to_seq: u64,
    ) -> Result<Option<Vec<Mutation>>> {
        let shard_index = shard_id as usize;
        if shard_index >= self.watermarks.len() {
            return Err(GlobAclError::InvalidData(format!(
                "shard {shard_id} is outside relay shard_count {}",
                self.watermarks.len()
            )));
        }
        if from_seq < self.base_watermarks[shard_index] {
            return Ok(None);
        }
        let upper = to_seq.min(self.watermarks[shard_index]);
        let mutations = self.mutations[shard_index]
            .iter()
            .filter(|mutation| mutation.commit_id.seq > from_seq && mutation.commit_id.seq <= upper)
            .cloned()
            .collect::<Vec<_>>();
        if upper > from_seq && mutations.len() != (upper - from_seq) as usize {
            return Ok(None);
        }
        Ok(Some(mutations))
    }
}
