#[derive(Clone, Debug)]
pub struct SourceOfTruth {
    shard_count: u16,
    entries: HashMap<AclKey, DenyEntry>,
    rules: HashMap<RuleKey, RuleEntry>,
    watermarks: Vec<u64>,
    compacted_watermarks: Vec<u64>,
    mutations: Vec<Mutation>,
    op_index: HashMap<String, Mutation>,
    epoch: u64,
    source_region: String,
}

impl SourceOfTruth {
    pub fn new(shard_count: u16, source_region: impl Into<String>) -> Self {
        let shard_count = shard_count.max(1);
        Self {
            shard_count,
            entries: HashMap::new(),
            rules: HashMap::new(),
            watermarks: vec![0; shard_count as usize],
            compacted_watermarks: vec![0; shard_count as usize],
            mutations: Vec::new(),
            op_index: HashMap::new(),
            epoch: 1,
            source_region: source_region.into(),
        }
    }

    pub fn from_mutations(
        shard_count: u16,
        source_region: impl Into<String>,
        mut mutations: Vec<Mutation>,
    ) -> Result<Self> {
        mutations.sort_by_key(|mutation| {
            (
                mutation.commit_id.shard_id,
                mutation.commit_id.seq,
                mutation.op_id.clone(),
            )
        });

        let mut state = Self::new(shard_count, source_region);
        for mutation in mutations {
            state.apply_loaded_mutation(mutation)?;
        }
        Ok(state)
    }

    pub fn from_snapshot_and_mutations(
        shard_count: u16,
        source_region: impl Into<String>,
        snapshot: Snapshot,
        idempotency_mutations: Vec<Mutation>,
        mut mutations: Vec<Mutation>,
    ) -> Result<Self> {
        if snapshot.shard_count != shard_count {
            return Err(GlobAclError::InvalidData(format!(
                "snapshot shard_count {} does not match expected {}",
                snapshot.shard_count, shard_count
            )));
        }
        snapshot.validate()?;

        mutations.sort_by_key(|mutation| {
            (
                mutation.commit_id.shard_id,
                mutation.commit_id.seq,
                mutation.op_id.clone(),
            )
        });

        let mut state = Self::new(shard_count, source_region);
        state.watermarks = snapshot.watermarks.clone();
        state.compacted_watermarks = snapshot.watermarks;
        for entry in snapshot.entries {
            state.entries.insert(entry.acl_key(), entry);
        }
        for rule in snapshot.rules {
            state.rules.insert(rule.rule_key(), rule);
        }
        for mutation in idempotency_mutations {
            state.insert_op_index(mutation)?;
        }
        for mutation in mutations {
            state.apply_loaded_mutation(mutation)?;
        }
        Ok(state)
    }

    pub fn from_snapshot_and_retained_history(
        shard_count: u16,
        source_region: impl Into<String>,
        snapshot: Snapshot,
        idempotency_mutations: Vec<Mutation>,
        mut retained_mutations: Vec<Mutation>,
        compacted_watermarks: Vec<u64>,
    ) -> Result<Self> {
        if snapshot.shard_count != shard_count {
            return Err(GlobAclError::InvalidData(format!(
                "snapshot shard_count {} does not match expected {}",
                snapshot.shard_count, shard_count
            )));
        }
        snapshot.validate()?;
        if compacted_watermarks.len() != shard_count as usize {
            return Err(GlobAclError::InvalidData(format!(
                "retained history has {} compacted watermarks for {shard_count} shards",
                compacted_watermarks.len()
            )));
        }
        for (shard_id, compacted_seq) in compacted_watermarks.iter().copied().enumerate() {
            if compacted_seq > snapshot.watermarks[shard_id] {
                return Err(GlobAclError::InvalidData(format!(
                    "retained history compacted watermark {compacted_seq} exceeds shard {shard_id} snapshot watermark {}",
                    snapshot.watermarks[shard_id]
                )));
            }
        }

        retained_mutations.sort_by_key(|mutation| {
            (
                mutation.commit_id.shard_id,
                mutation.commit_id.seq,
                mutation.op_id.clone(),
            )
        });

        let mut state = Self::new(shard_count, source_region);
        state.watermarks = snapshot.watermarks.clone();
        state.compacted_watermarks = compacted_watermarks.clone();
        for entry in snapshot.entries {
            state.entries.insert(entry.acl_key(), entry);
        }
        for rule in snapshot.rules {
            state.rules.insert(rule.rule_key(), rule);
        }
        for mutation in idempotency_mutations {
            state.insert_op_index(mutation)?;
        }

        let mut expected_history_seq = compacted_watermarks;
        for mutation in retained_mutations {
            let shard_id = mutation.commit_id.shard_id;
            if shard_id >= shard_count {
                return Err(GlobAclError::InvalidData(format!(
                    "shard {shard_id} is outside shard_count {shard_count}"
                )));
            }
            let slot = shard_id as usize;
            let expected_seq = expected_history_seq[slot] + 1;
            if mutation.commit_id.seq != expected_seq {
                return Err(GlobAclError::Gap {
                    shard_id,
                    expected_seq,
                    received_seq: mutation.commit_id.seq,
                });
            }
            expected_history_seq[slot] = mutation.commit_id.seq;

            if mutation.commit_id.seq <= state.watermarks[slot] {
                state.insert_op_index(mutation.clone())?;
                state.mutations.push(mutation);
            } else {
                state.apply_loaded_mutation(mutation)?;
            }
        }

        for (shard_id, replayed_seq) in expected_history_seq.iter().copied().enumerate() {
            if replayed_seq < state.watermarks[shard_id] {
                return Err(GlobAclError::Gap {
                    shard_id: shard_id as u16,
                    expected_seq: replayed_seq + 1,
                    received_seq: state.watermarks[shard_id],
                });
            }
        }

        Ok(state)
    }

    pub fn commit(&mut self, request: DenyRequest) -> Result<CommitOutcome> {
        let outcome = self.prepare_commit(request)?;
        if !outcome.duplicate {
            self.apply_replicated_mutation(outcome.mutation.clone())?;
        }

        Ok(outcome)
    }

    pub fn commit_rule(&mut self, request: RuleRequest) -> Result<CommitOutcome> {
        let outcome = self.prepare_rule_commit(request)?;
        if !outcome.duplicate {
            self.apply_replicated_mutation(outcome.mutation.clone())?;
        }

        Ok(outcome)
    }

    pub fn prepare_commit(&self, request: DenyRequest) -> Result<CommitOutcome> {
        if request.op_id.trim().is_empty() {
            return Err(GlobAclError::Parse("op_id must not be empty".to_owned()));
        }

        if let Some(existing) = self.op_index.get(&request.op_id) {
            return Ok(CommitOutcome {
                mutation: existing.clone(),
                duplicate: true,
            });
        }

        let key = AclKey::from_raw(&request.tenant_id, &request.namespace, &request.key);
        let shard_id = shard_for_hash(key.key_hash, self.shard_count);
        let seq = self.watermarks[shard_id as usize] + 1;
        let commit_id = CommitId {
            shard_id,
            seq,
            epoch: self.epoch,
            source_region: self.source_region.clone(),
        };
        let entry = DenyEntry {
            tenant_id: request.tenant_id,
            namespace: request.namespace,
            key_hash: key.key_hash,
            action: request.action,
            priority: request.priority,
            reason_code: request.reason_code,
            expires_at: request.expires_at,
            created_by: request.created_by,
            commit_seq: seq,
            shard_id,
        };
        let mutation = Mutation {
            op_id: request.op_id,
            commit_id,
            entry,
            rule: None,
            delivery_priority: request.delivery_priority,
            committed_at_unix: now_unix(),
        };

        Ok(CommitOutcome {
            mutation,
            duplicate: false,
        })
    }

    pub fn prepare_rule_commit(&self, request: RuleRequest) -> Result<CommitOutcome> {
        if request.op_id.trim().is_empty() {
            return Err(GlobAclError::Parse("op_id must not be empty".to_owned()));
        }

        if let Some(existing) = self.op_index.get(&request.op_id) {
            return Ok(CommitOutcome {
                mutation: existing.clone(),
                duplicate: true,
            });
        }

        let compiled = compile_rule_pattern(request.kind, &request.pattern)?;
        let rule_hash = stable_key_hash(
            &request.tenant_id,
            request.kind.as_str(),
            &compiled.canonical_pattern,
        );
        let shard_id = shard_for_hash(rule_hash, self.shard_count);
        let seq = self.watermarks[shard_id as usize] + 1;
        let commit_id = CommitId {
            shard_id,
            seq,
            epoch: self.epoch,
            source_region: self.source_region.clone(),
        };
        let entry = DenyEntry {
            tenant_id: request.tenant_id.clone(),
            namespace: format!("__rule:{}", request.kind.as_str()),
            key_hash: rule_hash,
            action: request.action,
            priority: request.priority,
            reason_code: request.reason_code.clone(),
            expires_at: request.expires_at,
            created_by: request.created_by.clone(),
            commit_seq: seq,
            shard_id,
        };
        let rule = RuleEntry {
            tenant_id: request.tenant_id,
            kind: request.kind,
            pattern: compiled.canonical_pattern,
            rule_hash,
            action: request.action,
            priority: request.priority,
            reason_code: request.reason_code,
            expires_at: request.expires_at,
            created_by: request.created_by,
            commit_seq: seq,
            shard_id,
            ipv4_network: compiled.ipv4_network,
            ipv4_prefix_len: compiled.ipv4_prefix_len,
            domain_suffix: compiled.domain_suffix,
        };
        let mutation = Mutation {
            op_id: request.op_id,
            commit_id,
            entry,
            rule: Some(rule),
            delivery_priority: request.delivery_priority,
            committed_at_unix: now_unix(),
        };

        Ok(CommitOutcome {
            mutation,
            duplicate: false,
        })
    }

    pub fn apply_replicated_mutation(&mut self, mutation: Mutation) -> Result<ApplyStatus> {
        if let Some(existing) = self.op_index.get(&mutation.op_id) {
            if existing == &mutation {
                return Ok(ApplyStatus::DuplicateOrOld);
            }
            return Err(GlobAclError::InvalidData(format!(
                "op_id {} already exists with a different mutation",
                mutation.op_id
            )));
        }

        let shard_id = mutation.commit_id.shard_id;
        if shard_id >= self.shard_count {
            return Err(GlobAclError::InvalidData(format!(
                "shard {shard_id} is outside shard_count {}",
                self.shard_count
            )));
        }

        let current_seq = self.watermarks[shard_id as usize];
        if mutation.commit_id.seq <= current_seq {
            let already_applied = self.mutations.iter().any(|existing| {
                existing.commit_id.shard_id == shard_id
                    && existing.commit_id.seq == mutation.commit_id.seq
                    && existing == &mutation
            });
            if already_applied {
                return Ok(ApplyStatus::DuplicateOrOld);
            }
            return Err(GlobAclError::InvalidData(format!(
                "stale or conflicting mutation for shard {shard_id} seq {}",
                mutation.commit_id.seq
            )));
        }

        self.apply_committed_mutation(&mutation)?;
        self.op_index
            .insert(mutation.op_id.clone(), mutation.clone());
        self.mutations.push(mutation);

        Ok(ApplyStatus::Applied)
    }

    pub fn lookup(
        &self,
        tenant_id: &str,
        namespace: &str,
        raw_key: &str,
        now_unix: u64,
    ) -> Decision {
        let key = AclKey::from_raw(tenant_id, namespace, raw_key);
        decision_for_entry(self.entries.get(&key), now_unix)
    }

    pub fn check(
        &self,
        tenant_id: &str,
        namespace: &str,
        raw_value: &str,
        now_unix: u64,
    ) -> Decision {
        let point = self.lookup(tenant_id, namespace, raw_value, now_unix);
        if point.is_denied() {
            return point;
        }

        let mut best = RuleMatch::default();
        for rule in self.rules.values() {
            if rule.tenant_id == tenant_id && rule_matches_namespace(rule, namespace, raw_value) {
                best.consider(rule, now_unix);
            }
        }
        best.into_decision()
    }

    pub fn mutations_for_shard(&self, shard_id: u16, from_seq: u64) -> Vec<Mutation> {
        self.mutations
            .iter()
            .filter(|mutation| {
                mutation.commit_id.shard_id == shard_id && mutation.commit_id.seq > from_seq
            })
            .cloned()
            .collect()
    }

    pub fn mutation_history_compacted(&self, shard_id: u16, from_seq: u64) -> Option<u64> {
        let compacted_seq = self.compacted_watermarks.get(shard_id as usize).copied()?;
        (from_seq < compacted_seq).then_some(compacted_seq)
    }

    pub fn restore_snapshot(
        &mut self,
        snapshot: Snapshot,
        op_prefix: &str,
    ) -> Result<Vec<Mutation>> {
        if snapshot.shard_count != self.shard_count {
            return Err(GlobAclError::InvalidData(format!(
                "rollback snapshot has shard_count {}, expected {}",
                snapshot.shard_count, self.shard_count
            )));
        }
        snapshot.validate()?;

        let mut target_entries = HashMap::new();
        for entry in snapshot.entries {
            target_entries.insert(entry.acl_key(), entry);
        }
        let mut target_rules = HashMap::new();
        for rule in snapshot.rules {
            target_rules.insert(rule.rule_key(), rule);
        }

        let mut mutations = Vec::new();
        let mut current_entries = self.entries.values().cloned().collect::<Vec<_>>();
        current_entries.sort_by(compare_entries_by_key);
        for entry in current_entries {
            if !target_entries.contains_key(&entry.acl_key()) {
                let mut delete = entry;
                delete.action = Action::Delete;
                delete.reason_code = "rollback_delete".to_owned();
                delete.expires_at = 0;
                delete.created_by = "globacl-rollback".to_owned();
                mutations.push(self.commit_entry_direct(
                    next_restore_op_id(&self.op_index, op_prefix, mutations.len()),
                    delete,
                )?);
            }
        }

        let mut target_entry_values = target_entries.values().cloned().collect::<Vec<_>>();
        target_entry_values.sort_by(compare_entries_by_key);
        for entry in target_entry_values {
            let key = entry.acl_key();
            if self
                .entries
                .get(&key)
                .map(|current| !entry_semantically_equal(current, &entry))
                .unwrap_or(true)
            {
                mutations.push(self.commit_entry_direct(
                    next_restore_op_id(&self.op_index, op_prefix, mutations.len()),
                    entry,
                )?);
            }
        }

        let mut current_rules = self.rules.values().cloned().collect::<Vec<_>>();
        current_rules.sort_by(compare_rules_by_key);
        for rule in current_rules {
            if !target_rules.contains_key(&rule.rule_key()) {
                let mut delete = rule;
                delete.action = Action::Delete;
                delete.reason_code = "rollback_delete".to_owned();
                delete.expires_at = 0;
                delete.created_by = "globacl-rollback".to_owned();
                mutations.push(self.commit_rule_direct(
                    next_restore_op_id(&self.op_index, op_prefix, mutations.len()),
                    delete,
                )?);
            }
        }

        let mut target_rule_values = target_rules.values().cloned().collect::<Vec<_>>();
        target_rule_values.sort_by(compare_rules_by_key);
        for rule in target_rule_values {
            let key = rule.rule_key();
            if self
                .rules
                .get(&key)
                .map(|current| !rule_semantically_equal(current, &rule))
                .unwrap_or(true)
            {
                mutations.push(self.commit_rule_direct(
                    next_restore_op_id(&self.op_index, op_prefix, mutations.len()),
                    rule,
                )?);
            }
        }

        Ok(mutations)
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            shard_count: self.shard_count,
            watermarks: self.watermarks.clone(),
            entries: self.entries.values().cloned().collect(),
            rules: self.rules.values().cloned().collect(),
        }
    }

    pub fn shard_count(&self) -> u16 {
        self.shard_count
    }

    pub fn watermarks(&self) -> &[u64] {
        &self.watermarks
    }

    pub fn compacted_watermarks(&self) -> &[u64] {
        &self.compacted_watermarks
    }

    pub fn compact_mutation_history(&mut self, watermarks: &[u64]) -> Result<()> {
        if watermarks.len() != self.shard_count as usize {
            return Err(GlobAclError::InvalidData(format!(
                "compaction has {} watermarks for {} shards",
                watermarks.len(),
                self.shard_count
            )));
        }
        for (shard_id, compacted_seq) in watermarks.iter().copied().enumerate() {
            if compacted_seq > self.watermarks[shard_id] {
                return Err(GlobAclError::InvalidData(format!(
                    "compaction watermark {compacted_seq} exceeds shard {shard_id} watermark {}",
                    self.watermarks[shard_id]
                )));
            }
        }
        self.mutations.retain(|mutation| {
            mutation.commit_id.seq > watermarks[mutation.commit_id.shard_id as usize]
        });
        for (shard_id, compacted_seq) in watermarks.iter().copied().enumerate() {
            self.compacted_watermarks[shard_id] =
                self.compacted_watermarks[shard_id].max(compacted_seq);
        }
        Ok(())
    }

    pub fn idempotency_mutations(&self) -> Vec<Mutation> {
        let mut mutations = self.op_index.values().cloned().collect::<Vec<_>>();
        mutations.sort_by_key(|mutation| {
            (
                mutation.commit_id.shard_id,
                mutation.commit_id.seq,
                mutation.op_id.clone(),
            )
        });
        mutations
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch.max(1);
    }

    pub fn entries_len(&self) -> usize {
        self.entries.len()
    }

    pub fn mutations_len(&self) -> usize {
        self.mutations.len()
    }

    fn apply_loaded_mutation(&mut self, mutation: Mutation) -> Result<()> {
        self.apply_committed_mutation(&mutation)?;
        self.insert_op_index(mutation.clone())?;
        self.mutations.push(mutation);
        Ok(())
    }

    fn insert_op_index(&mut self, mutation: Mutation) -> Result<()> {
        if let Some(existing) = self.op_index.get(&mutation.op_id) {
            if existing == &mutation {
                return Ok(());
            }
            return Err(GlobAclError::InvalidData(format!(
                "op_id {} already exists with a different mutation",
                mutation.op_id
            )));
        }
        self.op_index.insert(mutation.op_id.clone(), mutation);
        Ok(())
    }

    fn apply_committed_mutation(&mut self, mutation: &Mutation) -> Result<()> {
        let shard_id = mutation.commit_id.shard_id;
        if shard_id >= self.shard_count {
            return Err(GlobAclError::InvalidData(format!(
                "shard {shard_id} is outside shard_count {}",
                self.shard_count
            )));
        }

        let expected_seq = self.watermarks[shard_id as usize] + 1;
        if mutation.commit_id.seq != expected_seq {
            return Err(GlobAclError::Gap {
                shard_id,
                expected_seq,
                received_seq: mutation.commit_id.seq,
            });
        }

        if let Some(rule) = &mutation.rule {
            let key = rule.rule_key();
            match rule.action {
                Action::Delete => {
                    self.rules.remove(&key);
                }
                Action::Deny | Action::AllowOverride => {
                    self.rules.insert(key, rule.clone());
                }
            }
        } else {
            let key = mutation.entry.acl_key();
            match mutation.entry.action {
                Action::Delete => {
                    self.entries.remove(&key);
                }
                Action::Deny | Action::AllowOverride => {
                    self.entries.insert(key, mutation.entry.clone());
                }
            }
        }
        self.watermarks[shard_id as usize] = mutation.commit_id.seq;
        Ok(())
    }

    fn commit_entry_direct(&mut self, op_id: String, mut entry: DenyEntry) -> Result<Mutation> {
        let shard_id = shard_for_hash(entry.key_hash, self.shard_count);
        let seq = self.watermarks[shard_id as usize] + 1;
        entry.shard_id = shard_id;
        entry.commit_seq = seq;
        let mutation = Mutation {
            op_id,
            commit_id: CommitId {
                shard_id,
                seq,
                epoch: self.epoch,
                source_region: self.source_region.clone(),
            },
            entry,
            rule: None,
            delivery_priority: DeliveryPriority::P0,
            committed_at_unix: now_unix(),
        };
        self.apply_committed_mutation(&mutation)?;
        self.op_index
            .insert(mutation.op_id.clone(), mutation.clone());
        self.mutations.push(mutation.clone());
        Ok(mutation)
    }

    fn commit_rule_direct(&mut self, op_id: String, mut rule: RuleEntry) -> Result<Mutation> {
        let shard_id = shard_for_hash(rule.rule_hash, self.shard_count);
        let seq = self.watermarks[shard_id as usize] + 1;
        rule.shard_id = shard_id;
        rule.commit_seq = seq;
        let entry = DenyEntry {
            tenant_id: rule.tenant_id.clone(),
            namespace: format!("__rule:{}", rule.kind.as_str()),
            key_hash: rule.rule_hash,
            action: rule.action,
            priority: rule.priority,
            reason_code: rule.reason_code.clone(),
            expires_at: rule.expires_at,
            created_by: rule.created_by.clone(),
            commit_seq: seq,
            shard_id,
        };
        let mutation = Mutation {
            op_id,
            commit_id: CommitId {
                shard_id,
                seq,
                epoch: self.epoch,
                source_region: self.source_region.clone(),
            },
            entry,
            rule: Some(rule),
            delivery_priority: DeliveryPriority::P0,
            committed_at_unix: now_unix(),
        };
        self.apply_committed_mutation(&mutation)?;
        self.op_index
            .insert(mutation.op_id.clone(), mutation.clone());
        self.mutations.push(mutation.clone());
        Ok(mutation)
    }
}
