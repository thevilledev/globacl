
#[derive(Clone, Debug)]
pub struct ActiveState {
    shard_count: u16,
    base: Arc<ImmutableBase>,
    delta_adds: HashMap<AclKey, DenyEntry>,
    delta_removes: HashMap<AclKey, u64>,
    rule_base: Arc<CompiledRules>,
    delta_rule_adds: HashMap<RuleKey, RuleEntry>,
    delta_rule_removes: HashMap<RuleKey, u64>,
    watermarks: Vec<u64>,
}

pub struct ActiveStateHandle {
    state: ArcSwap<ActiveState>,
}

#[derive(Clone, Debug)]
struct ImmutableBase {
    entries: Vec<CompactDenyEntry>,
    symbols: SymbolTable,
    filter: NegativeFilter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CompactDenyEntry {
    key_hash: u64,
    expires_at: u64,
    commit_seq: u64,
    priority: u32,
    tenant_id: u32,
    namespace: u32,
    reason_code: u32,
    created_by: u32,
    shard_id: u16,
    action: Action,
}

#[derive(Clone, Debug, Default)]
struct SymbolTable {
    values: Vec<String>,
    ids: HashMap<String, u32>,
}

#[derive(Clone, Debug)]
struct NegativeFilter {
    bits: Vec<u64>,
    bit_len: usize,
}

#[derive(Clone, Debug, Default)]
struct CompiledRules {
    ipv4_by_prefix: Vec<HashMap<(String, u32), Vec<RuleEntry>>>,
    domain_suffixes: HashMap<(String, String), Vec<RuleEntry>>,
    rules_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveStateStats {
    pub base_entries: usize,
    pub delta_adds: usize,
    pub delta_removes: usize,
    pub base_rules: usize,
    pub delta_rule_adds: usize,
    pub delta_rule_removes: usize,
    pub filter_bits: usize,
    pub filter_hashes: usize,
    pub estimated_bytes: usize,
}

impl ActiveStateHandle {
    pub fn new(state: ActiveState) -> Self {
        Self {
            state: ArcSwap::from_pointee(state),
        }
    }

    pub fn from_snapshot(snapshot: Snapshot) -> Result<Self> {
        Ok(Self::new(ActiveState::from_snapshot(snapshot)?))
    }

    pub fn load(&self) -> Arc<ActiveState> {
        self.state.load_full()
    }

    pub fn store(&self, state: ActiveState) {
        self.state.store(Arc::new(state));
    }
}

impl ActiveState {
    pub fn new(shard_count: u16) -> Self {
        let shard_count = shard_count.max(1);
        Self {
            shard_count,
            base: Arc::new(ImmutableBase::from_entries(Vec::new())),
            delta_adds: HashMap::new(),
            delta_removes: HashMap::new(),
            rule_base: Arc::new(CompiledRules::from_rules(Vec::new())),
            delta_rule_adds: HashMap::new(),
            delta_rule_removes: HashMap::new(),
            watermarks: vec![0; shard_count as usize],
        }
    }

    pub fn from_snapshot(snapshot: Snapshot) -> Result<Self> {
        snapshot.validate()?;

        Ok(Self {
            shard_count: snapshot.shard_count,
            base: Arc::new(ImmutableBase::from_entries(snapshot.entries)),
            delta_adds: HashMap::new(),
            delta_removes: HashMap::new(),
            rule_base: Arc::new(CompiledRules::from_rules(snapshot.rules)),
            delta_rule_adds: HashMap::new(),
            delta_rule_removes: HashMap::new(),
            watermarks: snapshot.watermarks,
        })
    }

    pub fn apply_mutation(&mut self, mutation: &Mutation) -> Result<ApplyStatus> {
        let shard_id = mutation.commit_id.shard_id;
        if shard_id >= self.shard_count {
            return Err(GlobAclError::InvalidData(format!(
                "shard {shard_id} is outside shard_count {}",
                self.shard_count
            )));
        }

        let current_seq = self.watermarks[shard_id as usize];
        if mutation.commit_id.seq <= current_seq {
            return Ok(ApplyStatus::DuplicateOrOld);
        }

        let expected_seq = current_seq + 1;
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
                    self.delta_rule_adds.remove(&key);
                    self.delta_rule_removes.insert(key, mutation.commit_id.seq);
                }
                Action::Deny | Action::AllowOverride => {
                    self.delta_rule_removes.remove(&key);
                    self.delta_rule_adds.insert(key, rule.clone());
                }
            }
        } else {
            let key = mutation.entry.acl_key();
            match mutation.entry.action {
                Action::Delete => {
                    self.delta_adds.remove(&key);
                    self.delta_removes.insert(key, mutation.commit_id.seq);
                }
                Action::Deny | Action::AllowOverride => {
                    self.delta_removes.remove(&key);
                    self.delta_adds.insert(key, mutation.entry.clone());
                }
            }
        }
        self.watermarks[shard_id as usize] = mutation.commit_id.seq;
        Ok(ApplyStatus::Applied)
    }

    pub fn lookup(
        &self,
        tenant_id: &str,
        namespace: &str,
        raw_key: &str,
        now_unix: u64,
    ) -> Decision {
        let key_hash = stable_key_hash(tenant_id, namespace, raw_key);

        if !self.delta_adds.is_empty() || !self.delta_removes.is_empty() {
            let key = AclKey {
                tenant_id: tenant_id.to_owned(),
                namespace: namespace.to_owned(),
                key_hash,
            };
            if let Some(entry) = self.delta_adds.get(&key) {
                return decision_for_entry(Some(entry), now_unix);
            }

            if self.delta_removes.contains_key(&key) {
                return Decision::Allow;
            }
        }

        self.base
            .decision_for_parts(tenant_id, namespace, key_hash, now_unix)
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
        self.consider_delta_rules(tenant_id, namespace, raw_value, now_unix, &mut best);
        self.rule_base.consider_matches(
            tenant_id,
            namespace,
            raw_value,
            now_unix,
            &self.delta_rule_removes,
            &mut best,
        );
        best.into_decision()
    }

    pub fn snapshot(&self) -> Snapshot {
        let entries = self.materialized_entries();
        let rules = self.materialized_rules();
        Snapshot {
            shard_count: self.shard_count,
            watermarks: self.watermarks.clone(),
            entries,
            rules,
        }
    }

    pub fn shard_count(&self) -> u16 {
        self.shard_count
    }

    pub fn entries_len(&self) -> usize {
        let mut len = self.base.len();
        for key in self.delta_removes.keys() {
            if self.base.contains_key(key) && !self.delta_adds.contains_key(key) {
                len = len.saturating_sub(1);
            }
        }
        for key in self.delta_adds.keys() {
            if !self.base.contains_key(key) {
                len += 1;
            }
        }
        len
    }

    pub fn watermarks(&self) -> &[u64] {
        &self.watermarks
    }

    pub fn stats(&self) -> ActiveStateStats {
        let base_bytes = self.base.estimated_bytes();
        let overlay_bytes = (self.delta_adds.len() * std::mem::size_of::<(AclKey, DenyEntry)>())
            + (self.delta_removes.len() * std::mem::size_of::<(AclKey, u64)>());
        let rule_bytes = self.rule_base.rules_len * std::mem::size_of::<RuleEntry>()
            + (self.delta_rule_adds.len() * std::mem::size_of::<(RuleKey, RuleEntry)>())
            + (self.delta_rule_removes.len() * std::mem::size_of::<(RuleKey, u64)>());

        ActiveStateStats {
            base_entries: self.base.len(),
            delta_adds: self.delta_adds.len(),
            delta_removes: self.delta_removes.len(),
            base_rules: self.rule_base.rules_len,
            delta_rule_adds: self.delta_rule_adds.len(),
            delta_rule_removes: self.delta_rule_removes.len(),
            filter_bits: self.base.filter.bit_len,
            filter_hashes: NEGATIVE_FILTER_HASHES,
            estimated_bytes: base_bytes + overlay_bytes + rule_bytes,
        }
    }

    /// Benchmark/observability probe for the immutable base negative filter.
    ///
    /// A `true` result is approximate and must never be treated as a deny decision
    /// without the exact lookup verification performed by [`Self::lookup`].
    pub fn base_filter_may_contain(&self, tenant_id: &str, namespace: &str, raw_key: &str) -> bool {
        self.base.filter.may_contain_parts(
            tenant_id,
            namespace,
            stable_key_hash(tenant_id, namespace, raw_key),
        )
    }

    pub fn delta_entries_len(&self) -> usize {
        self.delta_adds.len()
            + self.delta_removes.len()
            + self.delta_rule_adds.len()
            + self.delta_rule_removes.len()
    }

    pub fn compact_delta_overlay(&mut self) {
        if self.delta_adds.is_empty()
            && self.delta_removes.is_empty()
            && self.delta_rule_adds.is_empty()
            && self.delta_rule_removes.is_empty()
        {
            return;
        }
        let entries = self.materialized_entries();
        self.base = Arc::new(ImmutableBase::from_entries(entries));
        let rules = self.materialized_rules();
        self.rule_base = Arc::new(CompiledRules::from_rules(rules));
        self.delta_adds.clear();
        self.delta_removes.clear();
        self.delta_rule_adds.clear();
        self.delta_rule_removes.clear();
    }

    fn materialized_entries(&self) -> Vec<DenyEntry> {
        let mut entries = Vec::with_capacity(self.entries_len());
        for entry in self.base.materialized_entries() {
            let key = entry.acl_key();
            if self.delta_removes.contains_key(&key) {
                continue;
            }
            if self.delta_adds.contains_key(&key) {
                continue;
            }
            entries.push(entry);
        }
        entries.extend(self.delta_adds.values().cloned());
        entries
    }

    fn materialized_rules(&self) -> Vec<RuleEntry> {
        let mut rules = self.rule_base.all_rules();
        rules.retain(|rule| {
            let key = rule.rule_key();
            !self.delta_rule_removes.contains_key(&key) && !self.delta_rule_adds.contains_key(&key)
        });
        rules.extend(self.delta_rule_adds.values().cloned());
        rules
    }

    fn consider_delta_rules(
        &self,
        tenant_id: &str,
        namespace: &str,
        raw_value: &str,
        now_unix: u64,
        best: &mut RuleMatch,
    ) {
        for rule in self.delta_rule_adds.values() {
            if rule.tenant_id == tenant_id && rule_matches_namespace(rule, namespace, raw_value) {
                best.consider(rule, now_unix);
            }
        }
    }
}

impl ImmutableBase {
    fn from_entries(mut entries: Vec<DenyEntry>) -> Self {
        entries.sort_by(compare_entries_by_key);

        let mut deduped: Vec<DenyEntry> = Vec::with_capacity(entries.len());
        for entry in entries {
            match deduped.last_mut() {
                Some(last) if same_entry_key(last, &entry) => {
                    if entry.commit_seq >= last.commit_seq {
                        *last = entry;
                    }
                }
                _ => deduped.push(entry),
            }
        }

        let mut symbols = SymbolTable::default();
        let mut compact_entries = Vec::with_capacity(deduped.len());
        for entry in deduped {
            compact_entries.push(CompactDenyEntry::from_entry(entry, &mut symbols));
        }
        compact_entries.sort_by(compare_compact_entries_by_key);

        let filter = NegativeFilter::from_compact_entries(&compact_entries, &symbols);
        Self {
            entries: compact_entries,
            symbols,
            filter,
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn decision_for_parts(
        &self,
        tenant_id: &str,
        namespace: &str,
        key_hash: u64,
        now_unix: u64,
    ) -> Decision {
        let Some(entry) = self.lookup_parts(tenant_id, namespace, key_hash) else {
            return Decision::Allow;
        };
        if entry.is_expired(now_unix) {
            return Decision::Allow;
        }
        match entry.action {
            Action::Deny => Decision::Deny {
                reason_code: self.symbols.get(entry.reason_code).to_owned(),
                priority: entry.priority,
                commit_id: CommitId {
                    shard_id: entry.shard_id,
                    seq: entry.commit_seq,
                    epoch: 1,
                    source_region: String::new(),
                },
            },
            Action::AllowOverride | Action::Delete => Decision::Allow,
        }
    }

    fn lookup_parts(
        &self,
        tenant_id: &str,
        namespace: &str,
        key_hash: u64,
    ) -> Option<&CompactDenyEntry> {
        if !self
            .filter
            .may_contain_parts(tenant_id, namespace, key_hash)
        {
            return None;
        }
        self.lookup_exact_parts(tenant_id, namespace, key_hash)
    }

    fn lookup_exact_parts(
        &self,
        tenant_id: &str,
        namespace: &str,
        key_hash: u64,
    ) -> Option<&CompactDenyEntry> {
        let tenant_id = self.symbols.id(tenant_id)?;
        let namespace = self.symbols.id(namespace)?;
        self.entries
            .binary_search_by(|entry| {
                compare_compact_entry_to_key(entry, tenant_id, namespace, key_hash)
            })
            .ok()
            .map(|index| &self.entries[index])
    }

    fn contains_key(&self, key: &AclKey) -> bool {
        self.lookup_exact_parts(&key.tenant_id, &key.namespace, key.key_hash)
            .is_some()
    }

    fn materialized_entries(&self) -> Vec<DenyEntry> {
        self.entries
            .iter()
            .map(|entry| entry.to_deny_entry(&self.symbols))
            .collect()
    }

    fn estimated_bytes(&self) -> usize {
        (self.entries.len() * std::mem::size_of::<CompactDenyEntry>())
            + (self.filter.bits.len() * std::mem::size_of::<u64>())
            + self.symbols.estimated_bytes()
    }
}

impl CompactDenyEntry {
    fn from_entry(entry: DenyEntry, symbols: &mut SymbolTable) -> Self {
        Self {
            key_hash: entry.key_hash,
            expires_at: entry.expires_at,
            commit_seq: entry.commit_seq,
            priority: entry.priority,
            tenant_id: symbols.intern(entry.tenant_id),
            namespace: symbols.intern(entry.namespace),
            reason_code: symbols.intern(entry.reason_code),
            created_by: symbols.intern(entry.created_by),
            shard_id: entry.shard_id,
            action: entry.action,
        }
    }

    fn is_expired(self, now_unix: u64) -> bool {
        self.expires_at != 0 && self.expires_at <= now_unix
    }

    fn to_deny_entry(self, symbols: &SymbolTable) -> DenyEntry {
        DenyEntry {
            tenant_id: symbols.get(self.tenant_id).to_owned(),
            namespace: symbols.get(self.namespace).to_owned(),
            key_hash: self.key_hash,
            action: self.action,
            priority: self.priority,
            reason_code: symbols.get(self.reason_code).to_owned(),
            expires_at: self.expires_at,
            created_by: symbols.get(self.created_by).to_owned(),
            commit_seq: self.commit_seq,
            shard_id: self.shard_id,
        }
    }
}

impl SymbolTable {
    fn intern(&mut self, value: String) -> u32 {
        if let Some(id) = self.ids.get(value.as_str()) {
            return *id;
        }
        let id = self.values.len();
        let id = u32::try_from(id).expect("symbol table exceeded u32::MAX entries");
        self.values.push(value.clone());
        self.ids.insert(value, id);
        id
    }

    fn id(&self, value: &str) -> Option<u32> {
        self.ids.get(value).copied()
    }

    fn get(&self, id: u32) -> &str {
        &self.values[id as usize]
    }

    fn estimated_bytes(&self) -> usize {
        let value_bytes = self
            .values
            .iter()
            .map(|value| std::mem::size_of::<String>() + value.capacity())
            .sum::<usize>();
        let index_bytes = self
            .ids
            .keys()
            .map(|value| {
                std::mem::size_of::<String>() + value.capacity() + std::mem::size_of::<u32>()
            })
            .sum::<usize>();
        value_bytes + index_bytes
    }
}

impl NegativeFilter {
    fn from_compact_entries(entries: &[CompactDenyEntry], symbols: &SymbolTable) -> Self {
        if entries.is_empty() {
            return Self {
                bits: Vec::new(),
                bit_len: 0,
            };
        }

        let desired_bits = entries
            .len()
            .saturating_mul(NEGATIVE_FILTER_BITS_PER_ENTRY)
            .max(64);
        let words = desired_bits.div_ceil(64);
        let bit_len = words * 64;
        let mut filter = Self {
            bits: vec![0; words],
            bit_len,
        };

        for entry in entries {
            filter.insert_parts(
                symbols.get(entry.tenant_id),
                symbols.get(entry.namespace),
                entry.key_hash,
            );
        }

        filter
    }

    fn insert_parts(&mut self, tenant_id: &str, namespace: &str, key_hash: u64) {
        let (first, second) = self.hash_pair_parts(tenant_id, namespace, key_hash);
        for index in 0..NEGATIVE_FILTER_HASHES {
            let bit_index = self.bit_index(first, second, index);
            self.bits[bit_index / 64] |= 1u64 << (bit_index % 64);
        }
    }

    fn may_contain_parts(&self, tenant_id: &str, namespace: &str, key_hash: u64) -> bool {
        if self.bit_len == 0 {
            return false;
        }
        let (first, second) = self.hash_pair_parts(tenant_id, namespace, key_hash);
        for index in 0..NEGATIVE_FILTER_HASHES {
            let bit_index = self.bit_index(first, second, index);
            if (self.bits[bit_index / 64] & (1u64 << (bit_index % 64))) == 0 {
                return false;
            }
        }
        true
    }

    fn hash_pair_parts(&self, tenant_id: &str, namespace: &str, key_hash: u64) -> (u64, u64) {
        let seed = fingerprint_acl_key_parts(tenant_id, namespace, key_hash);
        let first = splitmix64(seed);
        let second = splitmix64(seed ^ 0x9e3779b97f4a7c15) | 1;
        (first, second)
    }

    fn bit_index(&self, first: u64, second: u64, index: usize) -> usize {
        let index = index as u64;
        let hash = first
            .wrapping_add(index.wrapping_mul(second))
            .wrapping_add(index.wrapping_mul(index));
        (hash as usize) % self.bit_len
    }
}

impl CompiledRules {
    fn from_rules(rules: Vec<RuleEntry>) -> Self {
        let mut compiled = Self {
            ipv4_by_prefix: vec![HashMap::new(); 33],
            domain_suffixes: HashMap::new(),
            rules_len: 0,
        };

        for rule in rules {
            if rule.action == Action::Delete {
                continue;
            }
            compiled.rules_len += 1;
            match rule.kind {
                RuleKind::Ipv4Cidr => {
                    let key = (rule.tenant_id.clone(), rule.ipv4_network);
                    compiled.ipv4_by_prefix[rule.ipv4_prefix_len as usize]
                        .entry(key)
                        .or_default()
                        .push(rule);
                }
                RuleKind::DomainSuffix => {
                    let key = (rule.tenant_id.clone(), rule.domain_suffix.clone());
                    compiled.domain_suffixes.entry(key).or_default().push(rule);
                }
            }
        }

        for prefix_bucket in &mut compiled.ipv4_by_prefix {
            for rules in prefix_bucket.values_mut() {
                rules.sort_by(compare_rules_for_match);
            }
        }
        for rules in compiled.domain_suffixes.values_mut() {
            rules.sort_by(compare_rules_for_match);
        }

        compiled
    }

    fn consider_matches(
        &self,
        tenant_id: &str,
        namespace: &str,
        raw_value: &str,
        now_unix: u64,
        removed: &HashMap<RuleKey, u64>,
        best: &mut RuleMatch,
    ) {
        match rule_kind_for_namespace(namespace) {
            Some(RuleKind::Ipv4Cidr) => {
                if let Ok(ip) = parse_ipv4_addr(raw_value) {
                    for prefix_len in (0..=32u8).rev() {
                        let network = mask_ipv4(ip, prefix_len);
                        let key = (tenant_id.to_owned(), network);
                        if let Some(rules) = self.ipv4_by_prefix[prefix_len as usize].get(&key) {
                            for rule in rules {
                                if !removed.contains_key(&rule.rule_key()) {
                                    best.consider(rule, now_unix);
                                }
                            }
                        }
                    }
                }
            }
            Some(RuleKind::DomainSuffix) => {
                let Ok(domain) = canonicalize_domain(raw_value) else {
                    return;
                };
                for suffix in domain_suffix_candidates(&domain) {
                    let key = (tenant_id.to_owned(), suffix);
                    if let Some(rules) = self.domain_suffixes.get(&key) {
                        for rule in rules {
                            if !removed.contains_key(&rule.rule_key()) {
                                best.consider(rule, now_unix);
                            }
                        }
                    }
                }
            }
            None => {}
        }
    }

    fn all_rules(&self) -> Vec<RuleEntry> {
        let mut rules = Vec::with_capacity(self.rules_len);
        for prefix_bucket in &self.ipv4_by_prefix {
            for bucket in prefix_bucket.values() {
                rules.extend(bucket.iter().cloned());
            }
        }
        for bucket in self.domain_suffixes.values() {
            rules.extend(bucket.iter().cloned());
        }
        rules
    }
}

#[derive(Default)]
struct RuleMatch {
    rule: Option<RuleEntry>,
}

impl RuleMatch {
    fn consider(&mut self, rule: &RuleEntry, now_unix: u64) {
        if rule.is_expired(now_unix) {
            return;
        }
        match &self.rule {
            Some(current) if compare_rules_for_match(rule, current) != Ordering::Less => {}
            _ => self.rule = Some(rule.clone()),
        }
    }

    fn into_decision(self) -> Decision {
        let Some(rule) = self.rule else {
            return Decision::Allow;
        };

        match rule.action {
            Action::Deny => Decision::Deny {
                reason_code: rule.reason_code,
                priority: rule.priority,
                commit_id: CommitId {
                    shard_id: rule.shard_id,
                    seq: rule.commit_seq,
                    epoch: 1,
                    source_region: String::new(),
                },
            },
            Action::AllowOverride | Action::Delete => Decision::Allow,
        }
    }
}

