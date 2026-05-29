#[cfg(test)]
mod tests {
    use super::*;

    fn consensus_test_app(root: &Path, node_id: &str, role: ConsensusRole, term: u64) -> App {
        let shard_count = 4u16;
        App {
            state: Mutex::new(SourceOfTruth::new(shard_count, "cluster-a")),
            log_dir: root.join("logs"),
            consensus_path: root.join("consensus.state"),
            idempotency_path: root.join("idempotency.glog"),
            pending_dir: root.join("pending"),
            bundle_dir: root.join("bundles"),
            snapshot_dir: root.join("snapshots"),
            snapshot_object_dir: root.join("snapshots").join("objects"),
            snapshot_manifest_dir: root.join("snapshots").join("manifests"),
            snapshot_path: root.join("snapshots").join("latest.gacl"),
            snapshot_manifest_path: root
                .join("snapshots")
                .join("manifests")
                .join("latest.manifest"),
            object_store: None,
            audit_path: root.join("audit.log"),
            publisher_offsets_path: root.join("publisher_offsets.state"),
            propagation_acks_path: root.join("propagation_acks.log"),
            signature_signer: SignatureSigner::ed25519_private_key(
                DEFAULT_SIGNATURE_KEY_ID,
                DEFAULT_SIGNATURE_KEY_VERSION,
                DEFAULT_SIGNATURE_PRIVATE_KEY,
            )
            .expect("test signer"),
            latest_canary: Mutex::new(None),
            replication: ReplicationConfig {
                cluster_id: "cluster-a".to_owned(),
                node_id: node_id.to_owned(),
                initial_leader_id: None,
                peers: vec![
                    ControlPeer {
                        node_id: "node-a".to_owned(),
                        addr: "127.0.0.1:7101".to_owned(),
                    },
                    ControlPeer {
                        node_id: "node-b".to_owned(),
                        addr: "127.0.0.1:7102".to_owned(),
                    },
                    ControlPeer {
                        node_id: "node-c".to_owned(),
                        addr: "127.0.0.1:7103".to_owned(),
                    },
                ],
                quorum: 2,
                heartbeat_interval_ms: 250,
                election_timeout_ms: 1200,
                sync_interval_ms: 1000,
            },
            compaction: CompactionConfig {
                min_log_entries: 10_000,
                compact_on_startup: true,
            },
            peer_token: Some("test-peer-token".to_owned()),
            consensus: Mutex::new(ConsensusState {
                current_term: term,
                voted_for: None,
                role,
                leader_id: (role == ConsensusRole::Leader).then(|| node_id.to_owned()),
                last_leader_contact_ms: 0,
                election_deadline_ms: u64::MAX,
            }),
            sync_status: Mutex::new(SyncStatus {
                last_peer_sync_unix: 0,
                sync_errors: 0,
            }),
            publisher: None,
            publisher_status: Mutex::new(PublisherStatus {
                last_published: vec![0; shard_count as usize],
                last_publish_unix: 0,
                publish_errors: 0,
            }),
            propagation_acks: Mutex::new(HashMap::new()),
            auth: AuthConfig::disabled(),
        }
    }

    fn test_form(fields: &[(&str, &str)]) -> HashMap<String, String> {
        let mut form = fields
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect::<HashMap<_, _>>();
        form.entry("cluster_id".to_owned())
            .or_insert_with(|| "cluster-a".to_owned());
        form
    }

    fn response_bool(body: &str, key: &str) -> bool {
        let form = parse_json_fields(body.as_bytes()).expect("parse response form");
        json_bool(&form, key)
    }

    fn deny_request(op_id: &str, key: &str) -> DenyRequest {
        DenyRequest {
            op_id: op_id.to_owned(),
            tenant_id: "tenant-a".to_owned(),
            namespace: "user".to_owned(),
            key: key.to_owned(),
            action: Action::Deny,
            priority: 0,
            reason_code: "test".to_owned(),
            expires_at: 0,
            created_by: "test".to_owned(),
            delivery_priority: DeliveryPriority::P1,
        }
    }

    fn prepared_mutation(op_id: &str, key: &str, epoch: u64) -> Mutation {
        let mut source = SourceOfTruth::new(4, "cluster-a");
        source.set_epoch(epoch);
        source
            .prepare_commit(deny_request(op_id, key))
            .expect("prepare mutation")
            .mutation
    }

    fn commit_two_mutations_on_same_shard(app: &App) -> (Mutation, Mutation) {
        let mut state = lock_state(app).expect("state");
        let first = state
            .commit(deny_request("op-1", "user-1"))
            .expect("first commit")
            .mutation;

        for suffix in 2..1000 {
            let op_id = format!("op-{suffix}");
            let key = format!("user-{suffix}");
            let request = deny_request(&op_id, &key);
            let prepared = state
                .prepare_commit(request.clone())
                .expect("prepare candidate")
                .mutation;
            if prepared.commit_id.shard_id == first.commit_id.shard_id {
                let second = state.commit(request).expect("second commit").mutation;
                return (first, second);
            }
        }

        panic!("could not find second mutation on shard {}", first.commit_id.shard_id);
    }

    fn enable_test_publisher(app: &mut App) {
        app.publisher = Some(PublisherConfig {
            nats_addr: "nats://127.0.0.1:4222".to_owned(),
            stream: "GLOBACL".to_owned(),
            subject_prefix: "globacl".to_owned(),
            publish_interval_ms: 100,
            autocreate_stream: false,
        });
    }

    fn remove_test_dir(path: impl AsRef<Path>) {
        match std::fs::remove_dir_all(path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => panic!("remove temp dir: {err}"),
        }
    }

    fn single_node_leader(root: &Path) -> App {
        let mut app = consensus_test_app(root, "node-a", ConsensusRole::Leader, 1);
        app.replication.peers = vec![ControlPeer {
            node_id: "node-a".to_owned(),
            addr: "127.0.0.1:7101".to_owned(),
        }];
        app.replication.quorum = 1;
        app
    }

    fn unavailable_object_store(require_upload: bool) -> ObjectStoreConfig {
        ObjectStoreConfig {
            endpoint: "http://127.0.0.1:1".to_owned(),
            region: "us-east-1".to_owned(),
            bucket: "globacl-test".to_owned(),
            prefix: "commitd-tests".to_owned(),
            access_key_id: "test-access".to_owned(),
            secret_access_key: "test-secret".to_owned(),
            session_token: None,
            force_path_style: true,
            request_timeout_ms: 500,
            allow_empty_bootstrap: false,
            require_upload,
        }
    }

    #[test]
    fn disk_full_before_log_append_does_not_apply_locally() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-disk-full-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = single_node_leader(&root);
        let _fault = set_test_storage_fault("mutation_log", StorageFault::DiskFull);

        let err = commit_request(&app, deny_request("op-disk-full", "user-1"))
            .expect_err("disk-full log write should reject commit");

        assert!(err.to_string().contains("simulated disk full"));
        let state = lock_state(&app).expect("state");
        assert_eq!(state.mutations_len(), 0);
        assert!(state.watermarks().iter().all(|seq| *seq == 0));
        drop(state);
        assert!(load_all_logs(&app.log_dir, 4)
            .expect("load logs after disk-full fault")
            .is_empty());
        remove_test_dir(root);
    }

    #[test]
    fn fsync_failure_during_snapshot_persist_keeps_durable_log() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-fsync-failure-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = single_node_leader(&root);
        let _fault = set_test_storage_fault("payload_file", StorageFault::Fsync);

        let err = commit_request(&app, deny_request("op-fsync", "user-1"))
            .expect_err("snapshot fsync failure should surface");

        assert!(err.to_string().contains("simulated fsync failure"));
        let state = lock_state(&app).expect("state");
        assert_eq!(state.mutations_len(), 1);
        let watermarks = state.watermarks().to_vec();
        drop(state);
        assert!(watermarks.iter().any(|seq| *seq == 1));
        let log = load_all_logs(&app.log_dir, 4).expect("load durable log");
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].op_id, "op-fsync");
        assert!(
            !app.snapshot_path.exists(),
            "failed fsync must not promote latest snapshot"
        );
        remove_test_dir(root);
    }

    #[test]
    fn corrupted_snapshot_is_rejected_on_restart_load() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-corrupt-snapshot-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 1);
        std::fs::create_dir_all(app.snapshot_path.parent().expect("snapshot parent"))
            .expect("create snapshot parent");
        std::fs::write(&app.snapshot_path, b"not-a-valid-snapshot").expect("write corrupt snapshot");

        let err = load_source_of_truth(
            &app.log_dir,
            &app.snapshot_path,
            &app.idempotency_path,
            4,
            &app.replication.cluster_id,
            None,
        )
        .expect_err("corrupt snapshot should not be accepted");

        assert!(err.to_string().contains("magic"));
        remove_test_dir(root);
    }

    #[test]
    fn corrupted_log_is_rejected_on_restart_load() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-corrupt-log-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 1);
        std::fs::create_dir_all(&app.log_dir).expect("create log dir");
        std::fs::write(app.log_dir.join("shard_0000.glog"), [8u8, 0, 0, 0, b'G', b'M'])
            .expect("write corrupt log");

        let err = load_source_of_truth(
            &app.log_dir,
            &app.snapshot_path,
            &app.idempotency_path,
            4,
            &app.replication.cluster_id,
            None,
        )
        .expect_err("corrupt log should not be accepted");

        assert!(
            err.to_string().contains("failed to fill whole buffer")
                || err.to_string().contains("magic"),
            "unexpected corrupt log error: {err}"
        );
        remove_test_dir(root);
    }

    #[test]
    fn object_store_outage_is_best_effort_by_default() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-object-store-best-effort-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let mut app = single_node_leader(&root);
        app.object_store = Some(unavailable_object_store(false));

        let outcome = commit_request(&app, deny_request("op-object-store-outage", "user-1"))
            .expect("best-effort object-store outage should not reject local commit");

        assert_eq!(outcome.mutation.op_id, "op-object-store-outage");
        assert!(app.snapshot_path.exists());
        assert!(app.snapshot_manifest_path.exists());
        remove_test_dir(root);
    }

    #[test]
    fn required_object_store_upload_outage_rejects_publication() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-object-store-required-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let mut app = single_node_leader(&root);
        app.object_store = Some(unavailable_object_store(true));
        let snapshot = {
            let state = lock_state(&app).expect("state");
            state.snapshot()
        };

        let err = persist_latest_snapshot(&app, &snapshot)
            .expect_err("required object-store outage should reject publication");

        assert!(err.to_string().contains("object store request failed"));
        assert!(app.snapshot_path.exists());
        remove_test_dir(root);
    }

    #[test]
    fn object_store_outage_blocks_bootstrap_without_local_state() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-object-store-bootstrap-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let store = unavailable_object_store(false);

        let err = restore_snapshot_before_load(
            Some(&store),
            &root.join("logs"),
            &root.join("snapshots").join("objects"),
            &root.join("snapshots").join("manifests"),
            &root.join("snapshots").join("latest.gacl"),
            &root
                .join("snapshots")
                .join("manifests")
                .join("latest.manifest"),
        )
        .expect_err("object-store outage should block remote bootstrap");

        assert!(err.to_string().contains("object store request failed"));
        remove_test_dir(root);
    }

    #[test]
    fn vote_request_rejects_stale_candidate_term() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-vote-stale-term-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 3);
        let response = handle_request_vote(
            &app,
            &test_form(&[
                ("term", "2"),
                ("candidate_id", "node-b"),
                ("last_seq", "0"),
                ("log_len", "0"),
            ]),
        )
        .expect("vote response");

        assert!(!response_bool(&response, "vote_granted"));
        let consensus = lock_consensus(&app).expect("consensus");
        assert_eq!(consensus.current_term, 3);
        assert_eq!(consensus.voted_for, None);
        drop(consensus);
        remove_test_dir(root);
    }

    #[test]
    fn vote_request_rejects_stale_candidate_log() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-vote-stale-log-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 1);
        {
            let mut state = lock_state(&app).expect("state");
            state.set_epoch(1);
            state
                .commit(deny_request("op-1", "user-1"))
                .expect("commit local mutation");
        }

        let response = handle_request_vote(
            &app,
            &test_form(&[
                ("term", "2"),
                ("candidate_id", "node-b"),
                ("last_seq", "0"),
                ("log_len", "0"),
            ]),
        )
        .expect("vote response");

        assert!(!response_bool(&response, "vote_granted"));
        let consensus = lock_consensus(&app).expect("consensus");
        assert_eq!(consensus.current_term, 2);
        assert_eq!(consensus.voted_for, None);
        drop(consensus);
        remove_test_dir(root);
    }

    #[test]
    fn vote_request_rejects_candidate_missing_local_shard_watermark() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-vote-stale-watermark-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 1);
        let mutation = {
            let mut state = lock_state(&app).expect("state");
            state
                .commit(deny_request("op-1", "user-1"))
                .expect("commit local mutation")
                .mutation
        };
        let mut candidate_watermarks = vec![999_u64; 4];
        candidate_watermarks[mutation.commit_id.shard_id as usize] = 0;
        let candidate_watermarks = json!(candidate_watermarks).to_string();

        let response = handle_request_vote(
            &app,
            &test_form(&[
                ("term", "2"),
                ("candidate_id", "node-b"),
                ("last_seq", "999"),
                ("log_len", "999"),
                ("watermarks", candidate_watermarks.as_str()),
            ]),
        )
        .expect("vote response");

        assert!(!response_bool(&response, "vote_granted"));
        let consensus = lock_consensus(&app).expect("consensus");
        assert_eq!(consensus.current_term, 2);
        assert_eq!(consensus.voted_for, None);
        drop(consensus);
        remove_test_dir(root);
    }

    #[test]
    fn vote_request_grants_only_one_vote_per_term() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-vote-once-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 1);

        let first = handle_request_vote(
            &app,
            &test_form(&[
                ("term", "2"),
                ("candidate_id", "node-b"),
                ("last_seq", "0"),
                ("log_len", "0"),
            ]),
        )
        .expect("first vote response");
        let second = handle_request_vote(
            &app,
            &test_form(&[
                ("term", "2"),
                ("candidate_id", "node-c"),
                ("last_seq", "0"),
                ("log_len", "0"),
            ]),
        )
        .expect("second vote response");

        assert!(response_bool(&first, "vote_granted"));
        assert!(!response_bool(&second, "vote_granted"));
        let consensus = lock_consensus(&app).expect("consensus");
        assert_eq!(consensus.current_term, 2);
        assert_eq!(consensus.voted_for.as_deref(), Some("node-b"));
        drop(consensus);
        remove_test_dir(root);
    }

    #[test]
    fn heartbeat_rejects_conflicting_leader_in_same_term() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-heartbeat-conflict-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 5);
        {
            let mut consensus = lock_consensus(&app).expect("consensus");
            consensus.voted_for = Some("node-b".to_owned());
            consensus.leader_id = Some("node-b".to_owned());
        }

        let conflicting =
            handle_heartbeat(&app, &test_form(&[("term", "5"), ("leader_id", "node-c")]))
                .expect("conflicting heartbeat");
        let accepted =
            handle_heartbeat(&app, &test_form(&[("term", "5"), ("leader_id", "node-b")]))
                .expect("accepted heartbeat");

        assert!(!response_bool(&conflicting, "success"));
        assert!(response_bool(&accepted, "success"));
        let consensus = lock_consensus(&app).expect("consensus");
        assert_eq!(consensus.current_term, 5);
        assert_eq!(consensus.leader_id.as_deref(), Some("node-b"));
        assert_eq!(consensus.voted_for.as_deref(), Some("node-b"));
        drop(consensus);
        remove_test_dir(root);
    }

    #[test]
    fn higher_term_heartbeat_steps_down_current_leader() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-heartbeat-stepdown-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Leader, 5);

        let response =
            handle_heartbeat(&app, &test_form(&[("term", "6"), ("leader_id", "node-b")]))
                .expect("heartbeat response");

        assert!(response_bool(&response, "success"));
        assert!(ensure_write_authority(&app).is_err());
        let consensus = lock_consensus(&app).expect("consensus");
        assert_eq!(consensus.current_term, 6);
        assert_eq!(consensus.role, ConsensusRole::Follower);
        assert_eq!(consensus.leader_id.as_deref(), Some("node-b"));
        assert_eq!(consensus.voted_for, None);
        drop(consensus);
        remove_test_dir(root);
    }

    #[test]
    fn consensus_state_restarts_with_persisted_term_and_vote() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-consensus-restart-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Candidate, 7);
        let persisted = ConsensusState {
            current_term: 7,
            voted_for: Some("node-b".to_owned()),
            role: ConsensusRole::Candidate,
            leader_id: None,
            last_leader_contact_ms: 123,
            election_deadline_ms: 456,
        };

        persist_consensus_state(&app.consensus_path, &persisted).expect("persist consensus");
        let loaded =
            load_consensus_state(&app.consensus_path, &app.replication).expect("load consensus");

        assert_eq!(loaded.current_term, 7);
        assert_eq!(loaded.voted_for.as_deref(), Some("node-b"));
        assert_eq!(loaded.role, ConsensusRole::Follower);
        assert_eq!(loaded.leader_id, None);
        remove_test_dir(root);
    }

    #[test]
    fn follower_sync_without_known_leader_is_noop() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-sync-no-leader-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Candidate, 3);

        sync_from_leader(&app).expect("sync without leader should be a noop");

        let sync_status = lock_sync_status(&app).expect("sync status");
        assert_eq!(sync_status.sync_errors, 0);
        drop(sync_status);
        remove_test_dir(root);
    }

    #[test]
    fn prepare_replaces_stale_pending_entry_from_older_term() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-pending-replace-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 1);
        let old = prepared_mutation("op-old", "user-1", 1);
        let mut new = old.clone();
        new.op_id = "op-new".to_owned();
        new.commit_id.epoch = 2;
        new.entry.reason_code = "newer-term".to_owned();

        prepare_replicated_mutation(&app, &old).expect("prepare old pending");
        prepare_replicated_mutation(&app, &new).expect("replace stale pending");

        let pending_path = pending_mutation_path(&app.pending_dir, &new);
        let pending = decode_mutation(&std::fs::read(pending_path).expect("read pending"))
            .expect("decode pending");
        assert_eq!(pending, new);
        let consensus = lock_consensus(&app).expect("consensus");
        assert_eq!(consensus.current_term, 2);
        drop(consensus);
        remove_test_dir(root);
    }

    #[test]
    fn pending_entry_rejects_older_epoch_replacement() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-pending-reject-old-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let pending_dir = root.join("pending");
        let mut newer = prepared_mutation("op-new", "user-1", 3);
        let mut older = newer.clone();
        older.op_id = "op-old".to_owned();
        older.commit_id.epoch = 2;
        newer.entry.reason_code = "newer-term".to_owned();

        write_pending_mutation(&pending_dir, &newer).expect("write newer pending");
        let err = write_pending_mutation(&pending_dir, &older).expect_err("reject older pending");

        assert!(err.to_string().contains("newer epoch"));
        remove_test_dir(root);
    }

    #[test]
    fn local_log_status_includes_durable_pending_mutations() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-pending-log-status-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 3);
        let mutation = prepared_mutation("op-pending-status", "user-1", 3);

        write_pending_mutation(&app.pending_dir, &mutation).expect("write pending");
        let (_last_seq, log_len, watermarks) = local_log_status(&app).expect("local status");

        assert_eq!(log_len, 1);
        assert_eq!(
            watermarks[mutation.commit_id.shard_id as usize],
            mutation.commit_id.seq
        );
        remove_test_dir(root);
    }

    #[test]
    fn new_leader_recovers_pending_mutation_in_current_term() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-pending-leader-recovery-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let mut app = consensus_test_app(&root, "node-a", ConsensusRole::Leader, 5);
        app.replication.peers = vec![ControlPeer {
            node_id: "node-a".to_owned(),
            addr: "127.0.0.1:7101".to_owned(),
        }];
        app.replication.quorum = 1;
        let old = prepared_mutation("op-recover-pending", "user-1", 4);

        write_pending_mutation(&app.pending_dir, &old).expect("write pending");
        let recovered =
            recover_pending_mutations_as_leader(&app).expect("recover pending as leader");

        assert_eq!(recovered, 1);
        assert!(!pending_mutation_path(&app.pending_dir, &old).exists());
        let state = lock_state(&app).expect("state");
        assert_eq!(state.mutations_len(), 1);
        assert_eq!(state.watermarks()[old.commit_id.shard_id as usize], old.commit_id.seq);
        let log = load_all_logs(&app.log_dir, 4).expect("load log");
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].op_id, old.op_id);
        assert_eq!(log[0].commit_id.epoch, 5);
        drop(state);
        remove_test_dir(root);
    }

    #[test]
    fn peer_commit_requires_matching_pending_entry() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-pending-required-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 1);
        let mutation = prepared_mutation("op-1", "user-1", 1);

        let err = commit_replicated_mutation(&app, mutation.clone(), true)
            .expect_err("commit without pending should fail");
        assert!(err.to_string().contains("pending mutation missing"));
        {
            let state = lock_state(&app).expect("state");
            assert_eq!(state.mutations_len(), 0);
        }

        prepare_replicated_mutation(&app, &mutation).expect("prepare mutation");
        let status =
            commit_replicated_mutation(&app, mutation.clone(), true).expect("commit prepared");
        assert_eq!(status, ApplyStatus::Applied);
        assert!(!pending_mutation_path(&app.pending_dir, &mutation).exists());
        {
            let state = lock_state(&app).expect("state");
            assert_eq!(state.mutations_len(), 1);
            assert_eq!(
                state.watermarks()[mutation.commit_id.shard_id as usize],
                mutation.commit_id.seq
            );
        }
        remove_test_dir(root);
    }

    #[test]
    fn follower_catch_up_replays_committed_mutation_without_pending_entry() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-catch-up-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 1);
        let mutation = prepared_mutation("op-1", "user-1", 1);

        let status =
            commit_replicated_mutation(&app, mutation.clone(), false).expect("catch-up replay");

        assert_eq!(status, ApplyStatus::Applied);
        assert!(!pending_mutation_path(&app.pending_dir, &mutation).exists());
        let state = lock_state(&app).expect("state");
        assert_eq!(state.mutations_len(), 1);
        assert_eq!(
            state.watermarks()[mutation.commit_id.shard_id as usize],
            mutation.commit_id.seq
        );
        drop(state);
        remove_test_dir(root);
    }

    #[test]
    fn log_compaction_rewrites_logs_and_preserves_idempotency_snapshot() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-log-compaction-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Leader, 1);

        let (one, two) = {
            let mut state = lock_state(&app).expect("state");
            let one = state
                .commit(deny_request("op-1", "user-1"))
                .expect("first commit")
                .mutation;
            let two = state
                .commit(deny_request("op-2", "user-2"))
                .expect("second commit")
                .mutation;
            persist_mutation(&app, &one).expect("persist first");
            persist_mutation(&app, &two).expect("persist second");
            (one, two)
        };

        {
            let mut state = lock_state(&app).expect("state");
            compact_mutation_logs_locked(&app, &mut state).expect("compact logs");
            assert_eq!(state.mutations_len(), 0);
            assert_eq!(state.compacted_watermarks(), state.watermarks());
        }

        assert!(load_all_logs(&app.log_dir, 4)
            .expect("load compacted logs")
            .is_empty());
        let idempotency =
            decode_mutation_stream(&std::fs::read(&app.idempotency_path).expect("idempotency"))
                .expect("decode idempotency");
        assert!(idempotency.contains(&one));
        assert!(idempotency.contains(&two));

        let loaded = load_source_of_truth(
            &app.log_dir,
            &app.snapshot_path,
            &app.idempotency_path,
            4,
            &app.replication.cluster_id,
            None,
        )
        .expect("load compacted source");
        let duplicate = loaded
            .prepare_commit(deny_request("op-1", "user-1"))
            .expect("prepare duplicate");
        assert!(duplicate.duplicate);
        assert_eq!(duplicate.mutation, one);

        remove_test_dir(root);
    }

    #[test]
    fn publisher_compaction_keeps_unpublished_mutation_tail() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-publisher-compaction-tail-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let mut app = consensus_test_app(&root, "node-a", ConsensusRole::Leader, 1);
        enable_test_publisher(&mut app);

        let (one, two) = commit_two_mutations_on_same_shard(&app);
        persist_mutation(&app, &one).expect("persist first");
        persist_mutation(&app, &two).expect("persist second");
        {
            let mut status = lock_publisher_status(&app).expect("publisher status");
            status.last_published[one.commit_id.shard_id as usize] = one.commit_id.seq;
        }

        {
            let mut state = lock_state(&app).expect("state");
            compact_mutation_logs_locked(&app, &mut state).expect("compact logs");
            assert_eq!(
                state.compacted_watermarks()[one.commit_id.shard_id as usize],
                one.commit_id.seq
            );
            assert_eq!(
                state.watermarks()[one.commit_id.shard_id as usize],
                two.commit_id.seq
            );
            assert_eq!(
                state.mutations_for_shard(one.commit_id.shard_id, one.commit_id.seq),
                vec![two.clone()]
            );
        }

        let log_tail = load_all_logs(&app.log_dir, 4).expect("load compacted logs");
        assert!(!log_tail.contains(&one));
        assert!(log_tail.contains(&two));

        let offsets = {
            let status = lock_publisher_status(&app).expect("publisher status");
            status.last_published.clone()
        };
        let loaded = load_source_of_truth(
            &app.log_dir,
            &app.snapshot_path,
            &app.idempotency_path,
            4,
            &app.replication.cluster_id,
            Some(offsets.as_slice()),
        )
        .expect("load publisher-compacted source");
        assert_eq!(
            loaded.compacted_watermarks()[one.commit_id.shard_id as usize],
            one.commit_id.seq
        );
        assert_eq!(
            loaded.watermarks()[one.commit_id.shard_id as usize],
            two.commit_id.seq
        );
        assert_eq!(
            loaded.mutations_for_shard(one.commit_id.shard_id, one.commit_id.seq),
            vec![two]
        );

        remove_test_dir(root);
    }

    #[test]
    fn publisher_compaction_rewrites_fully_published_logs() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-publisher-compaction-full-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let mut app = consensus_test_app(&root, "node-a", ConsensusRole::Leader, 1);
        enable_test_publisher(&mut app);

        let (one, two) = commit_two_mutations_on_same_shard(&app);
        persist_mutation(&app, &one).expect("persist first");
        persist_mutation(&app, &two).expect("persist second");
        {
            let mut status = lock_publisher_status(&app).expect("publisher status");
            status.last_published[two.commit_id.shard_id as usize] = two.commit_id.seq;
        }

        {
            let mut state = lock_state(&app).expect("state");
            compact_mutation_logs_locked(&app, &mut state).expect("compact logs");
            assert_eq!(state.mutations_len(), 0);
            assert_eq!(
                state.compacted_watermarks()[two.commit_id.shard_id as usize],
                two.commit_id.seq
            );
        }

        assert!(load_all_logs(&app.log_dir, 4)
            .expect("load compacted logs")
            .is_empty());

        remove_test_dir(root);
    }

    #[test]
    fn stale_leader_prepare_is_rejected_by_newer_term_peer() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-stale-prepare-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 3);
        let mutation = prepared_mutation("op-stale", "user-1", 2);

        let err = prepare_replicated_mutation(&app, &mutation)
            .expect_err("stale leader prepare should fail");

        assert!(err.to_string().contains("stale mutation epoch"));
        assert!(!pending_mutation_path(&app.pending_dir, &mutation).exists());
        let state = lock_state(&app).expect("state");
        assert_eq!(state.mutations_len(), 0);
        drop(state);
        remove_test_dir(root);
    }

    #[test]
    fn stale_leader_commit_is_rejected_by_newer_term_peer() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-stale-commit-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 3);
        let mutation = prepared_mutation("op-stale", "user-1", 2);

        let err = commit_replicated_mutation(&app, mutation.clone(), false)
            .expect_err("stale leader commit should fail");

        assert!(err.to_string().contains("stale mutation epoch"));
        let state = lock_state(&app).expect("state");
        assert_eq!(state.mutations_len(), 0);
        assert_eq!(state.watermarks()[mutation.commit_id.shard_id as usize], 0);
        drop(state);
        remove_test_dir(root);
    }

    #[test]
    fn replication_prepare_rejects_unknown_leader() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-unknown-leader-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 1);
        let mutation = prepared_mutation("op-unknown-leader", "user-1", 1);

        let err = prepare_replicated_mutation_from_leader(&app, &mutation, "node-x")
            .expect_err("unknown leader should be rejected");

        assert!(err.to_string().contains("unknown replication leader"));
        assert!(!pending_mutation_path(&app.pending_dir, &mutation).exists());
        remove_test_dir(root);
    }

    #[test]
    fn replication_routes_require_declared_leader_header() {
        let request = HttpRequest {
            method: "POST".to_owned(),
            path: "/internal/replication/prepare".to_owned(),
            headers: HashMap::new(),
            body: Vec::new(),
        };

        let err = required_replication_leader(&request)
            .expect_err("missing leader header should be rejected");

        assert!(err.to_string().contains("missing X-Globacl-Leader-Id"));
    }

    #[test]
    fn replication_prepare_rejects_conflicting_same_term_leader() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-conflicting-leader-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 3);
        {
            let mut consensus = lock_consensus(&app).expect("consensus");
            consensus.leader_id = Some("node-b".to_owned());
            consensus.voted_for = Some("node-b".to_owned());
        }
        let mutation = prepared_mutation("op-conflicting-leader", "user-1", 3);

        let err = prepare_replicated_mutation_from_leader(&app, &mutation, "node-c")
            .expect_err("conflicting leader should be rejected");

        assert!(err.to_string().contains("conflicting replication leader"));
        assert!(!pending_mutation_path(&app.pending_dir, &mutation).exists());
        let consensus = lock_consensus(&app).expect("consensus");
        assert_eq!(consensus.leader_id.as_deref(), Some("node-b"));
        assert_eq!(consensus.voted_for.as_deref(), Some("node-b"));
        drop(consensus);
        remove_test_dir(root);
    }

    #[test]
    fn same_term_heartbeat_is_accepted_after_vote_for_other_candidate() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-heartbeat-after-other-vote-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 3);
        {
            let mut consensus = lock_consensus(&app).expect("consensus");
            consensus.voted_for = Some("node-b".to_owned());
            consensus.leader_id = None;
        }

        let response =
            handle_heartbeat(&app, &test_form(&[("term", "3"), ("leader_id", "node-c")]))
                .expect("heartbeat response");

        assert!(response_bool(&response, "success"));
        let consensus = lock_consensus(&app).expect("consensus");
        assert_eq!(consensus.current_term, 3);
        assert_eq!(consensus.role, ConsensusRole::Follower);
        assert_eq!(consensus.leader_id.as_deref(), Some("node-c"));
        assert_eq!(consensus.voted_for.as_deref(), Some("node-b"));
        drop(consensus);
        remove_test_dir(root);
    }

    #[test]
    fn same_term_replication_is_accepted_after_vote_for_other_candidate() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-replication-after-other-vote-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Follower, 3);
        {
            let mut consensus = lock_consensus(&app).expect("consensus");
            consensus.voted_for = Some("node-b".to_owned());
            consensus.leader_id = None;
        }
        let mutation = prepared_mutation("op-same-term-leader", "user-1", 3);

        prepare_replicated_mutation_from_leader(&app, &mutation, "node-c")
            .expect("same-term leader should be accepted");

        assert!(pending_mutation_path(&app.pending_dir, &mutation).exists());
        let consensus = lock_consensus(&app).expect("consensus");
        assert_eq!(consensus.current_term, 3);
        assert_eq!(consensus.role, ConsensusRole::Follower);
        assert_eq!(consensus.leader_id.as_deref(), Some("node-c"));
        assert_eq!(consensus.voted_for.as_deref(), Some("node-b"));
        drop(consensus);
        remove_test_dir(root);
    }

    #[test]
    fn higher_term_replication_prepare_fences_local_leader() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-higher-term-leader-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Leader, 3);
        let mutation = prepared_mutation("op-higher-term", "user-1", 4);

        prepare_replicated_mutation_from_leader(&app, &mutation, "node-b")
            .expect("higher term leader should fence local leader");

        assert!(pending_mutation_path(&app.pending_dir, &mutation).exists());
        let consensus = lock_consensus(&app).expect("consensus");
        assert_eq!(consensus.current_term, 4);
        assert_eq!(consensus.role, ConsensusRole::Follower);
        assert_eq!(consensus.leader_id.as_deref(), Some("node-b"));
        assert_eq!(consensus.voted_for, None);
        drop(consensus);
        remove_test_dir(root);
    }

    #[test]
    fn leader_write_without_quorum_does_not_apply_locally() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-partitioned-leader-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Leader, 4);

        let err = commit_request(&app, deny_request("op-partitioned", "user-1"))
            .expect_err("partitioned leader should fail quorum prepare");

        assert!(err.to_string().contains("commitd quorum unavailable"));
        let state = lock_state(&app).expect("state");
        assert_eq!(state.mutations_len(), 0);
        assert_eq!(state.entries_len(), 0);
        assert!(state.watermarks().iter().all(|seq| *seq == 0));
        drop(state);
        remove_test_dir(root);
    }

    #[test]
    fn leader_ack_without_quorum_does_not_apply_locally() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-partitioned-ack-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Leader, 4);
        let ack = PropagationAck {
            relay_id: "relay-a".to_owned(),
            location: "region-a".to_owned(),
            agent_id: "agent-a".to_owned(),
            shard_id: 1,
            seq: 10,
            entries: 1,
            applied_at_unix: 1000,
            relay_received_at_unix: 1001,
        };

        let err = record_propagation_ack(&app, ack).expect_err("partitioned ack should fail");

        assert!(err.to_string().contains("commitd ack quorum unavailable"));
        assert_eq!(lock_propagation_acks(&app).expect("acks").len(), 0);
        assert!(!app.propagation_acks_path.exists());
        remove_test_dir(root);
    }

    #[test]
    fn stepped_down_leader_rejects_new_write() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-stepdown-write-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Leader, 4);

        handle_heartbeat(&app, &test_form(&[("term", "5"), ("leader_id", "node-b")]))
            .expect("higher-term heartbeat");
        let err = commit_request(&app, deny_request("op-after-stepdown", "user-1"))
            .expect_err("stepped-down leader should reject writes");

        assert!(err.to_string().contains("not the write leader"));
        let state = lock_state(&app).expect("state");
        assert_eq!(state.mutations_len(), 0);
        drop(state);
        remove_test_dir(root);
    }

    #[test]
    fn publisher_offsets_round_trip() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-offsets-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let path = root.join("publisher_offsets.state");
        let offsets = vec![1, 0, 42, u64::MAX - 1];

        persist_publisher_offsets(&path, &offsets).expect("persist offsets");

        let loaded = load_publisher_offsets(&path, offsets.len() as u16).expect("load offsets");
        assert_eq!(loaded, offsets);

        let expanded = load_publisher_offsets(&path, 6).expect("load expanded offsets");
        assert_eq!(&expanded[..4], offsets.as_slice());
        assert_eq!(&expanded[4..], &[0, 0]);

        std::fs::remove_dir_all(root).expect("remove temp offset dir");
    }

    #[test]
    fn propagation_ack_log_replays_latest_ack() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-acks-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let path = root.join("propagation_acks.log");
        let first = PropagationAck {
            relay_id: "relay-a".to_owned(),
            location: "region-a".to_owned(),
            agent_id: "agent-a".to_owned(),
            shard_id: 7,
            seq: 41,
            entries: 10,
            applied_at_unix: 1000,
            relay_received_at_unix: 1001,
        };
        let second = PropagationAck {
            seq: 42,
            entries: 11,
            applied_at_unix: 1002,
            relay_received_at_unix: 1003,
            ..first.clone()
        };

        append_propagation_ack(&path, &first).expect("append first ack");
        append_propagation_ack(&path, &second).expect("append second ack");

        let loaded = load_propagation_acks(&path).expect("load propagation acks");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get(&second.key()).expect("ack").seq, 42);

        std::fs::remove_dir_all(root).expect("remove temp ack dir");
    }

    #[test]
    fn propagation_ack_snapshot_rehydrates_follower_store() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-ack-snapshot-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let follower =
            consensus_test_app(&root.join("follower"), "node-b", ConsensusRole::Follower, 1);
        let first = PropagationAck {
            relay_id: "relay-a".to_owned(),
            location: "region-a".to_owned(),
            agent_id: "agent-a".to_owned(),
            shard_id: 7,
            seq: 41,
            entries: 10,
            applied_at_unix: 1000,
            relay_received_at_unix: 1001,
        };
        let second = PropagationAck {
            seq: 42,
            entries: 11,
            applied_at_unix: 1002,
            relay_received_at_unix: 1003,
            ..first.clone()
        };
        let snapshot = json!({
            "acks": [
                propagation_ack_json(&first),
                propagation_ack_json(&second)
            ]
        })
        .to_string();

        apply_propagation_ack_log_snapshot(&follower, snapshot.as_bytes())
            .expect("apply ack snapshot");

        let loaded = load_propagation_acks(&follower.propagation_acks_path)
            .expect("load follower acks");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get(&second.key()).expect("ack").seq, 42);

        std::fs::remove_dir_all(root).expect("remove temp ack snapshot dir");
    }

    #[test]
    fn empty_propagation_ack_snapshot_is_json_array() {
        let root = env::temp_dir().join(format!(
            "globacl-commitd-empty-ack-snapshot-{}-{}",
            std::process::id(),
            now_unix_millis()
        ));
        let app = consensus_test_app(&root, "node-a", ConsensusRole::Leader, 1);

        let snapshot = format_propagation_ack_log_snapshot(&app).expect("format empty snapshot");
        let value = parse_json_body(snapshot.as_bytes()).expect("parse empty snapshot JSON");
        assert_eq!(
            value.get("acks").and_then(JsonValue::as_array).map(Vec::len),
            Some(0)
        );
        assert_eq!(
            apply_propagation_ack_log_snapshot(&app, snapshot.as_bytes())
                .expect("apply empty snapshot"),
            0
        );

        let _ = std::fs::remove_dir_all(root);
    }
}
