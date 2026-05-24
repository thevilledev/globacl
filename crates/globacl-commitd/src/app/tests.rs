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
        fields
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
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
        assert_eq!(consensus.voted_for.as_deref(), Some("node-b"));
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
