#[cfg(test)]
mod tests {
    use super::*;

    fn request(op_id: &str, key: &str, action: Action) -> DenyRequest {
        DenyRequest {
            op_id: op_id.to_owned(),
            tenant_id: "tenant-a".to_owned(),
            namespace: "user".to_owned(),
            key: key.to_owned(),
            action,
            priority: 10,
            reason_code: "test".to_owned(),
            expires_at: 0,
            created_by: "unit-test".to_owned(),
            delivery_priority: DeliveryPriority::P1,
        }
    }

    fn rule_request(op_id: &str, kind: RuleKind, pattern: &str, action: Action) -> RuleRequest {
        RuleRequest {
            op_id: op_id.to_owned(),
            tenant_id: "tenant-a".to_owned(),
            kind,
            pattern: pattern.to_owned(),
            action,
            priority: 50,
            reason_code: "rule-test".to_owned(),
            expires_at: 0,
            created_by: "unit-test".to_owned(),
            delivery_priority: DeliveryPriority::P1,
        }
    }

    #[test]
    fn duplicate_op_id_is_idempotent() {
        let mut source = SourceOfTruth::new(16, "local");
        let first = source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let second = source.commit(request("op-1", "u1", Action::Deny)).unwrap();

        assert!(!first.duplicate);
        assert!(second.duplicate);
        assert_eq!(first.mutation.commit_id, second.mutation.commit_id);
        assert_eq!(source.mutations_len(), 1);
    }

    #[test]
    fn prepared_commit_is_not_visible_until_applied() {
        let mut source = SourceOfTruth::new(16, "local");
        let prepared = source
            .prepare_commit(request("op-1", "u1", Action::Deny))
            .unwrap();

        assert_eq!(source.mutations_len(), 0);
        assert_eq!(
            source.lookup("tenant-a", "user", "u1", now_unix()),
            Decision::Allow
        );

        let status = source
            .apply_replicated_mutation(prepared.mutation.clone())
            .unwrap();
        assert_eq!(status, ApplyStatus::Applied);
        assert!(source
            .lookup("tenant-a", "user", "u1", now_unix())
            .is_denied());

        let duplicate = source
            .apply_replicated_mutation(prepared.mutation.clone())
            .unwrap();
        assert_eq!(duplicate, ApplyStatus::DuplicateOrOld);
        assert_eq!(source.mutations_len(), 1);
    }

    #[test]
    fn active_state_applies_and_deletes_mutations() {
        let mut source = SourceOfTruth::new(16, "local");
        let add = source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let delete = source
            .commit(request("op-2", "u1", Action::Delete))
            .unwrap();

        let mut active = ActiveState::new(16);
        active.apply_mutation(&add.mutation).unwrap();
        assert!(active
            .lookup("tenant-a", "user", "u1", now_unix())
            .is_denied());

        active.apply_mutation(&delete.mutation).unwrap();
        assert_eq!(
            active.lookup("tenant-a", "user", "u1", now_unix()),
            Decision::Allow
        );
    }

    #[test]
    fn active_state_uses_base_and_delta_overlay() {
        let mut source = SourceOfTruth::new(16, "local");
        source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let mut active = ActiveState::from_snapshot(source.snapshot()).unwrap();

        assert_eq!(active.stats().base_entries, 1);
        assert_eq!(active.stats().delta_adds, 0);
        assert!(active
            .lookup("tenant-a", "user", "u1", now_unix())
            .is_denied());

        let add = source.commit(request("op-2", "u2", Action::Deny)).unwrap();
        active.apply_mutation(&add.mutation).unwrap();

        assert_eq!(active.stats().base_entries, 1);
        assert_eq!(active.stats().delta_adds, 1);
        assert!(active
            .lookup("tenant-a", "user", "u2", now_unix())
            .is_denied());

        active.compact_delta_overlay();
        assert_eq!(active.stats().base_entries, 2);
        assert_eq!(active.stats().delta_adds, 0);
        assert!(active
            .lookup("tenant-a", "user", "u2", now_unix())
            .is_denied());
    }

    #[test]
    fn active_state_exposes_base_filter_probe_for_benchmarks() {
        let mut source = SourceOfTruth::new(16, "local");
        source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let active = ActiveState::from_snapshot(source.snapshot()).unwrap();

        assert_eq!(active.stats().filter_hashes, NEGATIVE_FILTER_HASHES);
        assert!(active.base_filter_may_contain("tenant-a", "user", "u1"));
    }

    #[test]
    fn active_state_handle_loads_and_swaps_rcu_style() {
        let mut source = SourceOfTruth::new(16, "local");
        source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let handle = ActiveStateHandle::from_snapshot(source.snapshot()).unwrap();

        let old_reader = handle.load();
        assert!(old_reader
            .lookup("tenant-a", "user", "u1", now_unix())
            .is_denied());

        handle.store(ActiveState::new(16));

        assert!(old_reader
            .lookup("tenant-a", "user", "u1", now_unix())
            .is_denied());
        assert_eq!(
            handle.load().lookup("tenant-a", "user", "u1", now_unix()),
            Decision::Allow
        );
    }

    #[test]
    fn snapshot_round_trips() {
        let mut source = SourceOfTruth::new(16, "local");
        source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        source.commit(request("op-2", "u2", Action::Deny)).unwrap();
        source
            .commit_rule(rule_request(
                "rule-1",
                RuleKind::Ipv4Cidr,
                "10.0.0.0/8",
                Action::Deny,
            ))
            .unwrap();

        let snapshot = source.snapshot();
        let decoded = decode_snapshot(&encode_snapshot(&snapshot)).unwrap();
        let active = ActiveState::from_snapshot(decoded).unwrap();

        assert!(active
            .lookup("tenant-a", "user", "u1", now_unix())
            .is_denied());
        assert!(active
            .lookup("tenant-a", "user", "u2", now_unix())
            .is_denied());
        assert_eq!(
            active.lookup("tenant-a", "user", "u3", now_unix()),
            Decision::Allow
        );
        assert!(active
            .check("tenant-a", "ip", "10.1.2.3", now_unix())
            .is_denied());
    }

    #[test]
    fn snapshot_manifest_round_trips_and_validates_artifact() {
        let mut source = SourceOfTruth::new(16, "local");
        source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let snapshot = source.snapshot();
        let payload = encode_snapshot(&snapshot);
        let sha256 = snapshot_artifact_sha256_hex(&payload);
        let object = immutable_snapshot_object_name(&snapshot, &sha256);
        let manifest = SnapshotManifest::for_snapshot(
            &snapshot,
            1234,
            object.clone(),
            payload.len() as u64,
            sha256,
        );

        assert!(is_safe_snapshot_object_name(&object));
        let decoded = decode_snapshot_manifest(&encode_snapshot_manifest(&manifest)).unwrap();

        assert_eq!(decoded, manifest);
        decoded.validate_artifact(&payload).unwrap();
        decoded.validate_snapshot(&snapshot).unwrap();
        assert!(decoded.validate_artifact(b"changed").is_err());
    }

    #[test]
    fn mutation_stream_round_trips() {
        let mut source = SourceOfTruth::new(16, "local");
        let one = source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let two = source.commit(request("op-2", "u2", Action::Deny)).unwrap();

        let encoded = encode_mutation_stream(&[one.mutation.clone(), two.mutation.clone()]);
        let decoded = decode_mutation_stream(&encoded).unwrap();
        assert_eq!(decoded, vec![one.mutation, two.mutation]);
    }

    #[test]
    fn mutation_priority_round_trips() {
        let mut source = SourceOfTruth::new(16, "local");
        let mut request = request("op-1", "u1", Action::Deny);
        request.delivery_priority = DeliveryPriority::P0;
        let outcome = source.commit(request).unwrap();

        let decoded = decode_mutation(&encode_mutation(&outcome.mutation)).unwrap();

        assert_eq!(decoded.delivery_priority, DeliveryPriority::P0);
        assert_ne!(decoded.committed_at_unix, 0);
    }

    #[test]
    fn ipv4_rule_matches_source_and_active_state() {
        let mut source = SourceOfTruth::new(16, "local");
        let outcome = source
            .commit_rule(rule_request(
                "rule-1",
                RuleKind::Ipv4Cidr,
                "192.168.0.0/16",
                Action::Deny,
            ))
            .unwrap();

        assert!(source
            .check("tenant-a", "ip", "192.168.10.20", now_unix())
            .is_denied());
        assert_eq!(
            source.check("tenant-a", "ip", "192.169.10.20", now_unix()),
            Decision::Allow
        );

        let decoded = decode_mutation(&encode_mutation(&outcome.mutation)).unwrap();
        assert!(decoded.rule.is_some());

        let active = ActiveState::from_snapshot(source.snapshot()).unwrap();
        assert!(active
            .check("tenant-a", "ipv4", "192.168.1.1", now_unix())
            .is_denied());
    }

    #[test]
    fn domain_suffix_rule_matches_subdomains() {
        let mut source = SourceOfTruth::new(16, "local");
        source
            .commit_rule(rule_request(
                "rule-1",
                RuleKind::DomainSuffix,
                "*.Example.COM.",
                Action::Deny,
            ))
            .unwrap();

        let active = ActiveState::from_snapshot(source.snapshot()).unwrap();
        assert!(active
            .check("tenant-a", "domain", "api.example.com", now_unix())
            .is_denied());
        assert!(active
            .check("tenant-a", "domain", "example.com", now_unix())
            .is_denied());
        assert_eq!(
            active.check("tenant-a", "domain", "example.org", now_unix()),
            Decision::Allow
        );
    }

    #[test]
    fn rule_delete_removes_base_rule_through_overlay() {
        let mut source = SourceOfTruth::new(16, "local");
        source
            .commit_rule(rule_request(
                "rule-1",
                RuleKind::Ipv4Cidr,
                "10.0.0.0/8",
                Action::Deny,
            ))
            .unwrap();
        let mut active = ActiveState::from_snapshot(source.snapshot()).unwrap();
        let delete = source
            .commit_rule(rule_request(
                "rule-2",
                RuleKind::Ipv4Cidr,
                "10.0.0.0/8",
                Action::Delete,
            ))
            .unwrap();

        active.apply_mutation(&delete.mutation).unwrap();
        assert_eq!(
            active.check("tenant-a", "ip", "10.1.2.3", now_unix()),
            Decision::Allow
        );
        assert_eq!(active.stats().delta_rule_removes, 1);
    }

    #[test]
    fn blast_radius_helpers_flag_broad_denies() {
        let broad_point = DenyRequest {
            namespace: "tenant".to_owned(),
            key: "*".to_owned(),
            ..request("op-1", "u1", Action::Deny)
        };
        assert!(deny_requires_blast_radius_override(&broad_point));
        assert!(!deny_requires_blast_radius_override(&request(
            "op-2",
            "u1",
            Action::Deny
        )));

        assert!(rule_requires_blast_radius_override(&rule_request(
            "rule-1",
            RuleKind::Ipv4Cidr,
            "0.0.0.0/0",
            Action::Deny,
        )));
        assert!(!rule_requires_blast_radius_override(&rule_request(
            "rule-2",
            RuleKind::Ipv4Cidr,
            "10.0.0.0/8",
            Action::Deny,
        )));
        assert!(rule_requires_blast_radius_override(&rule_request(
            "rule-3",
            RuleKind::DomainSuffix,
            "com",
            Action::Deny,
        )));
        assert!(!rule_requires_blast_radius_override(&rule_request(
            "rule-4",
            RuleKind::DomainSuffix,
            "example.com",
            Action::Deny,
        )));
    }

    #[test]
    fn restore_snapshot_generates_forward_rollback_mutations() {
        let mut source = SourceOfTruth::new(16, "local");
        source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let empty = SourceOfTruth::new(16, "local").snapshot();

        let mutations = source.restore_snapshot(empty, "rollback-test").unwrap();

        assert_eq!(mutations.len(), 1);
        assert_eq!(mutations[0].entry.action, Action::Delete);
        assert_eq!(
            source.lookup("tenant-a", "user", "u1", now_unix()),
            Decision::Allow
        );
        assert_eq!(source.mutations_len(), 2);
    }

    #[test]
    fn payload_signature_verifies_exact_bytes() {
        let payload = b"snapshot-bytes";
        let signature = payload_signature_hex(DEFAULT_SIGNATURE_PRIVATE_KEY, payload).unwrap();

        assert!(
            verify_payload_signature(DEFAULT_SIGNATURE_PUBLIC_KEY, payload, &signature).unwrap()
        );
        assert!(
            !verify_payload_signature(DEFAULT_SIGNATURE_PUBLIC_KEY, b"changed", &signature)
                .unwrap()
        );

        let formatted = format_payload_signature(
            DEFAULT_SIGNATURE_KEY_ID,
            DEFAULT_SIGNATURE_PRIVATE_KEY,
            payload,
        )
        .unwrap();
        assert!(formatted.contains("algorithm=ed25519"));
        assert!(formatted.contains("key_id=dev-ed25519"));
        assert!(formatted.contains("key_version=1"));
    }

    #[test]
    fn payload_signature_accepts_non_default_keypair() {
        // RFC 8032 Ed25519 test vector 2.
        let private_key = "hex:4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
        let public_key = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
        let payload = [0x72];
        let expected_signature = concat!(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        );

        let signature = payload_signature_hex(private_key, &payload).unwrap();
        assert_eq!(signature, expected_signature);
        assert!(verify_payload_signature(public_key, &payload, &signature).unwrap());
        assert!(
            !verify_payload_signature(DEFAULT_SIGNATURE_PUBLIC_KEY, &payload, &signature).unwrap()
        );

        let formatted = format_payload_signature("custom-ed25519", private_key, &payload).unwrap();
        assert!(formatted.contains("algorithm=ed25519"));
        assert!(formatted.contains("key_id=custom-ed25519"));
        assert!(formatted.contains("key_version=1"));
        assert!(formatted.contains(expected_signature));
    }

    #[test]
    fn signature_verifier_rejects_key_version_downgrade() {
        let payload = b"snapshot-bytes";
        let signer = SignatureSigner::ed25519_private_key(
            DEFAULT_SIGNATURE_KEY_ID,
            1,
            DEFAULT_SIGNATURE_PRIVATE_KEY,
        )
        .unwrap();
        let signature = signer.sign_payload(payload).unwrap();
        let verifier =
            SignatureVerifier::single(DEFAULT_SIGNATURE_KEY_ID, 1, DEFAULT_SIGNATURE_PUBLIC_KEY, 1)
                .unwrap();
        verify_payload_signature_with_verifier(&verifier, payload, signature.as_bytes()).unwrap();

        let strict_verifier =
            SignatureVerifier::single(DEFAULT_SIGNATURE_KEY_ID, 1, DEFAULT_SIGNATURE_PUBLIC_KEY, 2)
                .unwrap();
        assert!(verify_payload_signature_with_verifier(
            &strict_verifier,
            payload,
            signature.as_bytes()
        )
        .is_err());
    }

    #[test]
    fn signature_public_keyring_parses_key_versions() {
        let value = format!(
            "{}:{}:{}\n",
            DEFAULT_SIGNATURE_KEY_ID, DEFAULT_SIGNATURE_KEY_VERSION, DEFAULT_SIGNATURE_PUBLIC_KEY
        );
        let keys = parse_signature_public_keys(&value).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, DEFAULT_SIGNATURE_KEY_ID);
        assert_eq!(keys[0].key_version, DEFAULT_SIGNATURE_KEY_VERSION);
        assert_eq!(keys[0].public_key_hex, DEFAULT_SIGNATURE_PUBLIC_KEY);

        let prefixed = format!(
            "{}:hex:{}",
            DEFAULT_SIGNATURE_KEY_ID, DEFAULT_SIGNATURE_PUBLIC_KEY
        );
        let keys = parse_signature_public_keys(&prefixed).unwrap();
        assert_eq!(keys[0].key_version, DEFAULT_SIGNATURE_KEY_VERSION);
        assert_eq!(
            keys[0].public_key_hex,
            format!("hex:{DEFAULT_SIGNATURE_PUBLIC_KEY}")
        );
    }

    #[test]
    fn gap_detection_rejects_out_of_order_apply() {
        let mut source = SourceOfTruth::new(1, "local");
        let first = source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let second = source.commit(request("op-2", "u2", Action::Deny)).unwrap();
        let mut active = ActiveState::new(1);

        let err = active.apply_mutation(&second.mutation).unwrap_err();
        assert!(matches!(err, GlobAclError::Gap { .. }));

        active.apply_mutation(&first.mutation).unwrap();
        active.apply_mutation(&second.mutation).unwrap();
        assert!(active
            .lookup("tenant-a", "user", "u2", now_unix())
            .is_denied());
    }

    #[test]
    fn append_log_replays_source_of_truth() {
        let root = std::env::temp_dir().join(format!(
            "globacl-core-test-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let log_dir = root.join("logs");

        let mut source = SourceOfTruth::new(16, "local");
        let one = source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let two = source.commit(request("op-2", "u2", Action::Deny)).unwrap();
        append_mutation_to_log(&log_dir, &one.mutation).unwrap();
        append_mutation_to_log(&log_dir, &two.mutation).unwrap();

        let loaded = load_all_logs(&log_dir, 16).unwrap();
        let replayed = SourceOfTruth::from_mutations(16, "local", loaded).unwrap();

        assert_eq!(replayed.mutations_len(), 2);
        assert!(replayed
            .lookup("tenant-a", "user", "u1", now_unix())
            .is_denied());
        assert!(replayed
            .lookup("tenant-a", "user", "u2", now_unix())
            .is_denied());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn snapshot_checkpoint_replays_tail_and_preserves_idempotency() {
        let mut source = SourceOfTruth::new(1, "local");
        let one = source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let checkpoint = source.snapshot();
        let two = source.commit(request("op-2", "u2", Action::Deny)).unwrap();

        let replayed = SourceOfTruth::from_snapshot_and_mutations(
            1,
            "local",
            checkpoint,
            vec![one.mutation.clone()],
            vec![two.mutation.clone()],
        )
        .unwrap();

        assert_eq!(replayed.mutations_len(), 1);
        assert_eq!(replayed.compacted_watermarks(), &[1]);
        assert_eq!(replayed.mutation_history_compacted(0, 0), Some(1));
        assert!(replayed
            .lookup("tenant-a", "user", "u1", now_unix())
            .is_denied());
        assert!(replayed
            .lookup("tenant-a", "user", "u2", now_unix())
            .is_denied());

        let duplicate = replayed
            .prepare_commit(request("op-1", "u1", Action::Deny))
            .unwrap();
        assert!(duplicate.duplicate);
        assert_eq!(duplicate.mutation, one.mutation);
    }

    #[test]
    fn compact_logs_to_watermarks_keeps_only_tail() {
        let root = std::env::temp_dir().join(format!(
            "globacl-core-compact-test-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let log_dir = root.join("logs");

        let mut source = SourceOfTruth::new(1, "local");
        let one = source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let two = source.commit(request("op-2", "u2", Action::Deny)).unwrap();
        append_mutation_to_log(&log_dir, &one.mutation).unwrap();
        append_mutation_to_log(&log_dir, &two.mutation).unwrap();

        let tail = load_logs_after_watermarks(&log_dir, 1, &[1]).unwrap();
        assert_eq!(tail, vec![two.mutation.clone()]);

        compact_logs_to_watermarks(&log_dir, 1, &[1]).unwrap();
        let compacted = read_shard_log(&log_dir, 0).unwrap();
        assert_eq!(compacted, vec![two.mutation]);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn delta_bundle_file_round_trips() {
        let root = std::env::temp_dir().join(format!(
            "globacl-core-bundle-test-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let bundle_dir = root.join("bundles");

        let mut source = SourceOfTruth::new(16, "local");
        let one = source.commit(request("op-1", "u1", Action::Deny)).unwrap();
        let path = write_delta_bundle_file(
            &bundle_dir,
            one.mutation.commit_id.shard_id,
            one.mutation.commit_id.seq,
            one.mutation.commit_id.seq,
            std::slice::from_ref(&one.mutation),
        )
        .unwrap();

        let decoded = read_delta_bundle_file(path).unwrap();
        assert_eq!(decoded, vec![one.mutation]);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pop_ack_parses_and_formats() {
        let form = parse_form_lines(
            b"agent_id=pop-a\nshard_id=7\nseq=42\nentries=12\napplied_at_unix=1000\n",
        )
        .unwrap();
        let ack = PopAck::from_form(&form).unwrap();

        assert_eq!(ack.agent_id, "pop-a");
        assert_eq!(ack.shard_id, 7);
        assert_eq!(ack.seq, 42);
        assert!(ack.to_form_body().contains("agent_id=pop-a"));
    }

    #[test]
    fn propagation_ack_parses_and_formats() {
        let form = parse_form_lines(
            b"relay_id=relay-a\nlocation=region-a\nagent_id=pop-a\nshard_id=7\nseq=42\nentries=12\napplied_at_unix=1000\nrelay_received_at_unix=1001\n",
        )
        .unwrap();
        let ack = PropagationAck::from_form(&form).unwrap();

        assert_eq!(ack.relay_id, "relay-a");
        assert_eq!(ack.location, "region-a");
        assert_eq!(ack.agent_id, "pop-a");
        assert_eq!(ack.shard_id, 7);
        assert_eq!(ack.seq, 42);
        assert_eq!(ack.key(), "relay-a:pop-a:7");
        assert!(ack.to_form_body().contains("relay_id=relay-a"));
    }

    #[test]
    fn json_u64_field_parses_jetstream_counters() {
        let payload = br#"{"type":"io.nats.jetstream.api.v1.consumer_info_response","num_ack_pending":2,"num_pending":17,"num_redelivered":1,"num_waiting":0}"#;

        assert_eq!(json_u64_field(payload, "num_pending"), Some(17));
        assert_eq!(json_u64_field(payload, "num_ack_pending"), Some(2));
        assert_eq!(json_u64_field(payload, "num_redelivered"), Some(1));
        assert_eq!(json_u64_field(payload, "num_waiting"), Some(0));
        assert_eq!(json_u64_field(payload, "missing"), None);
    }

    #[test]
    fn watermarks_round_trip() {
        let watermarks = vec![0, 7, 42];
        let decoded = parse_watermarks(format_watermarks(&watermarks).as_bytes()).unwrap();
        assert_eq!(decoded, watermarks);
    }
}
