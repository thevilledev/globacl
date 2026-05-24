#[cfg(test)]
mod tests {
    use super::*;
    use globacl_core::{write_snapshot_file, Action, DeliveryPriority, DenyRequest, SourceOfTruth};
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use std::{env, fs};

    #[test]
    fn embedded_handle_serves_lookup_without_http() {
        let root = temp_root("globacl-agent-embedded");
        let snapshot_path = root.join("latest.gacl");

        let mut source = SourceOfTruth::new(16, "test");
        source
            .commit(DenyRequest {
                op_id: "embedded-deny".to_owned(),
                tenant_id: "tenant-a".to_owned(),
                namespace: "user".to_owned(),
                key: "user-123".to_owned(),
                action: Action::Deny,
                priority: 100,
                reason_code: "test".to_owned(),
                expires_at: 0,
                created_by: "test".to_owned(),
                delivery_priority: DeliveryPriority::P1,
            })
            .expect("commit deny");
        write_snapshot_file(&snapshot_path, &source.snapshot()).expect("write snapshot");

        let config = AgentConfig::new("127.0.0.1:1", snapshot_path.clone())
            .expect("agent config")
            .with_agent_id("embedded-test")
            .with_stale_after(Duration::from_secs(60));
        let handle = load_snapshot_handle(config).expect("load embedded handle");

        assert!(matches!(
            handle.lookup("tenant-a", "user", "user-123", now_unix()),
            Decision::Deny { .. }
        ));
        assert_eq!(
            handle.lookup("tenant-a", "user", "other", now_unix()),
            Decision::Allow
        );
        assert!(!handle.health().expect("health").stale);

        let _ = fs::remove_dir_all(root);
    }

    fn temp_root(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }
}
