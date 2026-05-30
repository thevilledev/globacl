#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_health_includes_commitd_consensus_fields() {
        let app = App {
            commit_addr: "127.0.0.1:7003".to_owned(),
            auth: AuthConfig::disabled(),
        };
        let body = control_health_ok(
            &app,
            br#"{
                "status": "ok",
                "role": "leader",
                "node_id": "commitd-0",
                "cluster_id": "central",
                "leader_id": "commitd-0",
                "term": 7,
                "write_authority": true,
                "quorum": 2,
                "peer_count": 3
            }"#,
        );
        let object = body.as_object().expect("health body should be an object");

        assert_eq!(
            object.get("role").and_then(JsonValue::as_str),
            Some("control")
        );
        assert_eq!(
            object.get("commitd").and_then(JsonValue::as_str),
            Some("ok")
        );
        assert_eq!(
            object.get("commitd_role").and_then(JsonValue::as_str),
            Some("leader")
        );
        assert_eq!(
            object.get("commitd_node_id").and_then(JsonValue::as_str),
            Some("commitd-0")
        );
        assert_eq!(
            object.get("commitd_term").and_then(JsonValue::as_u64),
            Some(7)
        );
        assert_eq!(
            object
                .get("commitd_write_authority")
                .and_then(JsonValue::as_bool),
            Some(true)
        );
        assert_eq!(
            object.get("commitd_quorum").and_then(JsonValue::as_u64),
            Some(2)
        );
        assert_eq!(
            object
                .get("commitd_peer_count")
                .and_then(JsonValue::as_u64),
            Some(3)
        );
    }
}
