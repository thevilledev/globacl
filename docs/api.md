# API

The API uses newline-delimited `key=value` request bodies instead of JSON.

Required fields for `POST /v1/deny`:

```text
op_id
tenant_id
namespace
key
```

Optional fields:

```text
action=deny|allow_override|delete
priority=0
reason_code=unspecified
expires_at=0
created_by=unknown
```

Useful endpoints:

```text
GET  /health
POST /v1/deny
GET  /v1/mutations?shard=0&from_seq=0
GET  /v1/snapshot
GET  /v1/lookup?tenant_id=...&namespace=...&key=...
```
