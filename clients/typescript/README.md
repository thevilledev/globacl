# globacl TypeScript Client

Generated schema bindings live in `src/generated/schema.d.ts`. The ergonomic
fetch wrapper is in `src/client.ts`.

Use:

```ts
import { createControlClient } from "@globacl/client";

const client = createControlClient("http://127.0.0.1:7000", {
  bearerToken: "admin-token",
});
const outcome = await client.deny({
  op_id: "demo-1",
  tenant_id: "tenant-a",
  namespace: "user",
  key: "user-123",
  action: "deny",
});
```

Regenerate from `docs/openapi.yaml`:

```sh
scripts/generate-clients.sh
```
