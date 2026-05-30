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

## Global UI

The package also contains a vanilla TypeScript operational UI that uses this
client against a same-origin proxy:

```sh
pnpm run global-ui
```

By default it expects central control on `127.0.0.1:17000` and regional
agent/relay/demo port-forwards on `18201`/`18301`/`18101` and up. To create
that topology and keep the dashboard running:

```sh
./deploy/k3s/global-ui.sh
```
