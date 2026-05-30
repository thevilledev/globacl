import assert from "node:assert/strict";
import { test } from "node:test";

import { createControlClient } from "../dist/index.js";

test("client preserves base URL path prefixes", async () => {
  let observedUrl = "";
  const client = createControlClient("http://127.0.0.1:18000/api/control/", {
    fetch: async (input) => {
      observedUrl = String(input);
      return new Response('{"status":"ok"}', {
        headers: { "content-type": "application/json" },
        status: 200,
      });
    },
  });

  await client.health();

  assert.equal(observedUrl, "http://127.0.0.1:18000/api/control/health");
});
