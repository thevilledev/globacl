import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import { test } from "node:test";

test("global UI proxy forwards POST bodies with content-length", async (t) => {
  let observed = null;
  const upstream = http.createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => {
      chunks.push(Buffer.from(chunk));
    });
    request.on("end", () => {
      observed = {
        method: request.method,
        url: request.url,
        contentLength: request.headers["content-length"],
        transferEncoding: request.headers["transfer-encoding"],
        body: Buffer.concat(chunks).toString("utf8"),
      };
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end('{"status":"ok"}');
    });
  });
  const upstreamPort = await listen(upstream, 0);
  t.after(() => {
    upstream.close();
  });

  const proxyPort = await reservePort();
  const proxy = spawn(process.execPath, ["dist/global-ui/server.mjs", "--port", String(proxyPort)], {
    env: {
      ...process.env,
      GLOBACL_UI_CONTROL_URL: `http://127.0.0.1:${upstreamPort}`,
      GLOBACL_UI_REGIONS: "region-a",
    },
    stdio: "ignore",
  });
  t.after(() => {
    proxy.kill();
  });

  await waitForHttp(`http://127.0.0.1:${proxyPort}/api/config`);

  const body = '{"op_id":"ui-test"}';
  const response = await fetch(`http://127.0.0.1:${proxyPort}/api/control/v1/deny`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });

  assert.equal(response.status, 200);
  assert.equal(observed?.method, "POST");
  assert.equal(observed?.url, "/v1/deny");
  assert.equal(observed?.body, body);
  assert.equal(observed?.contentLength, String(Buffer.byteLength(body)));
  assert.equal(observed?.transferEncoding, undefined);
});

function listen(server, port) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      server.off("error", reject);
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("server did not expose a TCP address"));
        return;
      }
      resolve(address.port);
    });
  });
}

async function reservePort() {
  const server = http.createServer();
  const port = await listen(server, 0);
  await new Promise((resolve) => {
    server.close(resolve);
  });
  return port;
}

async function waitForHttp(url) {
  const deadline = Date.now() + 5000;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => {
      setTimeout(resolve, 50);
    });
  }
  throw lastError ?? new Error(`timed out waiting for ${url}`);
}
