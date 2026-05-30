import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const distRoot = path.resolve(here, "..");

const args = parseArgs(process.argv.slice(2));
const host = args.host ?? process.env.GLOBACL_UI_HOST ?? "127.0.0.1";
const port = Number(args.port ?? process.env.GLOBACL_UI_PORT ?? "18000");
const controlTarget = withTrailingSlash(
  process.env.GLOBACL_UI_CONTROL_URL ??
    `http://127.0.0.1:${process.env.CENTRAL_HOST_PORT ?? "17000"}`,
);
const regions = splitList(process.env.GLOBACL_UI_REGIONS ?? process.env.REGIONS ?? "region-a region-b region-c");
const demoBasePort = Number(process.env.DEMO_BASE_PORT ?? "18100");
const agentBasePort = Number(process.env.AGENT_BASE_PORT ?? "18200");
const relayBasePort = Number(process.env.RELAY_BASE_PORT ?? "18300");
const configuredRegions = regions.map((name, index) => ({
  name,
  agentTarget: withTrailingSlash(
    process.env[`GLOBACL_UI_${envKey(name)}_AGENT_URL`] ??
      `http://127.0.0.1:${agentBasePort + index + 1}`,
  ),
  relayTarget: withTrailingSlash(
    process.env[`GLOBACL_UI_${envKey(name)}_RELAY_URL`] ??
      `http://127.0.0.1:${relayBasePort + index + 1}`,
  ),
  demoTarget: withTrailingSlash(
    process.env[`GLOBACL_UI_${envKey(name)}_DEMO_URL`] ??
      `http://127.0.0.1:${demoBasePort + index + 1}`,
  ),
}));

const server = http.createServer((request, response) => {
  void handleRequest(request, response);
});

server.listen(port, host, () => {
  const url = `http://${host}:${port}/global-ui/`;
  console.log(`globacl global UI: ${url}`);
  console.log(`control proxy: ${controlTarget}`);
  for (const region of configuredRegions) {
    console.log(
      `${region.name}: agent=${region.agentTarget} relay=${region.relayTarget} demo=${region.demoTarget}`,
    );
  }
});

async function handleRequest(request, response) {
  try {
    const url = new URL(request.url ?? "/", `http://${request.headers.host ?? `${host}:${port}`}`);
    if (url.pathname === "/api/config") {
      writeJson(response, configPayload(request));
      return;
    }

    if (url.pathname.startsWith("/api/control/")) {
      await proxy(request, response, controlTarget, url.pathname.slice("/api/control/".length), url.search);
      return;
    }

    const regionMatch = url.pathname.match(/^\/api\/regions\/([^/]+)\/(agent|relay|demo)\/(.*)$/);
    if (regionMatch) {
      const [, rawRegion, kind, suffix] = regionMatch;
      const region = configuredRegions.find((candidate) => candidate.name === decodeURIComponent(rawRegion ?? ""));
      if (!region) {
        writeJson(response, { error: "unknown_region" }, 404);
        return;
      }
      const target =
        kind === "agent" ? region.agentTarget : kind === "relay" ? region.relayTarget : region.demoTarget;
      await proxy(request, response, target, suffix ?? "", url.search);
      return;
    }

    await serveStatic(url.pathname, response);
  } catch (error) {
    writeJson(response, { error: error instanceof Error ? error.message : String(error) }, 500);
  }
}

function configPayload(request) {
  const origin = `http://${request.headers.host ?? `${host}:${port}`}`;
  return {
    controlBaseUrl: `${origin}/api/control/`,
    regions: configuredRegions.map((region) => ({
      name: region.name,
      agentBaseUrl: `${origin}/api/regions/${encodeURIComponent(region.name)}/agent/`,
      relayBaseUrl: `${origin}/api/regions/${encodeURIComponent(region.name)}/relay/`,
      demoBaseUrl: `${origin}/api/regions/${encodeURIComponent(region.name)}/demo/`,
    })),
    target: {
      tenantId: process.env.GLOBACL_UI_TENANT_ID ?? "tenant-a",
      namespace: process.env.GLOBACL_UI_NAMESPACE ?? "user",
      key: process.env.GLOBACL_UI_KEY ?? "user-global",
    },
    pollMs: Number(process.env.GLOBACL_UI_POLL_MS ?? "2000"),
  };
}

async function proxy(request, response, targetBase, suffix, search) {
  const target = new URL(`${suffix}${search}`, targetBase);
  const headers = new Headers();
  for (const [key, value] of Object.entries(request.headers)) {
    if (!value || shouldDropRequestHeader(key)) {
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        headers.append(key, item);
      }
    } else {
      headers.set(key, value);
    }
  }

  const init = {
    method: request.method,
    headers,
  };
  if (request.method !== "GET" && request.method !== "HEAD") {
    const body = await readRequestBody(request);
    headers.set("Content-Length", String(body.byteLength));
    init.body = body;
  }

  const upstream = await fetch(target, init);
  response.writeHead(upstream.status, Object.fromEntries(upstream.headers.entries()));
  if (!upstream.body) {
    response.end();
    return;
  }
  const reader = upstream.body.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      response.end();
      return;
    }
    response.write(value);
  }
}

async function readRequestBody(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

async function serveStatic(rawPathname, response) {
  const pathname = rawPathname === "/" ? "/global-ui/" : rawPathname;
  const relativePath = pathname.endsWith("/")
    ? `${pathname.slice(1)}index.html`
    : pathname.slice(1);
  const filePath = path.resolve(distRoot, relativePath);
  const relative = path.relative(distRoot, filePath);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    writeJson(response, { error: "bad_path" }, 400);
    return;
  }

  try {
    const fileStat = await stat(filePath);
    if (!fileStat.isFile()) {
      writeJson(response, { error: "not_found" }, 404);
      return;
    }
  } catch {
    writeJson(response, { error: "not_found" }, 404);
    return;
  }

  response.writeHead(200, { "Content-Type": contentType(filePath) });
  createReadStream(filePath).pipe(response);
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (item === "--host") {
      parsed.host = argv[index + 1];
      index += 1;
    } else if (item?.startsWith("--host=")) {
      parsed.host = item.slice("--host=".length);
    } else if (item === "--port") {
      parsed.port = argv[index + 1];
      index += 1;
    } else if (item?.startsWith("--port=")) {
      parsed.port = item.slice("--port=".length);
    }
  }
  return parsed;
}

function splitList(value) {
  return value
    .split(/[,\s]+/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function envKey(value) {
  return value.replace(/[^a-zA-Z0-9]/g, "_").toUpperCase();
}

function withTrailingSlash(value) {
  return value.endsWith("/") ? value : `${value}/`;
}

function shouldDropRequestHeader(key) {
  return ["connection", "content-length", "host", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"].includes(
    key.toLowerCase(),
  );
}

function writeJson(response, payload, status = 200) {
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(JSON.stringify(payload));
}

function contentType(filePath) {
  if (filePath.endsWith(".html")) {
    return "text/html; charset=utf-8";
  }
  if (filePath.endsWith(".css")) {
    return "text/css; charset=utf-8";
  }
  if (filePath.endsWith(".js")) {
    return "text/javascript; charset=utf-8";
  }
  return "application/octet-stream";
}
