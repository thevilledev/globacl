import type { components } from "./generated/schema.js";

export type DenyMutationRequest = components["schemas"]["DenyMutationRequest"];
export type RuleMutationRequest = components["schemas"]["RuleMutationRequest"];
export type AckRequest = components["schemas"]["AckRequest"];
export type RollbackRequest = components["schemas"]["RollbackRequest"];

export type CommitOutcomeResponse = components["schemas"]["CommitOutcomeResponse"];
export type DecisionResponse = components["schemas"]["DecisionResponse"];
export type HealthResponse = components["schemas"]["HealthResponse"];
export type WatermarksResponse = components["schemas"]["WatermarksResponse"];
export type CanaryStatusResponse = components["schemas"]["CanaryStatusResponse"];
export type LatestCanaryResponse = components["schemas"]["LatestCanaryResponse"];
export type StatusResponse = components["schemas"]["StatusResponse"];
export type SignatureEnvelope = components["schemas"]["SignatureEnvelope"];
export type RelayAcksResponse = components["schemas"]["RelayAcksResponse"];
export type PropagationStatusResponse = components["schemas"]["PropagationStatusResponse"];
export type SnapshotManifestResponse = components["schemas"]["SnapshotManifestResponse"];
export type SnapshotListResponse = components["schemas"]["SnapshotListResponse"];
export type RollbackResponse = components["schemas"]["RollbackResponse"];
export type AuditLogResponse = components["schemas"]["AuditLogResponse"];

export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export interface ClientOptions {
  fetch?: FetchLike;
  bearerToken?: string;
}

export interface LookupParams {
  tenant_id: string;
  namespace: string;
  key: string;
}

export interface CheckParams {
  tenant_id: string;
  namespace: string;
  value: string;
}

export interface MutationStreamParams {
  shard: number;
  from_seq?: number;
  delivery_priority?: components["schemas"]["DeliveryPriorityValue"];
}

export interface DeltaBundleParams {
  shard: number;
  from_seq?: number;
  to_seq?: number;
}

export class GlobaclApiError extends Error {
  readonly status: number;
  readonly body: string;

  constructor(status: number, body: string) {
    super(`globacl API returned status ${status}: ${body}`);
    this.name = "GlobaclApiError";
    this.status = status;
    this.body = body;
  }
}

export class GlobaclClient {
  readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;
  private readonly bearerToken: string | undefined;

  constructor(baseUrl: string, options: ClientOptions = {}) {
    this.baseUrl = normalizeBaseUrl(baseUrl);
    const fetchImpl = options.fetch ?? globalThis.fetch?.bind(globalThis);
    if (!fetchImpl) {
      throw new Error("globacl client requires a fetch implementation");
    }
    this.fetchImpl = fetchImpl;
    this.bearerToken = options.bearerToken;
  }

  health(): Promise<HealthResponse> {
    return this.getJson("/health");
  }

  deny(request: DenyMutationRequest): Promise<CommitOutcomeResponse> {
    return this.postJson("/v1/deny", request);
  }

  mutation(request: DenyMutationRequest): Promise<CommitOutcomeResponse> {
    return this.postJson("/v1/mutation", request);
  }

  rule(request: RuleMutationRequest): Promise<CommitOutcomeResponse> {
    return this.postJson("/v1/rule", request);
  }

  createCanary(): Promise<CanaryStatusResponse> {
    return this.postJson("/v1/canary", {});
  }

  latestCanary(): Promise<LatestCanaryResponse> {
    return this.getJson("/v1/canary/latest");
  }

  lookup(params: LookupParams): Promise<DecisionResponse> {
    return this.getJson(`/v1/lookup?${query({ ...params })}`);
  }

  check(params: CheckParams): Promise<DecisionResponse> {
    return this.getJson(`/v1/check?${query({ ...params })}`);
  }

  watermarks(): Promise<WatermarksResponse> {
    return this.getJson("/v1/watermarks");
  }

  compactionWatermarks(): Promise<WatermarksResponse> {
    return this.getJson("/v1/compaction_watermarks");
  }

  mutations(params: MutationStreamParams): Promise<ArrayBuffer> {
    return this.getBytes(`/v1/mutations?${query({ ...params })}`);
  }

  mutationSignature(params: MutationStreamParams): Promise<SignatureEnvelope> {
    return this.getJson(`/v1/mutations.sig?${query({ ...params })}`);
  }

  deltaBundle(params: DeltaBundleParams): Promise<ArrayBuffer> {
    return this.getBytes(`/v1/delta_bundle?${query({ ...params })}`);
  }

  deltaBundleSignature(params: DeltaBundleParams): Promise<SignatureEnvelope> {
    return this.getJson(`/v1/delta_bundle.sig?${query({ ...params })}`);
  }

  ack(request: AckRequest): Promise<StatusResponse> {
    return this.postJson("/v1/ack", request);
  }

  relayAcks(): Promise<RelayAcksResponse> {
    return this.getJson("/v1/acks");
  }

  propagationStatus(): Promise<PropagationStatusResponse> {
    return this.getJson("/v1/propagation/status");
  }

  snapshot(): Promise<ArrayBuffer> {
    return this.getBytes("/v1/snapshot");
  }

  uploadSnapshot(snapshot: ArrayBuffer | Uint8Array): Promise<StatusResponse> {
    return this.postBytes("/v1/snapshot", snapshot);
  }

  snapshotSignature(): Promise<SignatureEnvelope> {
    return this.getJson("/v1/snapshot.sig");
  }

  snapshotManifest(): Promise<SnapshotManifestResponse> {
    return this.getJson("/v1/snapshot_manifest");
  }

  snapshotManifestSignature(): Promise<SignatureEnvelope> {
    return this.getJson("/v1/snapshot_manifest.sig");
  }

  snapshotArtifact(object: string): Promise<ArrayBuffer> {
    return this.getBytes(`/v1/snapshot_artifact?${query({ object })}`);
  }

  snapshotArtifactSignature(object: string): Promise<SignatureEnvelope> {
    return this.getJson(`/v1/snapshot_artifact.sig?${query({ object })}`);
  }

  snapshots(): Promise<SnapshotListResponse> {
    return this.getJson("/v1/snapshots");
  }

  rollback(request: RollbackRequest): Promise<RollbackResponse> {
    return this.postJson("/v1/rollback", request);
  }

  audit(): Promise<AuditLogResponse> {
    return this.getJson("/v1/audit");
  }

  private getJson<T>(path: string): Promise<T> {
    return this.requestJson<T>("GET", path);
  }

  private postJson<T>(path: string, body: unknown): Promise<T> {
    return this.requestJson<T>("POST", path, body);
  }

  private async requestJson<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers = new Headers({ Accept: "application/json" });
    this.authorize(headers);
    const init: RequestInit = { method, headers };
    if (body !== undefined) {
      headers.set("Content-Type", "application/json");
      init.body = JSON.stringify(body);
    }

    const response = await this.fetchImpl(this.url(path), init);
    const text = await response.text();
    if (!response.ok) {
      throw new GlobaclApiError(response.status, text);
    }
    return (text ? JSON.parse(text) : {}) as T;
  }

  private async getBytes(path: string): Promise<ArrayBuffer> {
    const response = await this.fetchImpl(this.url(path), {
      method: "GET",
      headers: this.headers({ Accept: "application/octet-stream" }),
    });
    if (!response.ok) {
      throw new GlobaclApiError(response.status, await response.text());
    }
    return response.arrayBuffer();
  }

  private async postBytes<T>(path: string, body: ArrayBuffer | Uint8Array): Promise<T> {
    const payload =
      body instanceof Uint8Array
        ? (new Uint8Array(body).buffer as ArrayBuffer)
        : body;
    const response = await this.fetchImpl(this.url(path), {
      method: "POST",
      headers: this.headers({
        Accept: "application/json",
        "Content-Type": "application/octet-stream",
      }),
      body: payload,
    });
    const text = await response.text();
    if (!response.ok) {
      throw new GlobaclApiError(response.status, text);
    }
    return (text ? JSON.parse(text) : {}) as T;
  }

  private url(path: string): URL {
    return new URL(path, this.baseUrl);
  }

  private headers(values: HeadersInit): Headers {
    const headers = new Headers(values);
    this.authorize(headers);
    return headers;
  }

  private authorize(headers: Headers): void {
    if (this.bearerToken) {
      headers.set("Authorization", `Bearer ${this.bearerToken}`);
    }
  }
}

export function createControlClient(baseUrl: string, options?: ClientOptions): GlobaclClient {
  return new GlobaclClient(baseUrl, options);
}

export function createAgentClient(baseUrl: string, options?: ClientOptions): GlobaclClient {
  return new GlobaclClient(baseUrl, options);
}

export function assertSafeInteger(value: number, fieldName = "value"): number {
  if (!Number.isSafeInteger(value)) {
    throw new Error(`${fieldName} is not a JavaScript-safe integer: ${value}`);
  }
  return value;
}

function normalizeBaseUrl(baseUrl: string): string {
  if (baseUrl.trim() === "") {
    throw new Error("globacl client requires a base URL");
  }
  return baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
}

function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      search.set(key, String(value));
    }
  }
  return search.toString();
}
