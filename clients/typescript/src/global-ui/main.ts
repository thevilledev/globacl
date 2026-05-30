import {
  GlobaclApiError,
  createAgentClient,
  createControlClient,
  type AuditLogResponse,
  type CanaryStatusResponse,
  type CommitOutcomeResponse,
  type DecisionResponse,
  type DenyMutationRequest,
  type HealthResponse,
  type LatestCanaryResponse,
  type PropagationStatusResponse,
  type RelayAcksResponse,
  type RuleMutationRequest,
  type SnapshotListResponse,
  type SnapshotManifestResponse,
  type WatermarksResponse,
  type components,
} from "../index.js";

type PropagationAckStatus = components["schemas"]["PropagationAckStatus"];
type DeliveryPriority = NonNullable<DenyMutationRequest["delivery_priority"]>;

interface LookupTarget {
  tenantId: string;
  namespace: string;
  key: string;
}

interface RegionConfig {
  name: string;
  agentBaseUrl: string;
  relayBaseUrl: string;
  demoBaseUrl: string;
}

interface ServerConfig {
  controlBaseUrl: string;
  regions: RegionConfig[];
  target: LookupTarget;
  pollMs: number;
}

interface UiConfig extends ServerConfig {
  bearerToken: string;
}

interface OkResult<T> {
  ok: true;
  value: T;
}

interface ErrResult {
  ok: false;
  label: string;
  message: string;
}

type LoadResult<T> = OkResult<T> | ErrResult;

interface RegionSnapshot {
  config: RegionConfig;
  agentHealth: LoadResult<HealthResponse>;
  relayHealth: LoadResult<HealthResponse>;
  demoHealth: LoadResult<HealthResponse>;
  relayAcks: LoadResult<RelayAcksResponse>;
  decision: LoadResult<DecisionResponse>;
}

interface DashboardSnapshot {
  capturedAt: Date;
  centralHealth: LoadResult<HealthResponse>;
  centralDecision: LoadResult<DecisionResponse>;
  propagation: LoadResult<PropagationStatusResponse>;
  watermarks: LoadResult<WatermarksResponse>;
  compactionWatermarks: LoadResult<WatermarksResponse>;
  latestCanary: LoadResult<LatestCanaryResponse>;
  snapshotManifest: LoadResult<SnapshotManifestResponse>;
  snapshots: LoadResult<SnapshotListResponse>;
  audit: LoadResult<AuditLogResponse>;
  regions: RegionSnapshot[];
}

interface UiEvent {
  at: Date;
  level: "info" | "error";
  title: string;
  detail: string;
}

type MutationMode = "point" | "rule";

interface UiState {
  config: UiConfig;
  snapshot: DashboardSnapshot | null;
  loading: boolean;
  busyAction: string | null;
  mutationMode: MutationMode;
  events: UiEvent[];
}

const DEFAULT_TARGET: LookupTarget = {
  tenantId: "tenant-a",
  namespace: "user",
  key: "user-global",
};

const STORAGE_KEY = "globacl.global-ui.config";
const MAX_EVENT_COUNT = 20;
const MAX_AUDIT_ITEMS = 80;

const appRoot = document.querySelector<HTMLDivElement>("#app");
if (!appRoot) {
  throw new Error("missing #app root");
}
const app = appRoot;

let state: UiState = {
  config: {
    controlBaseUrl: "http://127.0.0.1:17000",
    regions: [
      defaultRegion("region-a", 1),
      defaultRegion("region-b", 2),
      defaultRegion("region-c", 3),
    ],
    target: DEFAULT_TARGET,
    pollMs: 2000,
    bearerToken: "",
  },
  snapshot: null,
  loading: false,
  busyAction: null,
  mutationMode: "point",
  events: [],
};

let pollTimer = 0;
let refreshInFlight = false;

void bootstrap();

async function bootstrap(): Promise<void> {
  const serverConfig = await loadServerConfig();
  const savedConfig = loadSavedConfig();
  state.config = mergeConfig(serverConfig, savedConfig);
  render();
  await refresh();
  restartPolling();
}

function defaultRegion(name: string, index: number): RegionConfig {
  return {
    name,
    agentBaseUrl: `http://127.0.0.1:${18200 + index}`,
    relayBaseUrl: `http://127.0.0.1:${18300 + index}`,
    demoBaseUrl: `http://127.0.0.1:${18100 + index}`,
  };
}

async function loadServerConfig(): Promise<ServerConfig | null> {
  try {
    const response = await fetch("/api/config", { headers: { Accept: "application/json" } });
    if (!response.ok) {
      return null;
    }
    return (await response.json()) as ServerConfig;
  } catch {
    return null;
  }
}

function loadSavedConfig(): Partial<UiConfig> | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as Partial<UiConfig>;
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

function mergeConfig(
  serverConfig: ServerConfig | null,
  savedConfig: Partial<UiConfig> | null,
): UiConfig {
  const base: UiConfig = {
    controlBaseUrl: serverConfig?.controlBaseUrl ?? state.config.controlBaseUrl,
    regions:
      serverConfig?.regions && serverConfig.regions.length > 0
        ? serverConfig.regions
        : state.config.regions,
    target: serverConfig?.target ?? state.config.target,
    pollMs: serverConfig?.pollMs ?? state.config.pollMs,
    bearerToken: "",
  };

  if (!savedConfig) {
    return base;
  }

  return {
    controlBaseUrl: nonEmpty(savedConfig.controlBaseUrl, base.controlBaseUrl),
    regions:
      Array.isArray(savedConfig.regions) && savedConfig.regions.length > 0
        ? savedConfig.regions.map(normalizeRegion).filter((region) => region.name !== "")
        : base.regions,
    target: {
      tenantId: nonEmpty(savedConfig.target?.tenantId, base.target.tenantId),
      namespace: nonEmpty(savedConfig.target?.namespace, base.target.namespace),
      key: nonEmpty(savedConfig.target?.key, base.target.key),
    },
    pollMs:
      typeof savedConfig.pollMs === "number" && savedConfig.pollMs >= 500
        ? Math.round(savedConfig.pollMs)
        : base.pollMs,
    bearerToken: savedConfig.bearerToken ?? "",
  };
}

function normalizeRegion(region: RegionConfig): RegionConfig {
  return {
    name: String(region.name ?? "").trim(),
    agentBaseUrl: String(region.agentBaseUrl ?? "").trim(),
    relayBaseUrl: String(region.relayBaseUrl ?? "").trim(),
    demoBaseUrl: String(region.demoBaseUrl ?? "").trim(),
  };
}

function nonEmpty(value: string | undefined, fallback: string): string {
  const normalized = value?.trim();
  return normalized && normalized.length > 0 ? normalized : fallback;
}

function saveConfig(): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state.config));
}

function restartPolling(): void {
  if (pollTimer !== 0) {
    window.clearInterval(pollTimer);
  }
  pollTimer = window.setInterval(() => {
    void refresh({ quiet: true });
  }, state.config.pollMs);
}

async function refresh(options: { quiet?: boolean } = {}): Promise<void> {
  if (refreshInFlight) {
    return;
  }
  refreshInFlight = true;
  state.loading = true;
  if (!options.quiet) {
    render();
  }

  try {
    state.snapshot = await loadDashboardSnapshot();
  } finally {
    state.loading = false;
    refreshInFlight = false;
    render();
  }
}

async function loadDashboardSnapshot(): Promise<DashboardSnapshot> {
  const control = createControlClient(state.config.controlBaseUrl, clientOptions());
  const target = state.config.target;

  const [
    centralHealth,
    centralDecision,
    propagation,
    watermarks,
    compactionWatermarks,
    latestCanary,
    snapshotManifest,
    snapshots,
    audit,
    regions,
  ] = await Promise.all([
    capture("central health", control.health()),
    capture(
      "central decision",
      control.check({
        tenant_id: target.tenantId,
        namespace: target.namespace,
        value: target.key,
      }),
    ),
    capture("propagation status", control.propagationStatus()),
    capture("source watermarks", control.watermarks()),
    capture("compaction watermarks", control.compactionWatermarks()),
    capture("latest canary", control.latestCanary()),
    capture("snapshot manifest", control.snapshotManifest()),
    capture("snapshot list", control.snapshots()),
    capture("audit log", control.audit()),
    Promise.all(state.config.regions.map(loadRegionSnapshot)),
  ]);

  return {
    capturedAt: new Date(),
    centralHealth,
    centralDecision,
    propagation,
    watermarks,
    compactionWatermarks,
    latestCanary,
    snapshotManifest,
    snapshots,
    audit,
    regions,
  };
}

async function loadRegionSnapshot(config: RegionConfig): Promise<RegionSnapshot> {
  const agent = createAgentClient(config.agentBaseUrl);
  const relay = createAgentClient(config.relayBaseUrl);
  const demo = createAgentClient(config.demoBaseUrl);
  const target = state.config.target;
  const [agentHealth, relayHealth, demoHealth, relayAcks, decision] = await Promise.all([
    capture(`${config.name} agent health`, agent.health()),
    capture(`${config.name} relay health`, relay.health()),
    capture(`${config.name} demo health`, demo.health()),
    capture(`${config.name} relay acks`, relay.relayAcks()),
    capture(
      `${config.name} edge decision`,
      agent.check({
        tenant_id: target.tenantId,
        namespace: target.namespace,
        value: target.key,
      }),
    ),
  ]);

  return {
    config,
    agentHealth,
    relayHealth,
    demoHealth,
    relayAcks,
    decision,
  };
}

function clientOptions(): { bearerToken?: string } {
  const bearerToken = state.config.bearerToken.trim();
  return bearerToken ? { bearerToken } : {};
}

async function capture<T>(label: string, promise: Promise<T>): Promise<LoadResult<T>> {
  try {
    return { ok: true, value: await promise };
  } catch (error) {
    return {
      ok: false,
      label,
      message: errorMessage(error),
    };
  }
}

function errorMessage(error: unknown): string {
  if (error instanceof GlobaclApiError) {
    const detail = error.body.trim();
    return detail ? `HTTP ${error.status}: ${detail}` : `HTTP ${error.status}`;
  }
  return error instanceof Error ? error.message : String(error);
}

function render(): void {
  app.innerHTML = `
    <header class="topbar">
      <div>
        <p class="eyebrow">globacl</p>
        <h1>Global system view</h1>
      </div>
      <div class="topbar-actions">
        ${renderRefreshState()}
        <button class="icon-button" id="refresh-button" type="button" title="Refresh">Refresh</button>
        <button class="icon-button" id="canary-button" type="button" title="Create canary" ${state.busyAction ? "disabled" : ""}>Canary</button>
      </div>
    </header>
    <main class="layout">
      ${renderConfigPanel()}
      ${renderMetricGrid()}
      ${renderTopology()}
      <div class="content-grid">
        ${renderMutationPanel()}
        ${renderRegionalPanel()}
        ${renderWatermarksPanel()}
        ${renderPropagationPanel()}
        ${renderSnapshotPanel()}
        ${renderEventsPanel()}
      </div>
    </main>
  `;
  bindEvents();
}

function renderRefreshState(): string {
  const snapshot = state.snapshot;
  const label = snapshot
    ? `${formatTime(snapshot.capturedAt)}`
    : state.loading
      ? "loading"
      : "not loaded";
  const tone = state.loading ? "warn" : "ok";
  return `<span class="status-pill ${tone}">${escapeHtml(label)}</span>`;
}

function renderConfigPanel(): string {
  const config = state.config;
  return `
    <details class="panel config-panel">
      <summary class="section-heading config-summary">
        <div>
          <p class="eyebrow">connection</p>
          <h2>Endpoints and probe target</h2>
        </div>
        <span class="status-pill neutral">${state.config.regions.length} regions</span>
      </summary>
      <form id="config-form">
        <div class="config-body">
          <div class="config-grid">
            <label>
              <span>Control API</span>
              <input name="controlBaseUrl" value="${escapeHtml(config.controlBaseUrl)}" autocomplete="off" />
            </label>
            <label>
              <span>Tenant</span>
              <input name="tenantId" value="${escapeHtml(config.target.tenantId)}" autocomplete="off" />
            </label>
            <label>
              <span>Namespace</span>
              <input name="namespace" value="${escapeHtml(config.target.namespace)}" autocomplete="off" />
            </label>
            <label>
              <span>Probe key</span>
              <input name="key" value="${escapeHtml(config.target.key)}" autocomplete="off" />
            </label>
            <label>
              <span>Bearer token</span>
              <input name="bearerToken" value="${escapeHtml(config.bearerToken)}" type="password" autocomplete="off" />
            </label>
            <label>
              <span>Poll ms</span>
              <input name="pollMs" type="number" min="500" step="500" value="${config.pollMs}" />
            </label>
          </div>
          <div class="region-editor">
            <div class="table-head regions-head">
              <span>Region</span>
              <span>Agent API</span>
              <span>Relay API</span>
              <span>Demo API</span>
              <span></span>
            </div>
            ${config.regions.map(renderRegionEditorRow).join("")}
          </div>
          <div class="form-actions">
            <button type="submit">Apply</button>
            <button type="button" id="add-region-button">+ Region</button>
          </div>
        </div>
      </form>
    </details>
  `;
}

function renderRegionEditorRow(region: RegionConfig, index: number): string {
  return `
    <div class="region-row" data-region-row="${index}">
      <input name="regionName" value="${escapeHtml(region.name)}" autocomplete="off" />
      <input name="agentBaseUrl" value="${escapeHtml(region.agentBaseUrl)}" autocomplete="off" />
      <input name="relayBaseUrl" value="${escapeHtml(region.relayBaseUrl)}" autocomplete="off" />
      <input name="demoBaseUrl" value="${escapeHtml(region.demoBaseUrl)}" autocomplete="off" />
      <button type="button" class="small-button icon-only" data-remove-region="${index}" title="Remove region" aria-label="Remove region">x</button>
    </div>
  `;
}

function renderMetricGrid(): string {
  const snapshot = state.snapshot;
  const health = okValue(snapshot?.centralHealth);
  const propagation = okValue(snapshot?.propagation);
  const manifest = okValue(snapshot?.snapshotManifest);
  const canary = okValue(snapshot?.latestCanary);
  const watermarks = okValue(snapshot?.watermarks);
  const nonZeroShards = watermarks ? watermarkEntries(watermarks).filter((entry) => entry.seq > 0).length : 0;
  const canaryLabel = canary
    ? canary.status === "ok"
      ? `seq ${formatInt(canary.seq)}`
      : "none"
    : "unknown";

  return `
    <section class="metric-grid">
      ${renderMetric("Central", health?.status ?? "unknown", healthTone(health), health?.role ?? "control")}
      ${renderMetric("Propagation", propagation?.status ?? "unknown", propagationTone(propagation), `lag ${formatInt(propagation?.max_seq_lag ?? 0)}`)}
      ${renderMetric("Agents", formatInt(propagation?.agent_count ?? 0), "neutral", `${formatInt(propagation?.relay_count ?? 0)} relays`)}
      ${renderMetric("Acks", formatInt(propagation?.ack_count ?? 0), propagationTone(propagation), `${formatInt(propagation?.acked_shards ?? 0)} shards`)}
      ${renderMetric("Source max seq", formatInt(propagation?.source_max_seq ?? 0), "neutral", `${nonZeroShards} active shards`)}
      ${renderMetric("Canary", canaryLabel, canary?.status === "ok" ? "ok" : "warn", canary?.status === "ok" ? formatUnix(canary.created_at_unix) : "not committed")}
      ${renderMetric("Snapshot", manifest ? formatInt(manifest.max_seq) : "unknown", manifest ? "ok" : "warn", manifest ? `${formatInt(manifest.entry_count)} entries` : "manifest")}
    </section>
  `;
}

function renderMetric(title: string, value: string, tone: Tone, detail: string): string {
  return `
    <article class="metric ${tone}">
      <span>${escapeHtml(title)}</span>
      <strong>${escapeHtml(value)}</strong>
      <small>${escapeHtml(detail)}</small>
    </article>
  `;
}

function renderTopology(): string {
  const snapshot = state.snapshot;
  const health = okValue(snapshot?.centralHealth);
  const propagation = okValue(snapshot?.propagation);
  const acks = propagation?.acks ?? [];
  const regions = state.config.regions.map((config) => {
    const regionSnapshot = snapshot?.regions.find((item) => item.config.name === config.name);
    return renderTopologyRegion(config, regionSnapshot, acks);
  });

  return `
    <section class="panel topology-panel">
      <div class="section-heading">
        <div>
          <p class="eyebrow">topology</p>
          <h2>Central to regional edge</h2>
        </div>
        <span class="status-pill ${propagationTone(propagation)}">${escapeHtml(propagation?.status ?? "unknown")}</span>
      </div>
      <div class="topology-stage">
        <div class="central-node ${healthTone(health)}">
          <span>central control</span>
          <strong>${escapeHtml(health?.status ?? "unknown")}</strong>
          <small>${formatInt(propagation?.source_max_seq ?? 0)} source max seq</small>
        </div>
        <div class="region-lanes">
          ${regions.join("")}
        </div>
      </div>
    </section>
  `;
}

function renderTopologyRegion(
  config: RegionConfig,
  snapshot: RegionSnapshot | undefined,
  centralAcks: PropagationAckStatus[],
): string {
  const agentHealth = okValue(snapshot?.agentHealth);
  const decision = okValue(snapshot?.decision);
  const relayAcks = okValue(snapshot?.relayAcks);
  const matchingAcks = centralAcks.filter((ack) => ack.location === config.name);
  const maxLag = maxNumber(matchingAcks.map((ack) => ack.seq_lag ?? 0));
  const latestAckAge = minNumber(matchingAcks.map((ack) => ack.ack_age_secs ?? Number.POSITIVE_INFINITY));
  const tone = maxLag > 0 ? "warn" : healthTone(agentHealth);
  return `
    <article class="region-node ${tone}">
      <div>
        <span>${escapeHtml(config.name)}</span>
        <strong>${escapeHtml(agentHealth?.status ?? "unknown")}</strong>
      </div>
      <dl>
        <div><dt>decision</dt><dd>${renderDecisionText(decision)}</dd></div>
        <div><dt>relay acks</dt><dd>${formatInt(relayAcks?.ack_count ?? 0)}</dd></div>
        <div><dt>central lag</dt><dd>${formatInt(maxLag)}</dd></div>
        <div><dt>ack age</dt><dd>${Number.isFinite(latestAckAge) ? formatDuration(latestAckAge) : "none"}</dd></div>
      </dl>
    </article>
  `;
}

function renderMutationPanel(): string {
  const config = state.config;
  const mode = state.mutationMode;
  return `
    <section class="panel mutation-panel">
      <div class="section-heading">
        <div>
          <p class="eyebrow">authoring</p>
          <h2>Commit mutation</h2>
        </div>
        <div class="segmented" role="tablist" aria-label="Mutation type">
          <button type="button" data-mutation-mode="point" class="${mode === "point" ? "active" : ""}">Point</button>
          <button type="button" data-mutation-mode="rule" class="${mode === "rule" ? "active" : ""}">Rule</button>
        </div>
      </div>
      <form id="mutation-form" class="mutation-form" data-mode="${mode}">
        <input type="hidden" name="mode" value="${mode}" />
        <div class="form-grid">
          <label>
            <span>Tenant</span>
            <input name="tenantId" value="${escapeHtml(config.target.tenantId)}" autocomplete="off" />
          </label>
          <label class="point-field">
            <span>Namespace</span>
            <input name="namespace" value="${escapeHtml(config.target.namespace)}" autocomplete="off" />
          </label>
          <label class="point-field">
            <span>Key</span>
            <input name="key" value="${escapeHtml(config.target.key)}" autocomplete="off" />
          </label>
          <label class="rule-field">
            <span>Kind</span>
            <select name="kind">
              <option value="domain_suffix">domain_suffix</option>
              <option value="ipv4_cidr">ipv4_cidr</option>
            </select>
          </label>
          <label class="rule-field">
            <span>Pattern</span>
            <input name="pattern" value="blocked.example" autocomplete="off" />
          </label>
          <label>
            <span>Action</span>
            <select name="action">
              <option value="deny">deny</option>
              <option value="allow_override">allow_override</option>
              <option value="delete">delete</option>
            </select>
          </label>
          <label>
            <span>Delivery</span>
            <select name="deliveryPriority">
              <option value="p0">p0</option>
              <option value="p1">p1</option>
              <option value="p2">p2</option>
            </select>
          </label>
          <label>
            <span>Priority</span>
            <input name="priority" type="number" min="0" step="1" value="0" />
          </label>
          <label>
            <span>Reason</span>
            <input name="reasonCode" value="global_ui" autocomplete="off" />
          </label>
          <label>
            <span>Actor</span>
            <input name="createdBy" value="global-ui" autocomplete="off" />
          </label>
        </div>
        <label class="checkbox-line">
          <input name="overrideBlastRadius" type="checkbox" />
          <span>Blast override</span>
        </label>
        <div class="form-actions">
          <button type="submit" ${state.busyAction ? "disabled" : ""}>Commit</button>
        </div>
      </form>
    </section>
  `;
}

function renderRegionalPanel(): string {
  const snapshot = state.snapshot;
  const rows = snapshot?.regions.map(renderRegionRow).join("") ?? renderEmptyRow("No regional data");
  const centralDecision = okValue(snapshot?.centralDecision);
  return `
    <section class="panel regional-panel">
      <div class="section-heading">
        <div>
          <p class="eyebrow">edge</p>
          <h2>Regional lookups</h2>
        </div>
        <span class="status-pill ${decisionTone(centralDecision)}">central ${renderDecisionText(centralDecision)}</span>
      </div>
      <div class="data-table region-table">
        <div class="table-head">
          <span>Region</span>
          <span>Agent</span>
          <span>Relay</span>
          <span>Demo</span>
          <span>Decision</span>
          <span>Max seq</span>
          <span>Canary</span>
        </div>
        ${rows}
      </div>
    </section>
  `;
}

function renderRegionRow(region: RegionSnapshot): string {
  const agentHealth = okValue(region.agentHealth);
  const relayHealth = okValue(region.relayHealth);
  const demoHealth = okValue(region.demoHealth);
  const decision = okValue(region.decision);
  return `
    <div class="table-row">
      <span>${escapeHtml(region.config.name)}</span>
      <span>${renderHealthBadge(agentHealth, region.agentHealth)}</span>
      <span>${renderHealthBadge(relayHealth, region.relayHealth)}</span>
      <span>${renderHealthBadge(demoHealth, region.demoHealth)}</span>
      <span>${renderDecisionBadge(decision, region.decision)}</span>
      <span>${formatInt(numberField(agentHealth, "max_seq"))}</span>
      <span>${formatInt(numberField(agentHealth, "last_canary_seq"))}</span>
    </div>
  `;
}

function renderWatermarksPanel(): string {
  const snapshot = state.snapshot;
  const watermarks = okValue(snapshot?.watermarks);
  const compaction = okValue(snapshot?.compactionWatermarks);
  const entries = watermarks ? watermarkEntries(watermarks) : [];
  const maxSeq = maxNumber(entries.map((entry) => entry.seq));
  const cells = entries
    .map((entry) => {
      const compacted = compaction ? watermarkForShard(compaction, entry.shard) : 0;
      const intensity = maxSeq === 0 ? 0 : Math.max(0.08, entry.seq / maxSeq);
      return `
        <span
          class="shard-cell"
          style="--fill:${intensity.toFixed(3)}"
          title="shard ${entry.shard}: seq ${entry.seq}, compacted ${compacted}"
        >
          ${entry.shard}
        </span>
      `;
    })
    .join("");

  return `
    <section class="panel watermarks-panel">
      <div class="section-heading">
        <div>
          <p class="eyebrow">source</p>
          <h2>Shard watermarks</h2>
        </div>
        <span class="status-pill neutral">${entries.length} shards</span>
      </div>
      <div class="watermark-strip">
        ${cells || `<span class="empty-state">No watermarks</span>`}
      </div>
    </section>
  `;
}

function renderPropagationPanel(): string {
  const propagation = okValue(state.snapshot?.propagation);
  const error = resultError(state.snapshot?.propagation);
  const rows =
    propagation?.acks && propagation.acks.length > 0
      ? propagation.acks.map(renderAckRow).join("")
      : renderEmptyRow(error ?? "No propagation acknowledgements");
  return `
    <section class="panel propagation-panel">
      <div class="section-heading">
        <div>
          <p class="eyebrow">propagation</p>
          <h2>Acknowledgement stream</h2>
        </div>
        <span class="status-pill ${propagationTone(propagation)}">max lag ${formatInt(propagation?.max_seq_lag ?? 0)}</span>
      </div>
      <div class="data-table ack-table">
        <div class="table-head">
          <span>Relay</span>
          <span>Location</span>
          <span>Agent</span>
          <span>Shard</span>
          <span>Seq</span>
          <span>Source</span>
          <span>Lag</span>
          <span>Age</span>
        </div>
        ${rows}
      </div>
    </section>
  `;
}

function renderAckRow(ack: PropagationAckStatus): string {
  const lag = ack.seq_lag ?? 0;
  return `
    <div class="table-row ${lag > 0 ? "row-warn" : ""}">
      <span>${escapeHtml(ack.relay_id)}</span>
      <span>${escapeHtml(ack.location)}</span>
      <span>${escapeHtml(ack.agent_id)}</span>
      <span>${ack.shard_id}</span>
      <span>${formatInt(ack.seq)}</span>
      <span>${formatInt(ack.source_seq ?? 0)}</span>
      <span>${formatInt(lag)}</span>
      <span>${formatDuration(ack.ack_age_secs ?? ack.lag_secs ?? 0)}</span>
    </div>
  `;
}

function renderSnapshotPanel(): string {
  const manifest = okValue(state.snapshot?.snapshotManifest);
  const snapshots = okValue(state.snapshot?.snapshots);
  const latest = snapshots?.snapshots?.[snapshots.snapshots.length - 1] ?? "none";
  return `
    <section class="panel snapshot-panel">
      <div class="section-heading">
        <div>
          <p class="eyebrow">repair</p>
          <h2>Snapshot state</h2>
        </div>
        <span class="status-pill ${manifest ? "ok" : "warn"}">${manifest ? "manifest" : "unavailable"}</span>
      </div>
      <dl class="detail-grid">
        <div><dt>entry count</dt><dd>${formatInt(manifest?.entry_count ?? 0)}</dd></div>
        <div><dt>rule count</dt><dd>${formatInt(manifest?.rule_count ?? 0)}</dd></div>
        <div><dt>artifact bytes</dt><dd>${formatBytes(manifest?.artifact_bytes ?? 0)}</dd></div>
        <div><dt>created</dt><dd>${manifest ? formatUnix(manifest.created_at_unix) : "unknown"}</dd></div>
        <div><dt>snapshot count</dt><dd>${formatInt(snapshots?.snapshot_count ?? 0)}</dd></div>
        <div><dt>latest archive</dt><dd>${escapeHtml(latest)}</dd></div>
      </dl>
      <p class="hash-line">${escapeHtml(manifest?.artifact_sha256 ?? resultError(state.snapshot?.snapshotManifest) ?? "no artifact hash")}</p>
    </section>
  `;
}

function renderEventsPanel(): string {
  const audit = okValue(state.snapshot?.audit);
  const auditItems = audit?.items ?? [];
  const merged = [
    ...state.events.map(renderUiEvent),
    ...auditItems.slice(-MAX_AUDIT_ITEMS).reverse().map(renderAuditItem),
  ].join("");
  return `
    <section class="panel events-panel">
      <div class="section-heading">
        <div>
          <p class="eyebrow">events</p>
          <h2>Audit and UI activity</h2>
        </div>
        <span class="status-pill ${audit ? "neutral" : "warn"}">${auditItems.length} audit items</span>
      </div>
      <div class="event-list">
        ${merged || `<div class="empty-state">${escapeHtml(resultError(state.snapshot?.audit) ?? "No events")}</div>`}
      </div>
    </section>
  `;
}

function renderUiEvent(event: UiEvent): string {
  return `
    <article class="event-item ${event.level}">
      <time>${formatTime(event.at)}</time>
      <strong>${escapeHtml(event.title)}</strong>
      <span>${escapeHtml(event.detail)}</span>
    </article>
  `;
}

function renderAuditItem(item: NonNullable<AuditLogResponse["items"]>[number]): string {
  const seq = item.seq === undefined ? "" : ` shard ${item.shard_id ?? "?"} seq ${item.seq}`;
  const detail = [
    item.op_id,
    item.reason,
    item.snapshot,
    item.pattern,
    seq,
    typeof item.actor === "string" ? `actor ${item.actor}` : "",
  ]
    .filter((part) => String(part).trim().length > 0)
    .join(" | ");
  return `
    <article class="event-item">
      <time>${formatUnix(item.ts)}</time>
      <strong>${escapeHtml(item.event)}:${escapeHtml(item.result)}</strong>
      <span>${escapeHtml(detail)}</span>
    </article>
  `;
}

function renderEmptyRow(message: string): string {
  return `<div class="table-row empty-row"><span>${escapeHtml(message)}</span></div>`;
}

function bindEvents(): void {
  document.querySelector<HTMLButtonElement>("#refresh-button")?.addEventListener("click", () => {
    void refresh();
  });
  document.querySelector<HTMLButtonElement>("#canary-button")?.addEventListener("click", () => {
    void createCanary();
  });
  document.querySelector<HTMLFormElement>("#config-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    if (event.currentTarget instanceof HTMLFormElement) {
      applyConfigFromForm(event.currentTarget);
    }
  });
  document.querySelector<HTMLButtonElement>("#add-region-button")?.addEventListener("click", () => {
    state.config.regions = [
      ...state.config.regions,
      defaultRegion(`region-${state.config.regions.length + 1}`, state.config.regions.length + 1),
    ];
    saveConfig();
    render();
  });
  document.querySelectorAll<HTMLButtonElement>("[data-remove-region]").forEach((button) => {
    button.addEventListener("click", () => {
      const index = Number(button.dataset.removeRegion);
      state.config.regions = state.config.regions.filter((_, candidate) => candidate !== index);
      saveConfig();
      render();
    });
  });
  document.querySelectorAll<HTMLButtonElement>("[data-mutation-mode]").forEach((button) => {
    button.addEventListener("click", () => {
      const mode = button.dataset.mutationMode;
      if (mode === "point" || mode === "rule") {
        state.mutationMode = mode;
        render();
      }
    });
  });
  document.querySelector<HTMLFormElement>("#mutation-form")?.addEventListener("submit", (event) => {
    event.preventDefault();
    if (event.currentTarget instanceof HTMLFormElement) {
      void commitMutation(event.currentTarget);
    }
  });
}

function applyConfigFromForm(form: HTMLFormElement): void {
  const data = new FormData(form);
  const regions = Array.from(document.querySelectorAll<HTMLElement>("[data-region-row]"))
    .map((row) => ({
      name: inputValue(row, "regionName"),
      agentBaseUrl: inputValue(row, "agentBaseUrl"),
      relayBaseUrl: inputValue(row, "relayBaseUrl"),
      demoBaseUrl: inputValue(row, "demoBaseUrl"),
    }))
    .map(normalizeRegion)
    .filter((region) => region.name !== "");

  state.config = {
    controlBaseUrl: formValue(data, "controlBaseUrl", state.config.controlBaseUrl),
    regions,
    target: {
      tenantId: formValue(data, "tenantId", state.config.target.tenantId),
      namespace: formValue(data, "namespace", state.config.target.namespace),
      key: formValue(data, "key", state.config.target.key),
    },
    pollMs: Math.max(500, Number(formValue(data, "pollMs", String(state.config.pollMs))) || 2000),
    bearerToken: String(data.get("bearerToken") ?? ""),
  };
  saveConfig();
  restartPolling();
  void refresh();
}

function inputValue(root: ParentNode, name: string): string {
  return root.querySelector<HTMLInputElement>(`input[name="${name}"]`)?.value.trim() ?? "";
}

function formValue(data: FormData, name: string, fallback: string): string {
  const value = String(data.get(name) ?? "").trim();
  return value.length > 0 ? value : fallback;
}

async function commitMutation(form: HTMLFormElement): Promise<void> {
  state.busyAction = "commit";
  render();
  const data = new FormData(form);
  const control = createControlClient(state.config.controlBaseUrl, clientOptions());
  const mode = formValue(data, "mode", state.mutationMode);

  try {
    const outcome =
      mode === "rule"
        ? await control.rule(ruleRequestFromForm(data))
        : await control.deny(denyRequestFromForm(data));
    rememberTarget(data);
    pushEvent("info", "mutation committed", outcomeSummary(outcome));
    await refresh();
  } catch (error) {
    pushEvent("error", "mutation failed", errorMessage(error));
    render();
  } finally {
    state.busyAction = null;
    render();
  }
}

function denyRequestFromForm(data: FormData): DenyMutationRequest {
  const overrideBlastRadius = data.get("overrideBlastRadius") === "on";
  return {
    op_id: `ui-${Date.now()}`,
    tenant_id: formValue(data, "tenantId", state.config.target.tenantId),
    namespace: formValue(data, "namespace", state.config.target.namespace),
    key: formValue(data, "key", state.config.target.key),
    action: formValue(data, "action", "deny") as DenyMutationRequest["action"],
    priority: Number(formValue(data, "priority", "0")) || 0,
    reason_code: formValue(data, "reasonCode", "global_ui"),
    created_by: formValue(data, "createdBy", "global-ui"),
    delivery_priority: formValue(
      data,
      "deliveryPriority",
      "p0",
    ) as DeliveryPriority,
    override_blast_radius: overrideBlastRadius,
    blast_radius_override: false,
    two_person_approved: false,
  };
}

function ruleRequestFromForm(data: FormData): RuleMutationRequest {
  const overrideBlastRadius = data.get("overrideBlastRadius") === "on";
  return {
    op_id: `ui-${Date.now()}`,
    tenant_id: formValue(data, "tenantId", state.config.target.tenantId),
    kind: formValue(data, "kind", "domain_suffix") as RuleMutationRequest["kind"],
    pattern: formValue(data, "pattern", "blocked.example"),
    action: formValue(data, "action", "deny") as RuleMutationRequest["action"],
    priority: Number(formValue(data, "priority", "0")) || 0,
    reason_code: formValue(data, "reasonCode", "global_ui"),
    created_by: formValue(data, "createdBy", "global-ui"),
    delivery_priority: formValue(
      data,
      "deliveryPriority",
      "p0",
    ) as DeliveryPriority,
    override_blast_radius: overrideBlastRadius,
    blast_radius_override: false,
    two_person_approved: false,
  };
}

function rememberTarget(data: FormData): void {
  state.config.target = {
    tenantId: formValue(data, "tenantId", state.config.target.tenantId),
    namespace: formValue(data, "namespace", state.config.target.namespace),
    key: formValue(data, "key", state.config.target.key),
  };
  saveConfig();
}

async function createCanary(): Promise<void> {
  state.busyAction = "canary";
  render();
  try {
    const canary = await createControlClient(state.config.controlBaseUrl, clientOptions()).createCanary();
    pushEvent("info", "canary committed", canarySummary(canary));
    await refresh();
  } catch (error) {
    pushEvent("error", "canary failed", errorMessage(error));
    render();
  } finally {
    state.busyAction = null;
    render();
  }
}

function pushEvent(level: UiEvent["level"], title: string, detail: string): void {
  state.events = [{ at: new Date(), level, title, detail }, ...state.events].slice(0, MAX_EVENT_COUNT);
}

function outcomeSummary(outcome: CommitOutcomeResponse): string {
  const duplicate = outcome.duplicate ? "duplicate" : "new";
  return `${outcome.action} ${duplicate} on shard ${outcome.shard_id} seq ${outcome.seq}`;
}

function canarySummary(canary: CanaryStatusResponse): string {
  return `${canary.key} shard ${canary.shard_id} seq ${canary.seq}`;
}

type Tone = "ok" | "warn" | "bad" | "neutral";

function healthTone(health: HealthResponse | undefined): Tone {
  if (!health) {
    return "warn";
  }
  if (health.status === "ok") {
    return "ok";
  }
  if (health.status === "stale") {
    return "warn";
  }
  return "bad";
}

function propagationTone(propagation: PropagationStatusResponse | undefined): Tone {
  if (!propagation) {
    return "warn";
  }
  if (propagation.status === "ok" && propagation.max_seq_lag === 0) {
    return "ok";
  }
  return propagation.max_seq_lag > 0 ? "warn" : "bad";
}

function decisionTone(decision: DecisionResponse | undefined): Tone {
  if (!decision) {
    return "warn";
  }
  return decision.decision === "deny" ? "bad" : "ok";
}

function renderHealthBadge(
  health: HealthResponse | undefined,
  result: LoadResult<HealthResponse>,
): string {
  if (!result.ok) {
    return `<span class="status-pill bad" title="${escapeHtml(result.message)}">error</span>`;
  }
  return `<span class="status-pill ${healthTone(health)}">${escapeHtml(health?.status ?? "unknown")}</span>`;
}

function renderDecisionBadge(
  decision: DecisionResponse | undefined,
  result: LoadResult<DecisionResponse>,
): string {
  if (!result.ok) {
    return `<span class="status-pill bad" title="${escapeHtml(result.message)}">error</span>`;
  }
  return `<span class="status-pill ${decisionTone(decision)}">${renderDecisionText(decision)}</span>`;
}

function renderDecisionText(decision: DecisionResponse | undefined): string {
  return escapeHtml(decision?.decision ?? "unknown");
}

function okValue<T>(result: LoadResult<T> | undefined): T | undefined {
  return result?.ok ? result.value : undefined;
}

function resultError(result: LoadResult<unknown> | undefined): string | null {
  return result && !result.ok ? `${result.label}: ${result.message}` : null;
}

function watermarkEntries(response: WatermarksResponse): Array<{ shard: number; seq: number }> {
  return Object.entries(response)
    .filter(([key]) => /^shard_[0-9]{4}$/.test(key))
    .map(([key, value]) => ({
      shard: Number(key.slice("shard_".length)),
      seq: Number(value),
    }))
    .sort((left, right) => left.shard - right.shard);
}

function watermarkForShard(response: WatermarksResponse, shard: number): number {
  return Number(response[`shard_${String(shard).padStart(4, "0")}`] ?? 0);
}

function numberField(health: HealthResponse | undefined, field: string): number {
  const value = health?.[field];
  return typeof value === "number" ? value : 0;
}

function maxNumber(values: number[]): number {
  return values.reduce((max, value) => (value > max ? value : max), 0);
}

function minNumber(values: number[]): number {
  return values.reduce((min, value) => (value < min ? value : min), Number.POSITIVE_INFINITY);
}

function formatInt(value: number): string {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 }).format(value);
}

function formatBytes(value: number): string {
  if (value < 1024) {
    return `${value} B`;
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KiB`;
  }
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) {
    return "unknown";
  }
  if (seconds < 60) {
    return `${Math.max(0, Math.round(seconds))}s`;
  }
  const minutes = Math.floor(seconds / 60);
  const remainder = Math.round(seconds % 60);
  return `${minutes}m ${remainder}s`;
}

function formatUnix(value: number): string {
  if (!value) {
    return "never";
  }
  return formatTime(new Date(value * 1000));
}

function formatTime(value: Date): string {
  return value.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function escapeHtml(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      case "'":
        return "&#39;";
      default:
        return char;
    }
  });
}
