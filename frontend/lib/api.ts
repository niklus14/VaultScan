/**
 * VaultScan API client — talks to the FastAPI backend.
 * In dev, Next.js rewrites /api/* → http://localhost:8000/api/*
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type ScanMode = "assume_role" | "direct" | "simulate";

export interface Vulnerability {
  id: string;
  service: string;
  severity: Severity;
  description: string;
  title?: string;
  remediation?: string;
  compliance?: string[];
  rule_id?: string;
  region?: string;
}

export interface ScanResult {
  scan_id: string;
  timestamp: string;
  mode: string;
  region: string;
  account_id?: string | null;
  role_arn?: string | null;
  caller_arn?: string | null;
  score: number;
  total_findings: number;
  summary: Record<Severity, number>;
  findings: Array<Record<string, unknown>>;
  vulnerabilities: Vulnerability[];
  compliance: Array<{
    name: string;
    version: string;
    status: "PASSING" | "FAILING";
    passed: number;
    total: number;
    controls: Array<{ label: string; value: number }>;
  }>;
  remediation: {
    title: string;
    target: string;
    lines: string[];
    steps: Array<{ id: number; label: string; done: boolean }>;
  };
  audit_stream: Array<{
    level: "INF" | "MED" | "CRIT";
    header: string;
    message: string;
    time: string;
  }>;
  infra_status: Array<{
    label: string;
    value: string;
    state: "online" | "syncing" | "error" | string;
  }>;
  posture_point?: { t: string; score: number };
  attack_paths?: Array<{
    id: string;
    name: string;
    outcome: string;
    severity: string;
    likelihood: string;
    impact: string;
    steps: Array<{
      role: string;
      rule_id?: string;
      severity?: string;
      service?: string;
      resource?: string;
      title?: string;
      remediation?: string;
    }>;
    break_chain: string[];
  }>;
}

export interface HistoryItem {
  id: string;
  scan_id: string;
  timestamp: string;
  score: number;
  critical: number;
  mode?: string;
  account_id?: string;
  region?: string;
  total_findings?: number;
}

export interface ConnectionStatus {
  connected: boolean;
  mode: string;
  account_id?: string | null;
  arn?: string | null;
  role_arn?: string | null;
  region?: string;
  error?: string | null;
  hint?: string | null;
}

export interface PublicConfig {
  default_role_arn: string;
  default_region: string;
  auth_mode?: ScanMode;
  connection_name?: string;
  credentials_configured?: boolean;
  ready_to_scan?: boolean;
  grok_enabled: boolean;
  grok_model?: string | null;
}

export type CloudProvider = "aws" | "gcp";

export interface ConnectionSettings {
  connection_name: string;
  provider: CloudProvider | string;
  auth_mode: ScanMode;
  role_arn: string;
  external_id: string;
  region: string;
  session_name: string;
  access_key_id_masked: string | null;
  has_access_key: boolean;
  has_secret_key: boolean;
  has_session_token: boolean;
  gcp_project_id?: string;
  gcp_service_account_email_masked?: string | null;
  has_gcp_service_account?: boolean;
  credentials_configured: boolean;
  updated_at: string | null;
  last_tested_at: string | null;
  last_test_status: "ok" | "failed" | "never";
  last_test_message: string | null;
  last_account_id: string | null;
  last_caller_arn: string | null;
  ready_to_scan: boolean;
  guidance: Array<{ level: string; text: string }>;
}

export interface ConnectionSettingsUpdate {
  connection_name?: string;
  provider?: CloudProvider;
  auth_mode?: ScanMode;
  role_arn?: string;
  external_id?: string;
  region?: string;
  session_name?: string;
  access_key_id?: string;
  secret_access_key?: string;
  session_token?: string;
  gcp_project_id?: string;
  gcp_service_account_email?: string;
  gcp_service_account_json?: string;
  clear_credentials?: boolean;
  clear_session_token?: boolean;
}

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "";

/** Browser-session copy of AWS secrets so Apply works after Vercel cold starts. */
const CREDS_KEY = "vaultscan_aws_creds_v1";

export type StoredAwsCreds = {
  access_key_id?: string;
  secret_access_key?: string;
  session_token?: string;
  role_arn?: string;
  auth_mode?: ScanMode;
  region?: string;
  external_id?: string;
};

export function rememberAwsCreds(partial: StoredAwsCreds) {
  if (typeof window === "undefined") return;
  try {
    const prev = loadAwsCreds() || {};
    const next: StoredAwsCreds = { ...prev };
    for (const [k, v] of Object.entries(partial)) {
      if (v !== undefined && v !== null && String(v).trim() !== "") {
        (next as Record<string, string>)[k] = String(v).trim();
      }
    }
    sessionStorage.setItem(CREDS_KEY, JSON.stringify(next));
  } catch {
    /* ignore quota / private mode */
  }
}

export function loadAwsCreds(): StoredAwsCreds | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = sessionStorage.getItem(CREDS_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as StoredAwsCreds;
  } catch {
    return null;
  }
}

export function clearAwsCreds() {
  if (typeof window === "undefined") return;
  try {
    sessionStorage.removeItem(CREDS_KEY);
  } catch {
    /* ignore */
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers || {}),
    },
  });

  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { detail: text };
  }

  if (!res.ok) {
    const detail =
      typeof data === "object" && data && "detail" in data
        ? (data as { detail: unknown }).detail
        : text;
    const msg =
      typeof detail === "string"
        ? detail
        : typeof detail === "object" && detail && "error" in detail
          ? String((detail as { error: string }).error)
          : JSON.stringify(detail);
    throw new Error(msg || `HTTP ${res.status}`);
  }

  return data as T;
}

export function getHealth() {
  return request<{
    ok: boolean;
    grok_configured: boolean;
    default_role_arn: string;
    region: string;
  }>("/api/health");
}

export function getPublicConfig() {
  return request<PublicConfig>("/api/config/public");
}

export function getConnection(params?: {
  mode?: ScanMode;
  role_arn?: string;
  region?: string;
}) {
  const q = new URLSearchParams();
  if (params?.mode) q.set("mode", params.mode);
  if (params?.role_arn) q.set("role_arn", params.role_arn);
  if (params?.region) q.set("region", params.region);
  const qs = q.toString();
  return request<ConnectionStatus>(`/api/connection${qs ? `?${qs}` : ""}`);
}

export function runScan(body: {
  mode?: ScanMode;
  role_arn?: string;
  external_id?: string;
  region?: string;
} = {}) {
  // Omit unset fields so the server uses Settings-page configuration
  const payload: Record<string, string> = {};
  if (body.mode) payload.mode = body.mode;
  if (body.role_arn) payload.role_arn = body.role_arn;
  if (body.external_id) payload.external_id = body.external_id;
  if (body.region) payload.region = body.region;
  return request<ScanResult>("/api/scan", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getLatestScan() {
  return request<ScanResult>("/api/scans/latest");
}

export function listScans() {
  return request<{ scans: HistoryItem[]; count: number }>("/api/scans");
}

export function summarizeScan(scanId?: string) {
  return request<{ scan_id: string; summary: string; model: string }>(
    "/api/ai/summarize",
    {
      method: "POST",
      body: JSON.stringify({ scan_id: scanId ?? null }),
    },
  );
}

export interface ReportPackage {
  scan_id: string;
  generated_at?: string;
  narrative: {
    headline: string;
    risk_level: string;
    executive_summary: string;
    what_this_means: string;
    priority_actions: string;
    technical_notes: string;
  };
  metrics: {
    score: number;
    total_findings: number;
    summary: Record<string, number>;
    account_id?: string | null;
    region?: string;
    mode?: string;
    role_arn?: string | null;
  };
  charts: {
    by_severity: Array<{
      severity: string;
      count: number;
      label: string;
    }>;
    by_service: Array<{ service: string; count: number }>;
  };
  findings_table: Array<{
    resource: string;
    service: string;
    severity: string;
    title: string;
    description: string;
    remediation: string;
    compliance: string[];
    why_it_matters: string;
  }>;
  compliance: Array<{
    name: string;
    version: string;
    status: "PASSING" | "FAILING" | string;
    passed: number;
    total: number;
    controls?: Array<{ label: string; value: number }>;
  }>;
  remediation: {
    title?: string;
    target?: string;
    lines?: string[];
    steps?: Array<{ id: number; label: string; done: boolean }>;
  };
  glossary: Array<{ term: string; meaning: string }>;
}

export function generateReport(scanId?: string, forceRefresh = false) {
  return request<ReportPackage>("/api/ai/report", {
    method: "POST",
    body: JSON.stringify({
      scan_id: scanId ?? null,
      force_refresh: forceRefresh,
    }),
  });
}

/** Last cached report package (no new scan, no AI if already generated). */
export function getLatestReport() {
  return request<ReportPackage>("/api/report/latest");
}

/** Download a binary report export (PDF or DOCX) for an existing scan. */
export async function downloadReportExport(
  format: "pdf" | "docx",
  scanId?: string,
): Promise<void> {
  const params = new URLSearchParams();
  if (scanId && scanId !== "SCAN-DEMO") {
    params.set("scan_id", scanId);
  }
  const qs = params.toString();
  const res = await fetch(
    `${process.env.NEXT_PUBLIC_API_BASE ?? ""}/api/report/export/${format}${qs ? `?${qs}` : ""}`,
  );
  if (!res.ok) {
    let msg = `Export failed (${res.status})`;
    try {
      const err = await res.json();
      if (typeof err?.detail === "string") msg = err.detail;
      else if (err?.detail?.error) msg = err.detail.error;
    } catch {
      /* ignore */
    }
    throw new Error(msg);
  }
  const blob = await res.blob();
  const dispo = res.headers.get("Content-Disposition") || "";
  const match = /filename="?([^";]+)"?/i.exec(dispo);
  const filename =
    match?.[1] ||
    `VaultScan_Report.${format === "pdf" ? "pdf" : "docx"}`;

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function chatWithGrok(body: {
  message: string;
  history?: Array<{ role: "user" | "assistant" | "system"; content: string }>;
  scan_id?: string;
}) {
  return request<{ reply: string; model: string; scan_id?: string | null }>(
    "/api/ai/chat",
    {
      method: "POST",
      body: JSON.stringify(body),
    },
  );
}

export type AttackPathEnriched = {
  id: string;
  name: string;
  outcome: string;
  severity: string;
  likelihood: string;
  impact: string;
  steps: Array<{
    role: string;
    rule_id?: string;
    severity?: string;
    service?: string;
    resource?: string;
    title?: string;
    remediation?: string;
  }>;
  break_chain: string[];
  wow_headline?: string;
  story?: string;
  attacker_playbook?: string;
  time_to_compromise?: string;
  blast_radius?: string;
  ai_enriched?: boolean;
};

export function enrichAttackPaths(scanId?: string) {
  return request<{
    scan_id: string;
    paths: AttackPathEnriched[];
    count: number;
    ai_used: boolean;
  }>("/api/ai/attack-paths", {
    method: "POST",
    body: JSON.stringify({ scan_id: scanId ?? null }),
  });
}

export function getConnectionSettings() {
  return request<ConnectionSettings>("/api/settings/connection");
}

export function saveConnectionSettings(body: ConnectionSettingsUpdate) {
  return request<{
    ok: boolean;
    message: string;
    connection: ConnectionSettings;
  }>("/api/settings/connection", {
    method: "PUT",
    body: JSON.stringify(body),
  });
}

export function testConnectionSettings() {
  return request<{
    ok: boolean;
    message: string;
    connection: ConnectionStatus;
    settings: ConnectionSettings;
  }>("/api/settings/connection/test", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function clearConnectionCredentials() {
  clearAwsCreds();
  return request<{
    ok: boolean;
    message: string;
    connection: ConnectionSettings;
  }>("/api/settings/connection/credentials", {
    method: "DELETE",
  });
}

/* ─── Schedule + Gmail alerts ───────────────────────────────────────────── */

export type AlertWhen =
  | "always"
  | "any_findings"
  | "high_or_critical"
  | "critical_only";

export interface ScheduleSettings {
  enabled: boolean;
  interval_minutes: number;
  email_enabled: boolean;
  /** User's Gmail — only field they configure for delivery */
  recipients: string;
  sender_display?: string;
  system_sender_ready?: boolean;
  from_name?: string;
  alert_when: AlertWhen | string;
  include_finding_details: boolean;
  last_run_at: string | null;
  next_run_at: string | null;
  last_run_status: string;
  last_run_message: string | null;
  last_email_status: string;
  last_email_message: string | null;
  last_email_at: string | null;
  run_count: number;
  updated_at: string | null;
  scheduler_supported: boolean;
  guidance: Array<{ level: string; text: string }>;
}

export interface ScheduleSettingsUpdate {
  enabled?: boolean;
  interval_minutes?: number;
  email_enabled?: boolean;
  recipients?: string;
  alert_when?: AlertWhen;
  include_finding_details?: boolean;
}

export function getScheduleSettings() {
  return request<ScheduleSettings>("/api/settings/schedule");
}

export function saveScheduleSettings(body: ScheduleSettingsUpdate) {
  return request<{
    ok: boolean;
    message: string;
    settings: ScheduleSettings;
  }>("/api/settings/schedule", {
    method: "PUT",
    body: JSON.stringify(body),
  });
}

export function runScheduleNow() {
  return request<{
    ok: boolean;
    message: string;
    scan_id?: string;
    score?: number;
    total_findings?: number;
    email?: { ok?: boolean; message?: string; skipped?: boolean } | null;
    settings?: ScheduleSettings;
  }>("/api/settings/schedule/run-now", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function testScheduleEmail() {
  return request<{
    ok: boolean;
    message: string;
    settings: ScheduleSettings;
  }>("/api/settings/schedule/test-email", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

/* ─── AI remediation ─────────────────────────────────────────────────────── */

export type FixRisk = "safe" | "elevated" | "dangerous";
export type FixActionStatus =
  | "planned"
  | "dry_run_ok"
  | "dry_run_fail"
  | "applied"
  | "failed"
  | "skipped"
  | "rolled_back"
  | "rollback_failed";

export interface FixAction {
  action_id: string;
  rule_id: string;
  finding_id: string;
  resource: string;
  title: string;
  risk: FixRisk;
  summary: string;
  auto_applicable: boolean;
  requires_confirm: boolean;
  cli_hint?: string;
  cli_commands?: string[];
  steps?: string[];
  status: FixActionStatus;
  preview?: string | null;
  error?: string | null;
  ai_notes?: string | null;
  region?: string;
  service?: string;
  severity?: string;
  evidence?: Record<string, unknown>;
}

export interface RemediateJob {
  job_id: string;
  created_at: string;
  updated_at?: string;
  scan_id?: string;
  mode: string;
  status: string;
  ai_used?: boolean;
  actions: FixAction[];
  score_before?: number | null;
  score_after?: number | null;
  rollback_available?: boolean;
  cli_script?: string;
  code_version?: string;
  fix_report?: FixChangeReport;
}

export interface FixChangeEntry {
  action_id?: string;
  rule_id?: string;
  resource?: string;
  title?: string;
  summary?: string;
  risk?: FixRisk;
  severity?: string;
  status?: FixActionStatus;
  before?: string;
  what_changed?: string;
  after?: string;
  cli_commands?: string[];
  cli_text?: string;
  ai_notes?: string | null;
  ai_story?: string;
  preview?: string | null;
  error?: string | null;
}

export interface FixChangeReport {
  report_id: string;
  generated_at: string;
  job_id?: string;
  scan_id?: string;
  job_status?: string;
  score_before?: number | null;
  score_after?: number | null;
  score_delta?: number | null;
  counts: {
    total: number;
    applied: number;
    failed: number;
    skipped: number;
    rolled_back: number;
  };
  executive_summary: string;
  recommendations: string[];
  changes: FixChangeEntry[];
  cli_script?: string;
  ai_used?: boolean;
}

export function getRemediationReport(body: {
  job_id: string;
  use_ai?: boolean;
}) {
  return request<{
    ok: boolean;
    report: FixChangeReport;
    ai_used: boolean;
  }>("/api/remediate/report", {
    method: "POST",
    body: JSON.stringify({
      job_id: body.job_id,
      use_ai: body.use_ai ?? true,
    }),
  });
}

/** Download fix change report as PDF or Word (full before/after + CLI + AI). */
export async function downloadFixReportExport(
  format: "pdf" | "docx",
  jobId: string,
  useAi = true,
): Promise<void> {
  const params = new URLSearchParams({
    job_id: jobId,
    use_ai: useAi ? "true" : "false",
  });
  const res = await fetch(
    `${process.env.NEXT_PUBLIC_API_BASE ?? ""}/api/remediate/report/export/${format}?${params}`,
  );
  if (!res.ok) {
    let msg = `Export failed (${res.status})`;
    try {
      const err = await res.json();
      if (typeof err?.detail === "string") msg = err.detail;
      else if (err?.detail?.error) msg = err.detail.error;
    } catch {
      /* ignore */
    }
    throw new Error(msg);
  }
  const blob = await res.blob();
  const dispo = res.headers.get("Content-Disposition") || "";
  const match = /filename="?([^";]+)"?/i.exec(dispo);
  const filename =
    match?.[1] ||
    `VaultScan_FixReport.${format === "pdf" ? "pdf" : "docx"}`;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function planRemediation(body: {
  scan_id?: string | null;
  finding_ids?: string[];
  mode?: "all_safe" | "selected" | "all";
  use_ai?: boolean;
}) {
  return request<{
    ok: boolean;
    job: RemediateJob;
    ai_used: boolean;
    counts: { total: number; auto: number; safe: number };
  }>("/api/remediate/plan", {
    method: "POST",
    body: JSON.stringify({
      scan_id: body.scan_id ?? null,
      finding_ids: body.finding_ids ?? null,
      mode: body.mode ?? "all_safe",
      use_ai: body.use_ai ?? true,
    }),
  });
}

export function dryRunRemediation(jobId: string) {
  return request<{ ok: boolean; job: RemediateJob }>("/api/remediate/dry-run", {
    method: "POST",
    body: JSON.stringify({ job_id: jobId }),
  });
}

export function applyRemediation(body: {
  job_id: string;
  confirm?: boolean;
  confirm_phrase?: string;
  only_safe?: boolean;
  allow_write_with_scan_creds?: boolean;
  rescan?: boolean;
}) {
  const creds = loadAwsCreds() || {};
  return request<{
    ok: boolean;
    job: RemediateJob;
    rescan?: ScanResult | { error: string };
    message?: string;
    session_mode?: string;
    code_version?: string;
    cli_script?: string;
  }>("/api/remediate/apply", {
    method: "POST",
    body: JSON.stringify({
      job_id: body.job_id,
      confirm: body.confirm ?? true,
      confirm_phrase: body.confirm_phrase ?? null,
      only_safe: body.only_safe ?? false,
      allow_write_with_scan_creds: body.allow_write_with_scan_creds ?? false,
      rescan: body.rescan ?? true,
      // Re-send secrets so real AWS Apply works after Vercel cold start
      access_key_id: creds.access_key_id || undefined,
      secret_access_key: creds.secret_access_key || undefined,
      session_token: creds.session_token || undefined,
      role_arn: creds.role_arn || undefined,
      auth_mode: creds.auth_mode || undefined,
      region: creds.region || undefined,
      external_id: creds.external_id || undefined,
    }),
  });
}

/** Restore resources as they were before the job (“Please make it as before”). */
export function rollbackRemediation(body: {
  job_id: string;
  action_ids?: string[];
  confirm?: boolean;
  confirm_phrase?: string;
  allow_write_with_scan_creds?: boolean;
  rescan?: boolean;
}) {
  return request<{
    ok: boolean;
    job: RemediateJob;
    rescan?: ScanResult | { error: string };
    message?: string;
  }>("/api/remediate/rollback", {
    method: "POST",
    body: JSON.stringify({
      job_id: body.job_id,
      action_ids: body.action_ids ?? null,
      confirm: body.confirm ?? true,
      confirm_phrase: body.confirm_phrase ?? "ROLLBACK",
      allow_write_with_scan_creds: body.allow_write_with_scan_creds ?? false,
      rescan: body.rescan ?? true,
    }),
  });
}

export function listRemediationJobs() {
  return request<{ jobs: RemediateJob[] }>("/api/remediate/jobs");
}

export function getRemediationJob(jobId: string) {
  return request<RemediateJob>(`/api/remediate/jobs/${jobId}`);
}
