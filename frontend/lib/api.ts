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
  return request<{
    ok: boolean;
    message: string;
    connection: ConnectionSettings;
  }>("/api/settings/connection/credentials", {
    method: "DELETE",
  });
}
