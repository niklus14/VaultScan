"use client";

import { create } from "zustand";
import {
  type ScanResult,
  type HistoryItem,
  type ConnectionStatus,
  type PublicConfig,
  type ScanMode,
  runScan,
  listScans,
  getConnection,
  getPublicConfig,
  getLatestScan,
} from "./api";
import {
  vulnerabilities as mockVulns,
  complianceFrameworks as mockCompliance,
  remediationPlaybook as mockRemediation,
  scanHistory as mockHistory,
  auditStream as mockAudit,
  infraStatus as mockInfra,
} from "@/components/cspm/data";
import {
  buildTrendFromHistory,
  type TrendPoint,
} from "@/components/cspm/posture-chart";

interface ScanStore {
  scan: ScanResult | null;
  history: HistoryItem[];
  postureTrend: TrendPoint[];
  connection: ConnectionStatus | null;
  config: PublicConfig | null;
  loading: boolean;
  error: string | null;
  mode: ScanMode;
  roleArn: string;
  region: string;

  setMode: (mode: ScanMode) => void;
  setRoleArn: (arn: string) => void;
  setRegion: (region: string) => void;
  bootstrap: () => Promise<void>;
  refreshConnection: () => Promise<void>;
  launchScan: () => Promise<void>;
}

function mapMockAsScan(): ScanResult {
  return {
    scan_id: "SCAN-DEMO",
    timestamp: new Date().toISOString(),
    mode: "mock",
    region: "eu-west-1",
    account_id: "demo",
    score: 100,
    total_findings: mockVulns.length,
    summary: {
      CRITICAL: mockVulns.filter((v) => v.severity === "CRITICAL").length,
      HIGH: mockVulns.filter((v) => v.severity === "HIGH").length,
      MEDIUM: mockVulns.filter((v) => v.severity === "MEDIUM").length,
      LOW: mockVulns.filter((v) => v.severity === "LOW").length,
    },
    findings: [],
    vulnerabilities: mockVulns,
    compliance: mockCompliance,
    remediation: mockRemediation,
    audit_stream: mockAudit,
    infra_status: mockInfra,
  };
}

function trendFrom(history: HistoryItem[]): TrendPoint[] {
  return buildTrendFromHistory(history);
}

export const useScanStore = create<ScanStore>((set, get) => ({
  scan: null,
  history: [],
  postureTrend: [],
  connection: null,
  config: null,
  loading: false,
  error: null,
  mode: "assume_role",
  roleArn: "arn:aws:iam::850919910218:role/demo-test-vulnerable-ec2-role",
  region: "us-east-1",

  setMode: (mode) => set({ mode }),
  setRoleArn: (roleArn) => set({ roleArn }),
  setRegion: (region) => set({ region }),

  bootstrap: async () => {
    try {
      const config = await getPublicConfig();
      set({
        config,
        roleArn: config.default_role_arn || get().roleArn,
        region: config.default_region || get().region,
        mode: config.auth_mode || get().mode,
      });
    } catch {
      /* backend offline */
    }

    try {
      await get().refreshConnection();
    } catch {
      /* ignore */
    }

    try {
      const latest = await getLatestScan();
      const hist = await listScans();
      set({
        scan: latest,
        history: hist.scans,
        postureTrend: trendFrom(hist.scans),
      });
    } catch {
      // no saved scans — empty trend (not fake decorative data)
      set({ scan: null, history: [], postureTrend: [] });
    }
  },

  refreshConnection: async () => {
    const { mode, roleArn, region } = get();
    try {
      const connection = await getConnection({ mode, role_arn: roleArn, region });
      set({ connection });
    } catch (e) {
      set({
        connection: {
          connected: false,
          mode,
          role_arn: roleArn,
          region,
          error: e instanceof Error ? e.message : "Backend unreachable",
        },
      });
    }
  },

  launchScan: async () => {
    set({ loading: true, error: null });
    try {
      const result = await runScan({});
      const hist = await listScans();
      set({
        scan: result,
        history: hist.scans,
        postureTrend: trendFrom(hist.scans),
        loading: false,
        error: null,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Scan failed";
      set({ loading: false, error: msg });
      throw e;
    }
  },
}));

export function useLiveData() {
  const scan = useScanStore((s) => s.scan);
  const history = useScanStore((s) => s.history);
  const postureTrend = useScanStore((s) => s.postureTrend);
  const loading = useScanStore((s) => s.loading);
  const error = useScanStore((s) => s.error);
  const connection = useScanStore((s) => s.connection);
  const mode = useScanStore((s) => s.mode);
  const roleArn = useScanStore((s) => s.roleArn);
  const region = useScanStore((s) => s.region);
  const config = useScanStore((s) => s.config);
  const launchScan = useScanStore((s) => s.launchScan);
  const setMode = useScanStore((s) => s.setMode);
  const setRoleArn = useScanStore((s) => s.setRoleArn);
  const setRegion = useScanStore((s) => s.setRegion);
  const bootstrap = useScanStore((s) => s.bootstrap);

  const fallback = mapMockAsScan();
  const active = scan ?? fallback;
  const isLive = !!scan;

  return {
    isLive,
    loading,
    error,
    connection,
    mode,
    roleArn,
    region,
    config,
    launchScan,
    setMode,
    setRoleArn,
    setRegion,
    bootstrap,
    score: active.score,
    summary: active.summary,
    vulnerabilities: active.vulnerabilities,
    compliance: active.compliance,
    remediation: active.remediation,
    auditStream: active.audit_stream,
    infraStatus: active.infra_status,
    history: history.length
      ? history
      : isLive
        ? []
        : mockHistory.map((h) => ({
            id: h.id,
            scan_id: h.id,
            timestamp: h.timestamp,
            score: h.score,
            critical: h.critical,
          })),
    postureTrend,
    hasRealTrend: postureTrend.length > 0,
    scanId: active.scan_id,
    timestamp: active.timestamp,
    accountId: active.account_id,
    scan,
  };
}
