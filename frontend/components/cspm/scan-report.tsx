"use client";

import { useEffect, useMemo, useState } from "react";
import {
  X,
  Printer,
  ShieldHalf,
  Loader2,
  Sparkles,
  AlertTriangle,
  CheckCircle2,
  Info,
  BookOpen,
  ListOrdered,
  RefreshCw,
  FileDown,
  FileText,
} from "lucide-react";
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";
import { useLiveData } from "@/lib/scan-store";
import {
  generateReport,
  getLatestReport,
  getLatestScan,
  downloadReportExport,
  type ReportPackage,
} from "@/lib/api";
import { useScanStore } from "@/lib/scan-store";
import { type Severity } from "./data";
import { cn } from "@/lib/utils";

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#ff3d57",
  HIGH: "#ff9900",
  MEDIUM: "#3874ff",
  LOW: "#6b7280",
};

const riskStyles: Record<string, string> = {
  CRITICAL: "border-danger/40 bg-danger/10 text-danger",
  HIGH: "border-warning/40 bg-warning/10 text-warning",
  MODERATE: "border-accent-blue/40 bg-accent-blue/10 text-accent-blue",
  LOW: "border-success/40 bg-success/10 text-success",
};

function scoreColor(score: number) {
  if (score >= 90) return "text-success";
  if (score >= 75) return "text-warning";
  return "text-danger";
}

function scoreRing(score: number) {
  if (score >= 90) return "#00e676";
  if (score >= 75) return "#ff9900";
  return "#ff3d57";
}

function SectionTitle({
  icon: Icon,
  children,
  hint,
}: {
  icon: React.ElementType;
  children: React.ReactNode;
  hint?: string;
}) {
  return (
    <div className="mb-3">
      <div className="flex items-center gap-2">
        <Icon className="size-4 text-accent-blue" />
        <h3 className="font-mono text-xs font-bold tracking-[0.16em] text-foreground">
          {children}
        </h3>
      </div>
      {hint && (
        <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
          {hint}
        </p>
      )}
    </div>
  );
}

function ScoreGauge({ score }: { score: number }) {
  const r = 54;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const offset = c * (1 - pct);
  const color = scoreRing(score);

  return (
    <div className="relative mx-auto flex h-36 w-36 items-center justify-center">
      <svg viewBox="0 0 140 140" className="size-full -rotate-90">
        <circle
          cx="70"
          cy="70"
          r={r}
          fill="none"
          stroke="rgba(255,255,255,0.06)"
          strokeWidth="10"
        />
        <circle
          cx="70"
          cy="70"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={offset}
          className="transition-all duration-700"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={cn("font-mono text-3xl font-bold", scoreColor(score))}>
          {score}
        </span>
        <span className="font-mono text-[10px] tracking-wider text-muted-foreground">
          / 100
        </span>
      </div>
    </div>
  );
}

function ChartTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: Array<{ name?: string; value?: number; payload?: Record<string, unknown> }>;
}) {
  if (!active || !payload?.length) return null;
  const p = payload[0];
  const label =
    (p.payload?.severity as string) ||
    (p.payload?.service as string) ||
    p.name ||
    "";
  return (
    <div className="rounded border border-border-strong bg-panel-alt px-3 py-2 font-mono text-[11px] shadow-lg">
      <p className="text-muted-foreground">{label}</p>
      <p className="font-bold text-foreground">{p.value} finding(s)</p>
    </div>
  );
}

export function ScanReport({ onClose }: { onClose: () => void }) {
  const { scanId, isLive, score, summary, vulnerabilities, compliance } =
    useLiveData();
  const storeSet = useScanStore.setState;

  const [report, setReport] = useState<ReportPackage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState<"pdf" | "docx" | null>(null);
  /** Real scan id used for PDF/DOCX — from store, report, or server latest */
  const [exportScanId, setExportScanId] = useState<string | null>(
    isLive && scanId !== "SCAN-DEMO" ? scanId : null,
  );

  const canExport = Boolean(
    exportScanId ||
      (report?.scan_id && report.scan_id !== "SCAN-DEMO") ||
      (isLive && scanId && scanId !== "SCAN-DEMO"),
  );

  const resolveExportId = () =>
    exportScanId ||
    (report?.scan_id && report.scan_id !== "SCAN-DEMO" ? report.scan_id : null) ||
    (isLive && scanId !== "SCAN-DEMO" ? scanId : null) ||
    undefined;

  const onDownload = async (format: "pdf" | "docx") => {
    const id = resolveExportId();
    setExporting(format);
    setError(null);
    try {
      // Always try server — uses last saved scan if id omitted
      await downloadReportExport(format, id);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : `Could not download ${format.toUpperCase()}. Run a scan once if none is saved yet.`,
      );
    } finally {
      setExporting(null);
    }
  };

  const loadReport = async (forceRefresh = false) => {
    setLoading(true);
    setError(null);
    try {
      // 1) Prefer restoring a real scan into the store if we only have mock data
      if (!isLive || scanId === "SCAN-DEMO") {
        try {
          const latest = await getLatestScan();
          storeSet({ scan: latest });
          setExportScanId(latest.scan_id);
        } catch {
          /* no saved scan yet */
        }
      } else {
        setExportScanId(scanId);
      }

      // 2) Instant reopen: cached report package (no new scan)
      if (!forceRefresh) {
        try {
          const cached = await getLatestReport();
          if (cached?.scan_id) {
            setReport(cached);
            setExportScanId(cached.scan_id);
            setLoading(false);
            // Still warm AI package in background if narrative is thin — skip for speed
            return;
          }
        } catch {
          /* fall through to generate */
        }
      }

      // 3) Generate or refresh from last saved scan (not a new AWS scan)
      const id =
        (isLive && scanId !== "SCAN-DEMO" ? scanId : null) ||
        exportScanId ||
        undefined;
      try {
        const pkg = await generateReport(id, forceRefresh);
        setReport(pkg);
        setExportScanId(pkg.scan_id);
      } catch (e) {
        // Structured fallback from store if we have live findings
        if (isLive && scanId !== "SCAN-DEMO") {
          setReport(
            buildLocalFallback(
              scanId,
              score,
              summary,
              vulnerabilities,
              compliance,
            ),
          );
          setExportScanId(scanId);
          setError(
            e instanceof Error
              ? `Cloud Assistant unavailable (${e.message}). Showing scan data — PDF still uses saved scan.`
              : "Showing scan data from last run.",
          );
        } else {
          setReport(
            buildLocalFallback(
              scanId,
              score,
              summary,
              vulnerabilities,
              compliance,
            ),
          );
          setError(
            e instanceof Error
              ? e.message
              : "No saved scan yet. Run a scan once; then you can reopen and export anytime.",
          );
        }
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadReport(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const pieData = useMemo(() => {
    const rows =
      report?.charts.by_severity ??
      (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => ({
        severity: s,
        count: summary[s] ?? 0,
        label: s,
      }));
    return rows.filter((r) => r.count > 0);
  }, [report, summary]);

  const barData = useMemo(() => {
    if (report?.charts.by_service?.length) return report.charts.by_service;
    const map: Record<string, number> = {};
    for (const v of vulnerabilities) {
      map[v.service] = (map[v.service] || 0) + 1;
    }
    return Object.entries(map)
      .map(([service, count]) => ({ service, count }))
      .sort((a, b) => b.count - a.count);
  }, [report, vulnerabilities]);

  const findings =
    report?.findings_table ??
    vulnerabilities.map((v) => ({
      resource: v.id,
      service: v.service,
      severity: v.severity,
      title: v.title || "",
      description: v.description,
      remediation: v.remediation || "",
      compliance: v.compliance || [],
      why_it_matters: "See description for impact.",
    }));

  const narrative = report?.narrative;
  const metrics = report?.metrics;
  const displayScore = metrics?.score ?? score;
  const totalFindings = metrics?.total_findings ?? vulnerabilities.length;
  const risk = narrative?.risk_level || "MODERATE";

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-background/85 p-3 backdrop-blur-sm sm:p-6"
      role="dialog"
      aria-modal="true"
      aria-label="Security posture report"
    >
      <div className="report-sheet w-full max-w-5xl rounded-lg border border-border bg-panel shadow-2xl">
        {/* Toolbar */}
        <div className="report-toolbar sticky top-0 z-10 flex flex-wrap items-center justify-between gap-2 border-b border-border bg-panel-alt/95 px-5 py-3 backdrop-blur">
          <div className="flex items-center gap-2">
            <Sparkles className="size-3.5 text-accent-blue" />
            <span className="font-mono text-[11px] tracking-[0.16em] text-muted-foreground">
              SECURITY REPORT
              {report?.scan_id && report.scan_id !== "SCAN-DEMO"
                ? ` · SAVED ${report.scan_id}`
                : isLive
                  ? " · LIVE SCAN"
                  : " · PREVIEW"}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => void loadReport(true)}
              disabled={loading}
              className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 font-mono text-[11px] font-bold tracking-wider text-muted-foreground transition hover:bg-white/5 hover:text-foreground disabled:opacity-50"
              title="Refresh Cloud Assistant text for the same scan (does not run a new AWS scan)"
            >
              <RefreshCw className={cn("size-3.5", loading && "animate-spin")} />
              REGENERATE
            </button>
            <button
              type="button"
              onClick={() => void onDownload("pdf")}
              disabled={!!exporting || loading}
              className="flex items-center gap-1.5 rounded-md border border-danger/35 bg-danger/10 px-3 py-1.5 font-mono text-[11px] font-bold tracking-wider text-danger transition hover:bg-danger/15 disabled:opacity-50"
              title={
                canExport
                  ? "Download PDF of the last saved scan (no new scan required)"
                  : "Uses last saved scan on the server if available"
              }
            >
              {exporting === "pdf" ? (
                <Loader2 className="size-3.5 animate-spin" />
              ) : (
                <FileDown className="size-3.5" />
              )}
              PDF
            </button>
            <button
              type="button"
              onClick={() => void onDownload("docx")}
              disabled={!!exporting || loading}
              className="flex items-center gap-1.5 rounded-md border border-accent-blue/40 bg-accent-blue/10 px-3 py-1.5 font-mono text-[11px] font-bold tracking-wider text-accent-blue transition hover:bg-accent-blue/20 disabled:opacity-50"
              title="Download Word document"
            >
              {exporting === "docx" ? (
                <Loader2 className="size-3.5 animate-spin" />
              ) : (
                <FileText className="size-3.5" />
              )}
              WORD
            </button>
            <button
              type="button"
              onClick={() => window.print()}
              className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 font-mono text-[11px] font-bold tracking-wider text-muted-foreground transition hover:bg-white/5 hover:text-foreground"
            >
              <Printer className="size-3.5" />
              PRINT
            </button>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close report"
              className="flex size-8 items-center justify-center rounded-md border border-border text-muted-foreground transition hover:bg-white/5 hover:text-foreground"
            >
              <X className="size-4" />
            </button>
          </div>
        </div>

        {loading && (
          <div className="flex flex-col items-center justify-center gap-3 py-24 font-mono text-xs text-muted-foreground">
            <Loader2 className="size-6 animate-spin text-accent-blue" />
            <p>Cloud Assistant is preparing your report…</p>
            <p className="text-[10px] text-muted-foreground/70">
              Building charts, tables, and plain-language explanations
            </p>
          </div>
        )}

        {!loading && (
          <div className="space-y-8 p-6 sm:p-8">
            {error && (
              <div className="flex items-start gap-2 rounded-md border border-warning/30 bg-warning/5 px-4 py-3 text-xs text-warning">
                <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
                <p>{error}</p>
              </div>
            )}

            {/* Masthead */}
            <header className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-6">
              <div className="flex items-start gap-3">
                <div className="flex size-11 shrink-0 items-center justify-center rounded-md bg-accent-blue">
                  <ShieldHalf
                    className="size-5 text-background"
                    strokeWidth={2.4}
                  />
                </div>
                <div>
                  <h2 className="font-mono text-lg font-bold tracking-[0.08em] text-foreground sm:text-xl">
                    CLOUD SECURITY POSTURE REPORT
                  </h2>
                  <p className="mt-1 max-w-xl text-sm leading-relaxed text-muted-foreground">
                    {narrative?.headline ||
                      "Automated assessment of misconfigurations and compliance gaps."}
                  </p>
                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    <span
                      className={cn(
                        "rounded-sm border px-2.5 py-1 font-mono text-[10px] font-bold tracking-wider",
                        riskStyles[risk] || riskStyles.MODERATE,
                      )}
                    >
                      RISK: {risk}
                    </span>
                    <span className="rounded-sm border border-border px-2.5 py-1 font-mono text-[10px] text-muted-foreground">
                      Scan {report?.scan_id || scanId}
                    </span>
                    {metrics?.account_id && (
                      <span className="rounded-sm border border-border px-2.5 py-1 font-mono text-[10px] text-muted-foreground">
                        Account {metrics.account_id}
                      </span>
                    )}
                    {metrics?.region && (
                      <span className="rounded-sm border border-border px-2.5 py-1 font-mono text-[10px] text-muted-foreground">
                        {metrics.region}
                      </span>
                    )}
                  </div>
                </div>
              </div>
              <div className="text-right font-mono text-[11px] leading-relaxed text-muted-foreground">
                <p>Generated with Cloud Assistant</p>
                <p>{report?.generated_at || new Date().toISOString()}</p>
              </div>
            </header>

            {/* Score + AI narrative */}
            <section className="grid gap-4 lg:grid-cols-3">
              <div className="rounded-lg border border-border bg-panel-alt p-5 text-center">
                <SectionTitle icon={ShieldHalf} hint="Higher is safer.">
                  POSTURE SCORE
                </SectionTitle>
                <ScoreGauge score={displayScore} />
                <p className="mt-2 text-[11px] text-muted-foreground">
                  {totalFindings} total finding{totalFindings === 1 ? "" : "s"}{" "}
                  in this scan
                </p>
              </div>

              <div className="rounded-lg border border-border bg-panel-alt p-5 lg:col-span-2">
                <SectionTitle
                  icon={Sparkles}
                  hint="Written for managers — what matters in plain language."
                >
                  EXECUTIVE BRIEF
                </SectionTitle>
                <p className="text-sm leading-relaxed text-foreground/90">
                  {narrative?.executive_summary ||
                    "Run a live scan, then regenerate to get a Cloud Assistant brief."}
                </p>
                <div className="mt-4 rounded-md border border-border bg-background/50 px-4 py-3">
                  <p className="mb-1 font-mono text-[10px] font-bold tracking-wider text-accent-blue">
                    WHAT THIS MEANS FOR THE BUSINESS
                  </p>
                  <p className="text-[13px] leading-relaxed text-muted-foreground">
                    {narrative?.what_this_means}
                  </p>
                </div>
              </div>
            </section>

            {/* Charts */}
            <section className="grid gap-4 lg:grid-cols-2">
              <div className="rounded-lg border border-border bg-panel-alt p-5">
                <SectionTitle
                  icon={AlertTriangle}
                  hint="How serious are the issues? Critical and High should be fixed first."
                >
                  FINDINGS BY SEVERITY
                </SectionTitle>
                {pieData.length === 0 ? (
                  <p className="py-10 text-center text-xs text-muted-foreground">
                    No findings — clean posture for this scan.
                  </p>
                ) : (
                  <div className="flex flex-col items-center gap-4 sm:flex-row">
                    <div className="h-48 w-full sm:w-1/2">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={pieData}
                            dataKey="count"
                            nameKey="severity"
                            innerRadius={48}
                            outerRadius={72}
                            paddingAngle={2}
                          >
                            {pieData.map((entry) => (
                              <Cell
                                key={entry.severity}
                                fill={
                                  SEV_COLORS[entry.severity] || "#6b7280"
                                }
                              />
                            ))}
                          </Pie>
                          <Tooltip content={<ChartTooltip />} />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                    <ul className="w-full space-y-2 sm:w-1/2">
                      {(report?.charts.by_severity || pieData).map((row) => (
                        <li
                          key={row.severity}
                          className="flex items-start justify-between gap-2 text-[12px]"
                        >
                          <div className="flex items-start gap-2">
                            <span
                              className="mt-1 size-2.5 shrink-0 rounded-sm"
                              style={{
                                background:
                                  SEV_COLORS[row.severity] || "#6b7280",
                              }}
                            />
                            <div>
                              <p className="font-mono text-[11px] font-bold text-foreground">
                                {row.severity}{" "}
                                <span className="text-muted-foreground">
                                  ({row.count})
                                </span>
                              </p>
                              {"label" in row && row.label && (
                                <p className="text-[11px] text-muted-foreground">
                                  {row.label}
                                </p>
                              )}
                            </div>
                          </div>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              <div className="rounded-lg border border-border bg-panel-alt p-5">
                <SectionTitle
                  icon={Info}
                  hint="Which AWS services have the most problems?"
                >
                  FINDINGS BY SERVICE
                </SectionTitle>
                {barData.length === 0 ? (
                  <p className="py-10 text-center text-xs text-muted-foreground">
                    No service breakdown yet.
                  </p>
                ) : (
                  <div className="h-52 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={barData}
                        margin={{ top: 8, right: 8, left: -12, bottom: 0 }}
                      >
                        <CartesianGrid
                          stroke="rgba(255,255,255,0.05)"
                          vertical={false}
                        />
                        <XAxis
                          dataKey="service"
                          tick={{ fill: "#6b7280", fontSize: 10 }}
                          axisLine={false}
                          tickLine={false}
                        />
                        <YAxis
                          allowDecimals={false}
                          tick={{ fill: "#6b7280", fontSize: 10 }}
                          axisLine={false}
                          tickLine={false}
                        />
                        <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(56,116,255,0.08)" }} />
                        <Bar dataKey="count" fill="#3874ff" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </div>
            </section>

            {/* Priority actions */}
            <section className="rounded-lg border border-border bg-panel-alt p-5">
              <SectionTitle
                icon={ListOrdered}
                hint="Start at the top. Complete these, then re-scan."
              >
                PRIORITY ACTION PLAN
              </SectionTitle>
              <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed text-foreground/90">
                {narrative?.priority_actions || "No actions generated yet."}
              </pre>
            </section>

            {/* Findings table */}
            <section>
              <SectionTitle
                icon={BookOpen}
                hint="Each row is one problem: what it is, why it matters, and how to fix it."
              >
                DETAILED FINDINGS TABLE
              </SectionTitle>
              <div className="overflow-x-auto rounded-lg border border-border">
                <table className="w-full min-w-[720px] border-collapse text-left">
                  <thead>
                    <tr className="border-b border-border bg-panel-alt font-mono text-[10px] tracking-[0.12em] text-muted-foreground">
                      <th className="px-3 py-3 font-medium">#</th>
                      <th className="px-3 py-3 font-medium">SEVERITY</th>
                      <th className="px-3 py-3 font-medium">SERVICE</th>
                      <th className="px-3 py-3 font-medium">WHAT WE FOUND</th>
                      <th className="px-3 py-3 font-medium">WHY IT MATTERS</th>
                      <th className="px-3 py-3 font-medium">HOW TO FIX</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.length === 0 ? (
                      <tr>
                        <td
                          colSpan={6}
                          className="px-4 py-8 text-center text-sm text-muted-foreground"
                        >
                          No findings — nothing to remediate in this scan.
                        </td>
                      </tr>
                    ) : (
                      findings.map((f, i) => (
                        <tr
                          key={`${f.resource}-${i}`}
                          className="border-t border-border/70 align-top transition hover:bg-white/[0.02]"
                        >
                          <td className="px-3 py-3 font-mono text-[11px] text-muted-foreground">
                            {i + 1}
                          </td>
                          <td className="px-3 py-3">
                            <span
                              className="rounded-sm border px-1.5 py-0.5 font-mono text-[10px] font-bold"
                              style={{
                                color: SEV_COLORS[f.severity] || "#6b7280",
                                borderColor: `${SEV_COLORS[f.severity] || "#6b7280"}55`,
                                background: `${SEV_COLORS[f.severity] || "#6b7280"}18`,
                              }}
                            >
                              {f.severity}
                            </span>
                          </td>
                          <td className="px-3 py-3 font-mono text-[11px] text-muted-foreground">
                            {f.service}
                          </td>
                          <td className="max-w-[220px] px-3 py-3">
                            <p className="text-[12px] font-semibold text-foreground">
                              {f.title || f.resource}
                            </p>
                            <p className="mt-0.5 font-mono text-[10px] text-muted-foreground">
                              {f.resource}
                            </p>
                            <p className="mt-1 text-[11px] leading-snug text-muted-foreground">
                              {f.description}
                            </p>
                            {f.compliance?.length > 0 && (
                              <p className="mt-1 font-mono text-[9px] text-accent-blue/80">
                                {f.compliance.slice(0, 3).join(" · ")}
                              </p>
                            )}
                          </td>
                          <td className="max-w-[180px] px-3 py-3 text-[12px] leading-snug text-muted-foreground">
                            {f.why_it_matters}
                          </td>
                          <td className="max-w-[220px] px-3 py-3">
                            <code className="block whitespace-pre-wrap break-all rounded border border-border bg-background/60 px-2 py-1.5 font-mono text-[10px] leading-relaxed text-success/90">
                              {f.remediation || "See remediation hub"}
                            </code>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </section>

            {/* Compliance */}
            <section>
              <SectionTitle
                icon={CheckCircle2}
                hint="How this environment looks against common audit frameworks."
              >
                COMPLIANCE SNAPSHOT
              </SectionTitle>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {(report?.compliance || compliance).map((f) => {
                  const pct = f.total
                    ? Math.round((f.passed / f.total) * 100)
                    : 0;
                  return (
                    <div
                      key={f.name}
                      className="rounded-lg border border-border bg-panel-alt p-4"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <p className="truncate text-xs font-semibold text-foreground">
                            {f.name}
                          </p>
                          <p className="font-mono text-[10px] text-muted-foreground">
                            {f.version}
                          </p>
                        </div>
                        <span
                          className={cn(
                            "shrink-0 rounded-sm px-2 py-0.5 font-mono text-[10px] font-bold",
                            f.status === "PASSING"
                              ? "bg-success/15 text-success"
                              : "bg-danger/15 text-danger",
                          )}
                        >
                          {f.status}
                        </span>
                      </div>
                      <div className="mt-3 flex items-end gap-2">
                        <span className="font-mono text-2xl font-bold text-foreground">
                          {pct}%
                        </span>
                        <span className="mb-1 font-mono text-[10px] text-muted-foreground">
                          {f.passed}/{f.total} controls
                        </span>
                      </div>
                      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-background">
                        <div
                          className={cn(
                            "h-full rounded-full",
                            pct >= 85 ? "bg-success" : pct >= 60 ? "bg-warning" : "bg-danger",
                          )}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </section>

            {/* Technical notes + glossary */}
            <section className="grid gap-4 lg:grid-cols-2">
              <div className="rounded-lg border border-border bg-panel-alt p-5">
                <SectionTitle
                  icon={Info}
                  hint="For security engineers and DevOps."
                >
                  TECHNICAL NOTES
                </SectionTitle>
                <p className="text-sm leading-relaxed text-muted-foreground">
                  {narrative?.technical_notes}
                </p>
              </div>
              <div className="rounded-lg border border-border bg-panel-alt p-5">
                <SectionTitle
                  icon={BookOpen}
                  hint="Quick definitions so the whole team can read this report."
                >
                  GLOSSARY
                </SectionTitle>
                <ul className="space-y-2.5">
                  {(report?.glossary || DEFAULT_GLOSSARY).map((g) => (
                    <li key={g.term} className="text-[12px] leading-snug">
                      <span className="font-semibold text-foreground">
                        {g.term}
                      </span>
                      <span className="text-muted-foreground">
                        {" — "}
                        {g.meaning}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            </section>

            <footer className="border-t border-border pt-4 text-center font-mono text-[10px] tracking-wider text-muted-foreground">
              V.A.U.L.T.S.C.A.N. · CLOUD ASSISTANT REPORT · CONFIDENTIAL
            </footer>
          </div>
        )}
      </div>
    </div>
  );
}

const DEFAULT_GLOSSARY = [
  {
    term: "Posture score",
    meaning:
      "0–100 health score. 100 means no known misconfigurations in this scan.",
  },
  {
    term: "Critical",
    meaning:
      "Actively dangerous exposure (e.g. public data or world-open admin ports).",
  },
  {
    term: "High",
    meaning:
      "Serious weakness that attackers often chain with other issues.",
  },
];

function buildLocalFallback(
  scanId: string,
  score: number,
  summary: Record<Severity, number>,
  vulnerabilities: Array<{
    id: string;
    service: string;
    severity: Severity;
    description: string;
    title?: string;
    remediation?: string;
    compliance?: string[];
  }>,
  compliance: ReportPackage["compliance"],
): ReportPackage {
  const risk =
    score >= 90 ? "LOW" : score >= 70 ? "MODERATE" : score >= 40 ? "HIGH" : "CRITICAL";
  const total = vulnerabilities.length;
  const byService: Record<string, number> = {};
  for (const v of vulnerabilities) {
    byService[v.service] = (byService[v.service] || 0) + 1;
  }

  return {
    scan_id: scanId,
    generated_at: new Date().toISOString(),
    narrative: {
      headline: `Cloud security posture is ${risk.toLowerCase()} (${score}/100)`,
      risk_level: risk,
      executive_summary: `This report covers ${total} finding(s): ${summary.CRITICAL ?? 0} critical, ${summary.HIGH ?? 0} high, ${summary.MEDIUM ?? 0} medium, ${summary.LOW ?? 0} low. A score of ${score}/100 reflects current cloud configuration health.`,
      what_this_means:
        "Misconfigurations are settings left too open. Critical and High items can lead to data exposure or account compromise if left unfixed.",
      priority_actions: vulnerabilities
        .slice(0, 5)
        .map(
          (v, i) =>
            `${i + 1}. [${v.severity}] ${v.id}: ${v.title || v.description}`,
        )
        .join("\n") || "1. No open issues.",
      technical_notes:
        "Run a live scan with a connected AWS account for Cloud Assistant enrichment. Remediation commands appear in the findings table.",
    },
    metrics: {
      score,
      total_findings: total,
      summary,
    },
    charts: {
      by_severity: (
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as Severity[]
      ).map((s) => ({
        severity: s,
        count: summary[s] ?? 0,
        label:
          s === "CRITICAL"
            ? "Critical — fix immediately"
            : s === "HIGH"
              ? "High — fix this week"
              : s === "MEDIUM"
                ? "Medium — plan remediation"
                : "Low — harden when possible",
      })),
      by_service: Object.entries(byService)
        .map(([service, count]) => ({ service, count }))
        .sort((a, b) => b.count - a.count),
    },
    findings_table: vulnerabilities.map((v) => ({
      resource: v.id,
      service: v.service,
      severity: v.severity,
      title: v.title || "",
      description: v.description,
      remediation: v.remediation || "",
      compliance: v.compliance || [],
      why_it_matters:
        v.severity === "CRITICAL"
          ? "Highest priority — treat as urgent until fixed."
          : "Review and schedule remediation based on severity.",
    })),
    compliance,
    remediation: {},
    glossary: DEFAULT_GLOSSARY,
  };
}
