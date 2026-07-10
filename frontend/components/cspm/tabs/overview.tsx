"use client";

import { ArrowDownRight, ArrowUpRight } from "lucide-react";
import { PostureChart } from "../posture-chart";
import { AuditStream } from "../audit-stream";
import { useLiveData } from "@/lib/scan-store";
import { cn } from "@/lib/utils";

function StatCard({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-border bg-panel p-5">
      <div className="mb-4 flex items-center gap-2 font-mono text-[11px] tracking-[0.14em] text-muted-foreground">
        <span className="text-accent-blue">■</span>
        {title}
      </div>
      {children}
    </div>
  );
}

function scoreTone(score: number) {
  if (score >= 90) return "text-success";
  if (score >= 70) return "text-warning";
  return "text-danger";
}

export function OverviewTab() {
  const {
    score,
    summary,
    compliance,
    infraStatus,
    isLive,
    postureTrend,
  } = useLiveData();

  const critical = summary.CRITICAL ?? 0;
  const compliancePct = (() => {
    if (!compliance.length) return 0;
    const passed = compliance.reduce((a, c) => a + c.passed, 0);
    const total = compliance.reduce((a, c) => a + c.total, 0);
    return total ? Math.round((passed / total) * 100) : 0;
  })();
  const failingFrameworks = compliance.filter(
    (c) => c.status === "FAILING",
  ).length;

  return (
    <div className="flex min-h-full flex-col gap-4">
      {!isLive && (
        <div className="rounded-md border border-warning/30 bg-warning/5 px-4 py-2 font-mono text-[11px] text-warning">
          Showing design mock data — launch a scan to load live AWS findings.
        </div>
      )}

      {/* KPI row */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <StatCard title="POSTURE SCORE">
          <div className="flex items-end gap-2">
            <span
              className={cn(
                "font-mono text-5xl font-bold leading-none",
                scoreTone(score),
              )}
            >
              {score}
            </span>
            <span className={cn("mb-1 font-mono text-xl", scoreTone(score))}>
              %
            </span>
          </div>
          <p className="mt-3 text-[11px] text-muted-foreground">
            {score >= 90
              ? "Optimal — posture is strong."
              : score >= 70
                ? "Acceptable — fix high/critical issues soon."
                : "At risk — prioritize critical findings."}
          </p>
        </StatCard>

        <StatCard title="CRITICAL MISCONFIGURATIONS">
          <div className="flex items-end gap-3">
            <span className="font-mono text-5xl font-bold leading-none text-foreground">
              {String(critical).padStart(2, "0")}
            </span>
            <span
              className={cn(
                "mb-1 flex items-center gap-0.5 font-mono text-xs font-bold",
                critical === 0 ? "text-success" : "text-danger",
              )}
            >
              {critical === 0 ? (
                <>
                  <ArrowDownRight className="size-4" />
                  CLEAR
                </>
              ) : (
                <>
                  <ArrowUpRight className="size-4" />
                  OPEN
                </>
              )}
            </span>
          </div>
          <p className="mt-3 text-[11px] text-muted-foreground">
            HIGH: {summary.HIGH ?? 0} · MED: {summary.MEDIUM ?? 0} · LOW:{" "}
            {summary.LOW ?? 0}
          </p>
        </StatCard>

        <StatCard title="COMPLIANCE COVERAGE">
          <div className="flex items-end gap-3">
            <span
              className={cn(
                "font-mono text-5xl font-bold leading-none",
                compliancePct >= 80 ? "text-success" : "text-warning",
              )}
            >
              {compliancePct}
            </span>
            <span
              className={cn(
                "mb-1 font-mono text-xl",
                compliancePct >= 80 ? "text-success" : "text-warning",
              )}
            >
              %
            </span>
          </div>
          <p className="mt-3 text-[11px] text-muted-foreground">
            {compliance.length} frameworks mapped · {failingFrameworks} failing.
          </p>
        </StatCard>
      </div>

      {/* Chart + infra */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="rounded-lg border border-border bg-panel p-5 lg:col-span-2">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h3 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
              POSTURE TREND
            </h3>
            <span
              className={cn(
                "rounded-sm border px-2 py-0.5 font-mono text-[10px]",
                postureTrend.length
                  ? "border-success/40 bg-success/10 text-success"
                  : "border-border bg-panel-alt text-muted-foreground",
              )}
            >
              {postureTrend.length
                ? `${postureTrend.length} SCAN${postureTrend.length === 1 ? "" : "S"}`
                : "WAITING FOR SCANS"}
            </span>
          </div>
          <PostureChart data={postureTrend} />
        </div>

        <div className="flex flex-col rounded-lg border border-border bg-panel p-5">
          <h3 className="mb-4 font-mono text-xs font-bold tracking-[0.14em] text-foreground">
            ACTIVE INFRASTRUCTURE STATUS
          </h3>
          <div className="space-y-3">
            {infraStatus.map((item) => (
              <div
                key={item.label}
                className="rounded-md border border-border bg-panel-alt px-3 py-2.5"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[10px] tracking-wider text-muted-foreground">
                    {item.label}
                  </span>
                  <span
                    className={cn(
                      "flex items-center gap-1 font-mono text-[10px] font-bold uppercase",
                      item.state === "online" ? "text-success" : "text-warning",
                    )}
                  >
                    <span
                      className={cn(
                        "pulse-dot size-1.5 rounded-full",
                        item.state === "online" ? "bg-success" : "bg-warning",
                      )}
                    />
                    {item.state}
                  </span>
                </div>
                <p className="mt-1 font-mono text-xs font-bold text-foreground">
                  {item.value}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Full-width audit stream — fills remaining overview space */}
      <div className="min-h-0 flex-1">
        <AuditStream variant="panel" />
      </div>
    </div>
  );
}
