"use client";

import { useState } from "react";
import {
  ArrowDownRight,
  ArrowUpRight,
  HelpCircle,
  ShieldCheck,
  BookOpenCheck,
} from "lucide-react";
import { PostureChart } from "../posture-chart";
import { AuditStream } from "../audit-stream";
import { useLiveData } from "@/lib/scan-store";
import { cn } from "@/lib/utils";

function StatCard({
  title,
  subtitle,
  explain,
  children,
}: {
  title: string;
  /** One-line plain-language meaning under the title */
  subtitle: string;
  /** Longer “what is this?” copy shown when user opens help */
  explain: string;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(false);

  return (
    <div className="rounded-lg border border-border bg-panel p-5">
      <div className="mb-1 flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2 font-mono text-[11px] tracking-[0.14em] text-muted-foreground">
            <span className="text-accent-blue">■</span>
            {title}
          </div>
          <p className="mt-1 text-xs leading-snug text-foreground/80">
            {subtitle}
          </p>
        </div>
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className={cn(
            "shrink-0 rounded-md border p-1.5 transition",
            open
              ? "border-accent-blue/50 bg-accent-blue/10 text-accent-blue"
              : "border-border bg-panel-alt text-muted-foreground hover:border-border-strong hover:text-foreground",
          )}
          aria-expanded={open}
          aria-label={`What is ${title}?`}
          title="What does this mean?"
        >
          <HelpCircle className="size-3.5" />
        </button>
      </div>

      {open && (
        <div className="mb-3 rounded-md border border-accent-blue/25 bg-accent-blue/5 px-3 py-2 text-[11px] leading-relaxed text-muted-foreground">
          {explain}
        </div>
      )}

      {children}
    </div>
  );
}

function scoreTone(score: number) {
  if (score >= 90) return "text-success";
  if (score >= 70) return "text-warning";
  return "text-danger";
}

function scoreBand(score: number): { label: string; detail: string } {
  if (score >= 90) {
    return {
      label: "Strong",
      detail: "Few or low-severity issues. Keep monitoring.",
    };
  }
  if (score >= 70) {
    return {
      label: "Needs attention",
      detail: "Fix High and Critical issues soon to raise this score.",
    };
  }
  return {
    label: "At risk",
    detail: "Serious misconfigurations found. Prioritize Critical fixes first.",
  };
}

function complianceBand(pct: number): { label: string; detail: string } {
  if (pct >= 90) {
    return {
      label: "Well aligned",
      detail: "Most modeled industry controls still look healthy.",
    };
  }
  if (pct >= 80) {
    return {
      label: "Mostly aligned",
      detail: "A few framework-linked findings — review the cards below.",
    };
  }
  return {
    label: "Gaps found",
    detail: "Findings map to several industry controls that need fixing.",
  };
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
  const high = summary.HIGH ?? 0;
  const med = summary.MEDIUM ?? 0;
  const low = summary.LOW ?? 0;
  const totalFindings = critical + high + med + low;

  const compliancePct = (() => {
    if (!compliance.length) return 0;
    const passed = compliance.reduce((a, c) => a + c.passed, 0);
    const total = compliance.reduce((a, c) => a + c.total, 0);
    return total ? Math.round((passed / total) * 100) : 0;
  })();
  const failingFrameworks = compliance.filter(
    (c) => c.status === "FAILING",
  ).length;

  const posture = scoreBand(score);
  const complianceStatus = complianceBand(compliancePct);

  return (
    <div className="flex min-h-full flex-col gap-4">
      {!isLive && (
        <div className="rounded-md border border-warning/30 bg-warning/5 px-4 py-2 font-mono text-[11px] text-warning">
          Showing design mock data — launch a scan to load live AWS findings.
        </div>
      )}

      {/* KPI row */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <StatCard
          title="POSTURE SCORE"
          subtitle="Overall cloud security health (0–100)"
          explain="Posture Score is VaultScan’s health grade for your AWS account after the latest scan. You start at 100; each finding lowers the score by severity (Critical hurts more than Low). Higher is safer. It answers: “How exposed is this environment right now?” It is not a legal audit score."
        >
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
              /100
            </span>
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <span
              className={cn(
                "inline-flex items-center gap-1 rounded-sm border px-2 py-0.5 font-mono text-[10px] font-bold tracking-wider",
                score >= 90
                  ? "border-success/40 bg-success/10 text-success"
                  : score >= 70
                    ? "border-warning/40 bg-warning/10 text-warning"
                    : "border-danger/40 bg-danger/10 text-danger",
              )}
            >
              <ShieldCheck className="size-3" />
              {posture.label.toUpperCase()}
            </span>
            <span className="text-[11px] text-muted-foreground">
              {totalFindings} finding{totalFindings === 1 ? "" : "s"} in last
              scan
            </span>
          </div>
          <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
            {posture.detail}
          </p>
        </StatCard>

        <StatCard
          title="CRITICAL ISSUES"
          subtitle="Problems that need action first"
          explain="Critical issues are the most dangerous misconfigurations VaultScan found (for example public data or world-open admin ports). High / Medium / Low are less urgent but still worth fixing. Open Findings for the full list and how to remediate each one."
        >
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
            Also open — High: {high} · Medium: {med} · Low: {low}
          </p>
          <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
            {critical === 0
              ? "No critical exposure detected. Still review High findings."
              : "Fix these before anything else — they create the fastest path to a breach."}
          </p>
        </StatCard>

        <StatCard
          title="COMPLIANCE COVERAGE"
          subtitle="Alignment with industry standards"
          explain="Compliance Coverage estimates how well this scan’s results align with common frameworks (CIS AWS, NIST SP 800-53, GDPR security controls). VaultScan tags each finding to those frameworks and shows how many modeled controls still look healthy. It is a CSPM-style map for managers—not a formal certification or full audit. Use it to answer: “Which security standards do these issues affect?”"
        >
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
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <span
              className={cn(
                "inline-flex items-center gap-1 rounded-sm border px-2 py-0.5 font-mono text-[10px] font-bold tracking-wider",
                compliancePct >= 80
                  ? "border-success/40 bg-success/10 text-success"
                  : "border-warning/40 bg-warning/10 text-warning",
              )}
            >
              <BookOpenCheck className="size-3" />
              {complianceStatus.label.toUpperCase()}
            </span>
            <span className="text-[11px] text-muted-foreground">
              {compliance.length} standard
              {compliance.length === 1 ? "" : "s"}
              {failingFrameworks > 0
                ? ` · ${failingFrameworks} need work`
                : " · all looking good"}
            </span>
          </div>
          <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
            {complianceStatus.detail}
          </p>
        </StatCard>
      </div>

      {/* Compact compliance strip with plain labels */}
      {compliance.length > 0 && (
        <div className="rounded-lg border border-border bg-panel p-4">
          <div className="mb-3 flex flex-wrap items-start justify-between gap-2">
            <div>
              <h3 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
                STANDARDS BREAKDOWN
              </h3>
              <p className="mt-1 max-w-2xl text-[11px] leading-relaxed text-muted-foreground">
                Each card is one industry framework. Percentage = share of that
                framework’s modeled controls that still pass after this scan.
                Fixing tagged findings in the Findings tab raises these numbers.
              </p>
            </div>
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            {compliance.map((c) => {
              const pct = c.total
                ? Math.round((c.passed / c.total) * 100)
                : 0;
              const shortHint =
                c.name.includes("CIS")
                  ? "AWS security baseline (industry checklist)"
                  : c.name.includes("NIST")
                    ? "US federal security control family"
                    : c.name.includes("GDPR")
                      ? "EU data-protection security measures"
                      : "Security framework";
              return (
                <div
                  key={c.name}
                  className={cn(
                    "rounded-lg border px-4 py-3",
                    c.status === "PASSING"
                      ? "border-success/25 bg-success/5"
                      : "border-danger/25 bg-danger/5",
                  )}
                >
                  <div className="flex items-center justify-between gap-2">
                    <p className="truncate text-xs font-semibold text-foreground">
                      {c.name}
                    </p>
                    <span
                      className={cn(
                        "shrink-0 font-mono text-[10px] font-bold",
                        c.status === "PASSING" ? "text-success" : "text-danger",
                      )}
                    >
                      {c.status === "PASSING" ? "ON TRACK" : "NEEDS WORK"}
                    </span>
                  </div>
                  <p className="mt-0.5 text-[10px] text-muted-foreground">
                    {shortHint}
                  </p>
                  <p className="mt-1.5 font-mono text-lg font-bold text-foreground">
                    {pct}
                    <span className="text-sm text-muted-foreground">%</span>
                  </p>
                  <p className="font-mono text-[10px] text-muted-foreground">
                    {c.passed} of {c.total} controls OK · {c.version}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Chart + infra */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="rounded-lg border border-border bg-panel p-5 lg:col-span-2">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
                POSTURE TREND
              </h3>
              <p className="mt-1 text-[11px] text-muted-foreground">
                How the health score changed across recent scans (higher =
                safer).
              </p>
            </div>
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
          <h3 className="mb-1 font-mono text-xs font-bold tracking-[0.14em] text-foreground">
            ACTIVE INFRASTRUCTURE STATUS
          </h3>
          <p className="mb-4 text-[11px] text-muted-foreground">
            Connection and engine status for this session.
          </p>
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
