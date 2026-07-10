"use client";

import { useMemo } from "react";
import {
  GitBranch,
  ShieldAlert,
  ArrowDown,
  Crosshair,
  Lightbulb,
} from "lucide-react";
import { useLiveData } from "@/lib/scan-store";
import { cn } from "@/lib/utils";
import type { Severity } from "@/components/cspm/data";

const severityStyles: Record<string, string> = {
  CRITICAL: "border-danger/40 bg-danger/10 text-danger",
  HIGH: "border-warning/40 bg-warning/10 text-warning",
  MEDIUM: "border-accent-blue/40 bg-accent-blue/10 text-accent-blue",
  LOW: "border-border text-muted-foreground",
};

type PathStep = {
  role: string;
  rule_id?: string;
  severity?: string;
  service?: string;
  resource?: string;
  title?: string;
  remediation?: string;
};

type AttackPath = {
  id: string;
  name: string;
  outcome: string;
  severity: string;
  likelihood: string;
  impact: string;
  steps: PathStep[];
  break_chain: string[];
};

/** Client-side fallback if older scans lack attack_paths */
function deriveClientPaths(
  vulnerabilities: Array<{
    id: string;
    service: string;
    severity: Severity;
    title?: string;
    description: string;
    remediation?: string;
    rule_id?: string;
  }>,
): AttackPath[] {
  if (!vulnerabilities.length) return [];
  const by = (pred: (v: (typeof vulnerabilities)[0]) => boolean) =>
    vulnerabilities.filter(pred);
  const paths: AttackPath[] = [];

  const s3pub = by(
    (v) =>
      v.service === "S3" &&
      (v.severity === "CRITICAL" ||
        (v.title || v.description).toLowerCase().includes("public")),
  );
  const s3enc = by(
    (v) =>
      v.service === "S3" &&
      (v.title || v.description).toLowerCase().includes("encrypt"),
  );
  if (s3pub[0]) {
    const steps: PathStep[] = [
      {
        role: "entry",
        ...s3pub[0],
        resource: s3pub[0].id,
        title: s3pub[0].title || s3pub[0].description,
      },
    ];
    if (s3enc[0]) {
      steps.push({
        role: "amplify",
        ...s3enc[0],
        resource: s3enc[0].id,
        title: s3enc[0].title || s3enc[0].description,
      });
    }
    paths.push({
      id: "client-s3",
      name: "Public storage → data exposure",
      outcome: "Objects may be readable from the internet",
      severity: "CRITICAL",
      likelihood: "High",
      impact: "Data breach risk",
      steps,
      break_chain: [
        "Enable Block Public Access",
        "Remove public ACLs/policies",
        "Enable encryption",
      ],
    });
  }

  const sg = by(
    (v) =>
      v.service === "EC2" &&
      (v.severity === "CRITICAL" ||
        (v.title || "").toLowerCase().includes("world") ||
        (v.title || "").toLowerCase().includes("0.0.0.0")),
  );
  const iam = by(
    (v) =>
      v.service === "IAM" &&
      (v.severity === "HIGH" || v.severity === "CRITICAL"),
  );
  if (sg[0] && iam[0]) {
    paths.push({
      id: "client-takeover",
      name: "Open admin port + weak IAM → takeover",
      outcome: "Foothold then privilege abuse",
      severity: "CRITICAL",
      likelihood: "High",
      impact: "Account compromise",
      steps: [
        {
          role: "entry",
          ...sg[0],
          resource: sg[0].id,
          title: sg[0].title || sg[0].description,
        },
        {
          role: "escalate",
          ...iam[0],
          resource: iam[0].id,
          title: iam[0].title || iam[0].description,
        },
      ],
      break_chain: [
        "Close world-open SSH/RDP",
        "Enforce MFA and least privilege",
      ],
    });
  }

  return paths;
}

export function AttackPathsTab() {
  const { scan, vulnerabilities, isLive } = useLiveData();

  const paths = useMemo(() => {
    const fromScan = (scan as { attack_paths?: AttackPath[] } | null)
      ?.attack_paths;
    if (fromScan && fromScan.length > 0) return fromScan;
    return deriveClientPaths(vulnerabilities);
  }, [scan, vulnerabilities]);

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-border bg-panel p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <div className="flex size-10 items-center justify-center rounded-md bg-danger/15 text-danger">
              <GitBranch className="size-5" />
            </div>
            <div>
              <h3 className="font-mono text-sm font-bold tracking-[0.12em] text-foreground">
                ATTACK PATH VISUALIZATION
              </h3>
              <p className="mt-1 max-w-2xl text-xs leading-relaxed text-muted-foreground">
                Misconfigurations rarely stand alone. These chains show how
                findings combine into higher-impact outcomes — and how to break
                the path.
              </p>
            </div>
          </div>
          <span className="rounded-sm border border-border px-2 py-1 font-mono text-[10px] text-muted-foreground">
            {paths.length} PATH{paths.length === 1 ? "" : "S"}
            {!isLive && " · FROM MOCK/LIVE DATA"}
          </span>
        </div>
      </div>

      {paths.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-border bg-panel px-6 py-20 text-center">
          <ShieldAlert className="size-10 text-success/60" />
          <p className="font-mono text-xs font-bold tracking-wider text-foreground">
            NO ACTIVE ATTACK PATHS
          </p>
          <p className="max-w-md text-xs text-muted-foreground">
            {vulnerabilities.length === 0
              ? "Run a scan to analyze how misconfigurations chain together."
              : "Current findings do not form a known multi-step attack chain. Keep hardening individual issues."}
          </p>
        </div>
      ) : (
        <div className="space-y-5">
          {paths.map((path, idx) => (
            <article
              key={path.id}
              className="overflow-hidden rounded-lg border border-border bg-panel"
            >
              <header className="flex flex-wrap items-start justify-between gap-3 border-b border-border bg-panel-alt/50 px-5 py-4">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[10px] text-muted-foreground">
                      PATH {String(idx + 1).padStart(2, "0")}
                    </span>
                    <span
                      className={cn(
                        "rounded-sm border px-2 py-0.5 font-mono text-[10px] font-bold tracking-wider",
                        severityStyles[path.severity] || severityStyles.HIGH,
                      )}
                    >
                      {path.severity}
                    </span>
                  </div>
                  <h4 className="mt-1.5 text-base font-semibold text-foreground">
                    {path.name}
                  </h4>
                  <p className="mt-1 flex items-start gap-1.5 text-xs text-muted-foreground">
                    <Crosshair className="mt-0.5 size-3.5 shrink-0 text-danger" />
                    <span>
                      <span className="font-medium text-foreground">
                        Outcome:{" "}
                      </span>
                      {path.outcome}
                    </span>
                  </p>
                </div>
                <div className="max-w-xs space-y-1 text-right font-mono text-[10px] text-muted-foreground">
                  <p>
                    <span className="text-foreground">Likelihood:</span>{" "}
                    {path.likelihood}
                  </p>
                  <p>
                    <span className="text-foreground">Impact:</span>{" "}
                    {path.impact}
                  </p>
                </div>
              </header>

              {/* Chain steps */}
              <div className="px-5 py-6">
                <div className="mx-auto flex max-w-2xl flex-col items-stretch gap-0">
                  {path.steps.map((step, i) => (
                    <div key={`${path.id}-${i}`} className="flex flex-col items-center">
                      <div
                        className={cn(
                          "w-full rounded-lg border px-4 py-3",
                          step.severity === "CRITICAL"
                            ? "border-danger/35 bg-danger/5"
                            : step.severity === "HIGH"
                              ? "border-warning/35 bg-warning/5"
                              : "border-border bg-panel-alt",
                        )}
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="rounded-sm border border-border px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider text-muted-foreground">
                            {step.role}
                          </span>
                          {step.severity && (
                            <span
                              className={cn(
                                "rounded-sm border px-1.5 py-0.5 font-mono text-[9px] font-bold",
                                severityStyles[step.severity],
                              )}
                            >
                              {step.severity}
                            </span>
                          )}
                          {step.service && (
                            <span className="font-mono text-[10px] text-muted-foreground">
                              {step.service}
                            </span>
                          )}
                        </div>
                        <p className="mt-2 text-sm font-medium text-foreground">
                          {step.title}
                        </p>
                        <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                          {step.resource}
                        </p>
                      </div>
                      {i < path.steps.length - 1 && (
                        <div className="flex flex-col items-center py-1 text-muted-foreground">
                          <div className="h-4 w-px bg-border-strong" />
                          <ArrowDown className="size-4" />
                          <div className="h-1 w-px bg-border-strong" />
                        </div>
                      )}
                    </div>
                  ))}
                  {/* Final outcome node */}
                  <div className="mt-1 flex flex-col items-center">
                    <div className="flex flex-col items-center py-1 text-danger">
                      <div className="h-3 w-px bg-danger/40" />
                      <ArrowDown className="size-4" />
                    </div>
                    <div className="w-full rounded-lg border border-danger/40 bg-danger/10 px-4 py-3 text-center">
                      <p className="font-mono text-[10px] font-bold tracking-wider text-danger">
                        IMPACT
                      </p>
                      <p className="mt-1 text-sm font-semibold text-foreground">
                        {path.outcome}
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Break chain */}
              <footer className="border-t border-border bg-panel-alt/40 px-5 py-4">
                <div className="flex items-center gap-2 text-success">
                  <Lightbulb className="size-4" />
                  <p className="font-mono text-[10px] font-bold tracking-wider">
                    BREAK THE CHAIN
                  </p>
                </div>
                <ol className="mt-2 list-decimal space-y-1 pl-5 text-xs leading-relaxed text-muted-foreground">
                  {path.break_chain.map((b) => (
                    <li key={b}>
                      <span className="text-foreground/90">{b}</span>
                    </li>
                  ))}
                </ol>
              </footer>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
