"use client";

import { useMemo, useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  Copy,
  Check,
  Search,
  ShieldAlert,
  Sparkles,
  Loader2,
} from "lucide-react";
import { useLiveData, useScanStore } from "@/lib/scan-store";
import type { Severity } from "@/components/cspm/data";
import {
  planRemediation,
  applyRemediation,
  type RemediateJob,
} from "@/lib/api";
import { cn } from "@/lib/utils";

const severityStyles: Record<Severity, string> = {
  CRITICAL: "border-danger/40 bg-danger/10 text-danger",
  HIGH: "border-warning/40 bg-warning/10 text-warning",
  MEDIUM: "border-accent-blue/40 bg-accent-blue/10 text-accent-blue",
  LOW: "border-border-strong bg-white/[0.03] text-muted-foreground",
};

const SEV_FILTERS: Array<"ALL" | Severity> = [
  "ALL",
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
];

export function FindingsTab() {
  const { vulnerabilities, isLive, compliance, scanId, mode } = useLiveData();
  const launchScan = useScanStore((s) => s.launchScan);
  const [sev, setSev] = useState<"ALL" | Severity>("ALL");
  const [service, setService] = useState<string>("ALL");
  const [framework, setFramework] = useState<string>("ALL");
  const [q, setQ] = useState("");
  const [openId, setOpenId] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [fixBusy, setFixBusy] = useState<string | null>(null);
  const [fixMsg, setFixMsg] = useState<string | null>(null);

  const fixOne = async (findingId: string) => {
    setFixBusy(findingId);
    setFixMsg(null);
    try {
      const planned = await planRemediation({
        scan_id: scanId && scanId !== "SCAN-DEMO" ? scanId : undefined,
        finding_ids: [findingId],
        mode: "selected",
        use_ai: true,
      });
      const job: RemediateJob = planned.job;
      const res = await applyRemediation({
        job_id: job.job_id,
        confirm: true,
        only_safe: false,
        confirm_phrase: "APPLY",
        allow_write_with_scan_creds: true,
        rescan: true,
      });
      const appliedN = (res.job.actions || []).filter(
        (a) => a.status === "applied",
      ).length;
      if (res.rescan && typeof res.rescan === "object" && "scan_id" in res.rescan) {
        useScanStore.setState({ scan: res.rescan as never });
      } else {
        await launchScan().catch(() => undefined);
      }
      setFixMsg(
        appliedN > 0
          ? "Fix applied and scan refreshed. Open Fixing options to undo with Please make it as before."
          : "No auto-apply path for this finding — see Fixing options or use the CLI hint.",
      );
    } catch (e) {
      setFixMsg(e instanceof Error ? e.message : "Fix failed");
    } finally {
      setFixBusy(null);
    }
  };

  const services = useMemo(() => {
    const s = new Set(vulnerabilities.map((v) => v.service));
    return ["ALL", ...Array.from(s).sort()];
  }, [vulnerabilities]);

  const frameworks = useMemo(() => {
    const s = new Set<string>();
    for (const v of vulnerabilities) {
      for (const c of v.compliance || []) {
        if (c.includes("CIS")) s.add("CIS");
        if (c.includes("NIST")) s.add("NIST");
        if (c.includes("GDPR")) s.add("GDPR");
        if (c.includes("HIPAA")) s.add("HIPAA");
        if (c.includes("SOC")) s.add("SOC2");
      }
    }
    return ["ALL", ...Array.from(s).sort()];
  }, [vulnerabilities]);

  const filtered = useMemo(() => {
    return vulnerabilities.filter((v) => {
      if (sev !== "ALL" && v.severity !== sev) return false;
      if (service !== "ALL" && v.service !== service) return false;
      if (framework !== "ALL") {
        const tags = (v.compliance || []).join(" ");
        if (!tags.includes(framework === "SOC2" ? "SOC" : framework)) {
          return false;
        }
      }
      if (q.trim()) {
        const hay = `${v.id} ${v.title || ""} ${v.description} ${v.service}`.toLowerCase();
        if (!hay.includes(q.trim().toLowerCase())) return false;
      }
      return true;
    });
  }, [vulnerabilities, sev, service, framework, q]);

  const criticalCount = vulnerabilities.filter(
    (v) => v.severity === "CRITICAL",
  ).length;

  const copyFix = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      /* ignore */
    }
  };

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-panel p-3">
        <div className="relative min-w-[180px] flex-1">
          <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search resource, title…"
            className="w-full rounded-md border border-border bg-background py-2 pl-8 pr-3 font-mono text-xs text-foreground outline-none focus:border-accent-blue/50"
          />
        </div>
        <select
          value={sev}
          onChange={(e) => setSev(e.target.value as "ALL" | Severity)}
          className="rounded-md border border-border bg-background px-2 py-2 font-mono text-[11px] text-foreground"
        >
          {SEV_FILTERS.map((s) => (
            <option key={s} value={s}>
              {s === "ALL" ? "All severity" : s}
            </option>
          ))}
        </select>
        <select
          value={service}
          onChange={(e) => setService(e.target.value)}
          className="rounded-md border border-border bg-background px-2 py-2 font-mono text-[11px] text-foreground"
        >
          {services.map((s) => (
            <option key={s} value={s}>
              {s === "ALL" ? "All services" : s}
            </option>
          ))}
        </select>
        <select
          value={framework}
          onChange={(e) => setFramework(e.target.value)}
          className="rounded-md border border-border bg-background px-2 py-2 font-mono text-[11px] text-foreground"
        >
          {frameworks.map((f) => (
            <option key={f} value={f}>
              {f === "ALL" ? "All frameworks" : f}
            </option>
          ))}
        </select>
        <span className="ml-auto font-mono text-[11px] text-muted-foreground">
          {filtered.length}/{vulnerabilities.length} ·{" "}
          <span className="font-bold text-danger">{criticalCount} CRIT</span>
          {!isLive && " · MOCK"}
        </span>
      </div>

      {fixMsg && (
        <p className="rounded-md border border-border bg-panel px-3 py-2 font-mono text-[11px] text-muted-foreground">
          {fixMsg}
        </p>
      )}

      {/* Compliance quick strip */}
      {compliance.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {compliance.map((c) => (
            <div
              key={c.name}
              className={cn(
                "rounded-md border px-3 py-1.5 font-mono text-[10px]",
                c.status === "PASSING"
                  ? "border-success/30 bg-success/5 text-success"
                  : "border-danger/30 bg-danger/5 text-danger",
              )}
            >
              <span className="font-bold">{c.name.split(" ")[0]}</span>{" "}
              {c.passed}/{c.total} · {c.status}
            </div>
          ))}
        </div>
      )}

      <div className="rounded-lg border border-border bg-panel">
        <div className="flex items-center gap-2 border-b border-border px-5 py-3">
          <ShieldAlert className="size-4 text-accent-blue" />
          <h3 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
            FINDINGS WORKSPACE
          </h3>
        </div>

        {filtered.length === 0 ? (
          <div className="px-5 py-16 text-center font-mono text-xs text-muted-foreground">
            {vulnerabilities.length === 0
              ? "No findings yet — launch a scan from the sidebar."
              : "No findings match these filters."}
          </div>
        ) : (
          <ul className="divide-y divide-border/60">
            {filtered.map((v, i) => {
              const key = `${v.id}-${v.rule_id || i}`;
              const open = openId === key;
              return (
                <li key={key} className="hover:bg-white/[0.015]">
                  <button
                    type="button"
                    onClick={() => setOpenId(open ? null : key)}
                    className="flex w-full items-start gap-3 px-5 py-3.5 text-left"
                  >
                    {open ? (
                      <ChevronDown className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                    )}
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={cn(
                            "rounded-sm border px-1.5 py-0.5 font-mono text-[10px] font-bold tracking-wider",
                            severityStyles[v.severity as Severity],
                          )}
                        >
                          {v.severity}
                        </span>
                        <span className="rounded-sm border border-border px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                          {v.service}
                        </span>
                        {v.rule_id && (
                          <span className="font-mono text-[10px] text-muted-foreground/70">
                            {v.rule_id}
                          </span>
                        )}
                      </div>
                      <p className="mt-1.5 text-sm font-medium text-foreground">
                        {v.title || v.description}
                      </p>
                      <p className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
                        {v.id}
                      </p>
                    </div>
                  </button>

                  {open && (
                    <div className="space-y-3 border-t border-border/40 bg-panel-alt/40 px-5 py-4 pl-12">
                      <div>
                        <p className="font-mono text-[10px] font-bold tracking-wider text-muted-foreground">
                          WHAT WE FOUND
                        </p>
                        <p className="mt-1 text-xs leading-relaxed text-foreground/90">
                          {v.description}
                        </p>
                      </div>
                      {(v.compliance?.length ?? 0) > 0 && (
                        <div>
                          <p className="font-mono text-[10px] font-bold tracking-wider text-muted-foreground">
                            COMPLIANCE
                          </p>
                          <div className="mt-1.5 flex flex-wrap gap-1.5">
                            {v.compliance!.map((c) => (
                              <span
                                key={c}
                                className="rounded-sm border border-accent-blue/30 bg-accent-blue/10 px-2 py-0.5 font-mono text-[10px] text-accent-blue"
                              >
                                {c}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      {v.remediation && (
                        <div>
                          <div className="flex items-center justify-between gap-2">
                            <p className="font-mono text-[10px] font-bold tracking-wider text-muted-foreground">
                              HOW TO FIX
                            </p>
                            <div className="flex items-center gap-1.5">
                              <button
                                type="button"
                                disabled={!isLive || fixBusy === v.id}
                                onClick={() => void fixOne(v.id)}
                                className="flex items-center gap-1 rounded border border-accent-blue/40 bg-accent-blue/10 px-2 py-1 font-mono text-[10px] font-bold text-accent-blue hover:bg-accent-blue/20 disabled:opacity-40"
                              >
                                {fixBusy === v.id ? (
                                  <Loader2 className="size-3 animate-spin" />
                                ) : (
                                  <Sparkles className="size-3" />
                                )}
                                FIX WITH AI
                              </button>
                              <button
                                type="button"
                                onClick={() =>
                                  void copyFix(v.remediation || "", key)
                                }
                                className="flex items-center gap-1 rounded border border-border px-2 py-1 font-mono text-[10px] text-muted-foreground hover:text-foreground"
                              >
                                {copied === key ? (
                                  <Check className="size-3 text-success" />
                                ) : (
                                  <Copy className="size-3" />
                                )}
                                {copied === key ? "COPIED" : "COPY"}
                              </button>
                            </div>
                          </div>
                          <pre className="mt-1.5 overflow-x-auto rounded-md border border-border bg-background p-3 font-mono text-[11px] leading-relaxed text-success/90">
                            {v.remediation}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}
