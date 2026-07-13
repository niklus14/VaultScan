"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  CheckCircle2,
  Loader2,
  Sparkles,
  Shield,
  RotateCcw,
  Play,
  AlertTriangle,
  Wrench,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  Terminal,
  Cloud,
  ListChecks,
  History,
  Info,
} from "lucide-react";
import { useLiveData, useScanStore } from "@/lib/scan-store";
import {
  planRemediation,
  dryRunRemediation,
  applyRemediation,
  rollbackRemediation,
  listRemediationJobs,
  type RemediateJob,
  type FixAction,
} from "@/lib/api";
import { cn } from "@/lib/utils";

const riskStyle: Record<string, string> = {
  safe: "bg-emerald-500/15 text-emerald-400 ring-1 ring-emerald-500/30",
  elevated: "bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30",
  dangerous: "bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/30",
};

const statusStyle: Record<string, string> = {
  planned: "bg-white/5 text-muted-foreground ring-1 ring-white/10",
  dry_run_ok: "bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/25",
  dry_run_fail: "bg-rose-500/10 text-rose-300 ring-1 ring-rose-500/25",
  applied: "bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30",
  failed: "bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/35",
  skipped: "bg-white/5 text-muted-foreground ring-1 ring-white/10",
  rolled_back: "bg-amber-500/15 text-amber-200 ring-1 ring-amber-500/30",
  rollback_failed: "bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/30",
};

const statusLabel: Record<string, string> = {
  planned: "Planned",
  dry_run_ok: "Dry-run OK",
  dry_run_fail: "Dry-run fail",
  applied: "Applied",
  failed: "Failed",
  skipped: "Skipped",
  rolled_back: "Restored",
  rollback_failed: "Rollback failed",
};

function shortError(err?: string | null) {
  if (!err) return "";
  return err.split("--- MANUAL CLI")[0].trim().split("\n")[0];
}

function ActionCard({
  action,
  defaultOpen,
}: {
  action: FixAction;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(!!defaultOpen || action.status === "failed");
  const [copiedLocal, setCopiedLocal] = useState(false);
  const cli =
    action.cli_commands && action.cli_commands.length
      ? action.cli_commands.join("\n")
      : action.cli_hint || "";
  const errLine = shortError(action.error);

  return (
    <article
      className={cn(
        "overflow-hidden rounded-xl border transition-colors",
        action.status === "failed"
          ? "border-rose-500/25 bg-rose-500/[0.04]"
          : action.status === "applied"
            ? "border-emerald-500/20 bg-emerald-500/[0.03]"
            : "border-border/80 bg-panel-alt/40",
      )}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-3 px-4 py-3.5 text-left hover:bg-white/[0.02]"
      >
        <span className="mt-0.5 text-muted-foreground">
          {open ? (
            <ChevronDown className="size-4" />
          ) : (
            <ChevronRight className="size-4" />
          )}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={cn(
                "rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
                riskStyle[action.risk] || riskStyle.elevated,
              )}
            >
              {action.risk}
            </span>
            <span className="rounded-md bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
              {action.rule_id}
            </span>
            <span
              className={cn(
                "rounded-full px-2 py-0.5 text-[10px] font-medium",
                statusStyle[action.status] || statusStyle.planned,
              )}
            >
              {statusLabel[action.status] || action.status}
            </span>
          </div>
          <p className="mt-1.5 text-sm font-medium leading-snug text-foreground">
            {action.summary}
          </p>
          <p className="mt-1 truncate font-mono text-[11px] text-muted-foreground">
            {action.resource}
          </p>
          {!open && errLine && (
            <p className="mt-2 line-clamp-1 text-xs text-rose-300/90">
              {errLine}
            </p>
          )}
        </div>
      </button>

      {open && (
        <div className="space-y-3 border-t border-border/60 px-4 py-3 pl-11">
          {action.ai_notes && (
            <div className="rounded-lg border border-accent-blue/20 bg-accent-blue/5 px-3 py-2.5">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-accent-blue/80">
                Assistant note
              </p>
              <p className="mt-1 text-xs leading-relaxed text-foreground/85">
                {action.ai_notes}
              </p>
            </div>
          )}
          {action.preview && (
            <p className="text-xs leading-relaxed text-muted-foreground">
              {action.preview}
            </p>
          )}
          {action.error && (
            <div className="rounded-lg border border-rose-500/25 bg-rose-500/10 px-3 py-2.5">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-rose-300">
                Error
              </p>
              <p className="mt-1 text-xs leading-relaxed text-rose-100/90">
                {action.error.split("--- MANUAL CLI")[0].trim()}
              </p>
            </div>
          )}
          {cli && (
            <div>
              <div className="mb-1.5 flex items-center justify-between gap-2">
                <span className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  <Terminal className="size-3" />
                  CLI
                </span>
                <button
                  type="button"
                  onClick={async (e) => {
                    e.stopPropagation();
                    try {
                      await navigator.clipboard.writeText(cli);
                      setCopiedLocal(true);
                      setTimeout(() => setCopiedLocal(false), 1600);
                    } catch {
                      /* ignore */
                    }
                  }}
                  className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-0.5 text-[10px] font-medium text-muted-foreground hover:bg-white/5 hover:text-foreground"
                >
                  {copiedLocal ? (
                    <Check className="size-3 text-emerald-400" />
                  ) : (
                    <Copy className="size-3" />
                  )}
                  {copiedLocal ? "Copied" : "Copy"}
                </button>
              </div>
              <pre className="max-h-36 overflow-auto rounded-lg border border-border/80 bg-[#0a0b0e] p-3 font-mono text-[11px] leading-relaxed text-emerald-400/90">
                {cli}
              </pre>
            </div>
          )}
        </div>
      )}
    </article>
  );
}

export function RemediationHubTab() {
  const { scanId, isLive, score, mode } = useLiveData();
  const launchScan = useScanStore((s) => s.launchScan);

  const [job, setJob] = useState<RemediateJob | null>(null);
  const [jobs, setJobs] = useState<RemediateJob[]>([]);
  const [onlySafe, setOnlySafe] = useState(false);
  const [useAi, setUseAi] = useState(true);
  const [phrase, setPhrase] = useState("APPLY");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [cliScript, setCliScript] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [cliOpen, setCliOpen] = useState(false);

  const refreshJobs = useCallback(async () => {
    try {
      const res = await listRemediationJobs();
      setJobs(res.jobs || []);
      if (!job && res.jobs?.[0]) setJob(res.jobs[0]);
    } catch {
      /* ignore */
    }
  }, [job]);

  useEffect(() => {
    void refreshJobs();
  }, [refreshJobs]);

  const plan = async (modePlan: "all_safe" | "all" | "selected") => {
    setBusy("plan");
    setError(null);
    setMessage(null);
    try {
      const res = await planRemediation({
        scan_id: scanId && scanId !== "SCAN-DEMO" ? scanId : undefined,
        mode: "all",
        use_ai: useAi,
      });
      setJob(res.job);
      const plannedCli = (res.job.actions || [])
        .flatMap((a) => a.cli_commands || (a.cli_hint ? [a.cli_hint] : []))
        .join("\n");
      if (plannedCli) {
        setCliScript(plannedCli);
        setCliOpen(false);
      }
      if (modePlan === "all_safe") setOnlySafe(true);
      else setOnlySafe(false);
      setPhrase("APPLY");
      setMessage(
        `Plan ready — ${res.counts.total} fixes · ${res.counts.auto} auto · ${res.counts.safe} safe` +
          (res.ai_used ? " · notes included" : "") +
          ". Review the list, then Apply.",
      );
      await refreshJobs();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Plan failed");
    } finally {
      setBusy(null);
    }
  };

  const dryRun = async () => {
    if (!job) return;
    setBusy("dry");
    setError(null);
    try {
      const res = await dryRunRemediation(job.job_id);
      setJob(res.job);
      setMessage("Dry-run finished — nothing was changed in AWS.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Dry-run failed");
    } finally {
      setBusy(null);
    }
  };

  const apply = async () => {
    if (!job) return;
    const actionable = (job.actions || []).filter(
      (a) => a.auto_applicable || (a.aws_calls && a.aws_calls.length),
    );
    const needsDanger =
      !onlySafe && actionable.some((a) => a.risk === "dangerous");
    const phraseOk = phrase.trim().toUpperCase() === "APPLY";
    if (needsDanger && !phraseOk) {
      setError(
        "Dangerous fixes need confirmation. Type APPLY in the box, then click Apply fixes.",
      );
      return;
    }
    setBusy("apply");
    setError(null);
    try {
      const res = await applyRemediation({
        job_id: job.job_id,
        confirm: true,
        confirm_phrase: phraseOk || needsDanger ? "APPLY" : undefined,
        only_safe: onlySafe,
        allow_write_with_scan_creds: true,
        rescan: true,
      });
      setJob(res.job);
      const script =
        res.cli_script ||
        res.job.cli_script ||
        (res.job.actions || [])
          .flatMap((a) => a.cli_commands || [])
          .join("\n");
      if (script) {
        setCliScript(script);
        setCliOpen(true);
      }
      const appliedN = (res.job.actions || []).filter(
        (a) => a.status === "applied",
      ).length;
      const failedActs = (res.job.actions || []).filter(
        (a) => a.status === "failed",
      );
      const firstFail = shortError(failedActs[0]?.error);
      if (appliedN === 0 || res.ok === false) {
        setError(
          [
            res.message?.split("[build=")[0]?.trim() || res.message,
            firstFail,
            script ? "Use the CLI script below if auto-apply could not finish." : null,
          ]
            .filter(Boolean)
            .join(" "),
        );
        setMessage(null);
      } else {
        setMessage(
          res.message ||
            `Applied ${appliedN} change(s)${failedActs.length ? `, ${failedActs.length} failed` : ""}. Re-scan uses live AWS.`,
        );
      }
      if (res.rescan && typeof res.rescan === "object" && "scan_id" in res.rescan) {
        useScanStore.setState({ scan: res.rescan as never });
      } else {
        try {
          await launchScan();
        } catch {
          /* ignore */
        }
      }
      await refreshJobs();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Apply failed");
    } finally {
      setBusy(null);
    }
  };

  const makeAsBefore = async () => {
    if (!job) return;
    if (phrase.trim().toUpperCase() !== "ROLLBACK") {
      setError("Type ROLLBACK to restore the previous configuration.");
      return;
    }
    setBusy("rollback");
    setError(null);
    try {
      const res = await rollbackRemediation({
        job_id: job.job_id,
        confirm: true,
        confirm_phrase: "ROLLBACK",
        allow_write_with_scan_creds: true,
        rescan: true,
      });
      setJob(res.job);
      setMessage(res.message || "Restored previous configuration.");
      if (res.rescan && "scan_id" in res.rescan) {
        useScanStore.setState({ scan: res.rescan as never });
      } else {
        try {
          await launchScan();
        } catch {
          /* ignore */
        }
      }
      setPhrase("");
      await refreshJobs();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Rollback failed");
    } finally {
      setBusy(null);
    }
  };

  const actions: FixAction[] = job?.actions || [];
  const counts = useMemo(() => {
    const applied = actions.filter((a) => a.status === "applied").length;
    const failed = actions.filter((a) => a.status === "failed").length;
    const skipped = actions.filter((a) => a.status === "skipped").length;
    const planned = actions.filter((a) => a.status === "planned").length;
    return { applied, failed, skipped, planned, total: actions.length };
  }, [actions]);

  const steps = [
    { n: 1, label: "Plan", done: !!job },
    { n: 2, label: "Review", done: !!job && actions.length > 0 },
    {
      n: 3,
      label: "Apply",
      done: counts.applied > 0,
    },
    { n: 4, label: "Undo", done: actions.some((a) => a.status === "rolled_back") },
  ];

  return (
    <div className="space-y-5">
      {/* Hero header */}
      <section className="relative overflow-hidden rounded-2xl border border-border bg-gradient-to-br from-panel via-panel to-[#0d1220] p-6 shadow-sm">
        <div className="pointer-events-none absolute -right-16 -top-16 size-48 rounded-full bg-accent-blue/10 blur-3xl" />
        <div className="relative flex flex-wrap items-start justify-between gap-4">
          <div className="max-w-2xl">
            <div className="flex items-center gap-2.5">
              <span className="flex size-9 items-center justify-center rounded-xl bg-accent-blue/15 ring-1 ring-accent-blue/25">
                <Wrench className="size-4 text-accent-blue" />
              </span>
              <div>
                <h2 className="text-base font-semibold tracking-tight text-foreground">
                  Fixing options
                </h2>
                <p className="text-xs text-muted-foreground">
                  Plan → apply real AWS fixes → re-scan · undo with Make as before
                </p>
              </div>
            </div>
            <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
              Build a fix plan from your latest scan, preview safely, then apply.
              Failed items include copy-paste AWS CLI. After apply, VaultScan
              re-scans so fixed findings drop off.
            </p>
          </div>

          <div className="flex flex-col items-end gap-2">
            <div className="rounded-xl border border-border/80 bg-background/50 px-4 py-3 text-right backdrop-blur">
              <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                Posture score
              </p>
              <p className="mt-0.5 text-2xl font-semibold tabular-nums text-foreground">
                {score ?? "—"}
              </p>
              {(job?.score_before != null || job?.score_after != null) && (
                <p className="mt-1 text-[11px] text-muted-foreground">
                  {job.score_before != null && (
                    <span>Before {job.score_before}</span>
                  )}
                  {job.score_after != null && (
                    <span className="text-emerald-400">
                      {" "}
                      → After {job.score_after}
                    </span>
                  )}
                </p>
              )}
            </div>
            <span
              className={cn(
                "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-medium",
                mode === "simulate"
                  ? "bg-emerald-500/10 text-emerald-300 ring-1 ring-emerald-500/25"
                  : "bg-accent-blue/10 text-accent-blue ring-1 ring-accent-blue/25",
              )}
            >
              <Cloud className="size-3" />
              {mode === "simulate" ? "Demo mode" : "Real AWS"}
            </span>
          </div>
        </div>

        {/* Pipeline */}
        <ol className="relative mt-6 flex flex-wrap gap-2">
          {steps.map((s, i) => (
            <li key={s.n} className="flex items-center gap-2">
              <span
                className={cn(
                  "inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-xs font-medium",
                  s.done
                    ? "bg-accent-blue/15 text-accent-blue ring-1 ring-accent-blue/30"
                    : "bg-white/5 text-muted-foreground ring-1 ring-white/10",
                )}
              >
                <span
                  className={cn(
                    "flex size-5 items-center justify-center rounded-full text-[10px] font-bold",
                    s.done ? "bg-accent-blue text-background" : "bg-white/10",
                  )}
                >
                  {s.done ? <Check className="size-3" /> : s.n}
                </span>
                {s.label}
              </span>
              {i < steps.length - 1 && (
                <span className="hidden text-muted-foreground/40 sm:inline">
                  →
                </span>
              )}
            </li>
          ))}
        </ol>
      </section>

      {/* Controls */}
      <section className="rounded-2xl border border-border bg-panel p-5">
        <div className="flex flex-wrap items-center gap-4">
          <label className="flex cursor-pointer items-center gap-2.5 text-sm text-foreground/90">
            <input
              type="checkbox"
              checked={onlySafe}
              onChange={(e) => setOnlySafe(e.target.checked)}
              className="size-3.5 rounded border-border accent-[var(--accent-blue)]"
            />
            <span>
              Only safe fixes
              <span className="ml-1.5 text-xs text-muted-foreground">
                (off = lab elevated/dangerous)
              </span>
            </span>
          </label>
          <label className="flex cursor-pointer items-center gap-2.5 text-sm text-foreground/90">
            <input
              type="checkbox"
              checked={useAi}
              onChange={(e) => setUseAi(e.target.checked)}
              className="size-3.5 rounded border-border accent-[var(--accent-blue)]"
            />
            Assistant notes on plan
          </label>
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          <button
            type="button"
            disabled={!!busy || !isLive}
            onClick={() => void plan("all")}
            className="inline-flex items-center gap-2 rounded-xl bg-accent-blue px-4 py-2.5 text-sm font-semibold text-background shadow-sm transition hover:brightness-110 disabled:opacity-40"
          >
            {busy === "plan" ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <ListChecks className="size-4" />
            )}
            Plan all fixes
          </button>
          <button
            type="button"
            disabled={!!busy || !isLive}
            onClick={() => void plan("all_safe")}
            className="inline-flex items-center gap-2 rounded-xl border border-border bg-background/40 px-4 py-2.5 text-sm font-medium text-foreground transition hover:bg-white/5 disabled:opacity-40"
          >
            <Sparkles className="size-4 text-accent-blue" />
            Plan safe only
          </button>
          <button
            type="button"
            disabled={!!busy || !job}
            onClick={() => void dryRun()}
            className="inline-flex items-center gap-2 rounded-xl border border-border px-4 py-2.5 text-sm font-medium text-muted-foreground transition hover:text-foreground disabled:opacity-40"
          >
            {busy === "dry" ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <Play className="size-4" />
            )}
            Dry-run
          </button>
          <button
            type="button"
            disabled={!!busy || !job}
            onClick={() => void apply()}
            className="inline-flex items-center gap-2 rounded-xl border border-emerald-500/40 bg-emerald-500/15 px-4 py-2.5 text-sm font-semibold text-emerald-300 transition hover:bg-emerald-500/25 disabled:opacity-40"
          >
            {busy === "apply" ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <Shield className="size-4" />
            )}
            Apply fixes
          </button>
          <button
            type="button"
            disabled={!!busy || !job?.rollback_available}
            onClick={() => void makeAsBefore()}
            className="inline-flex items-center gap-2 rounded-xl border border-amber-500/35 bg-amber-500/10 px-4 py-2.5 text-sm font-semibold text-amber-200 transition hover:bg-amber-500/20 disabled:opacity-40"
          >
            {busy === "rollback" ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <RotateCcw className="size-4" />
            )}
            Make as before
          </button>
        </div>

        <div className="mt-4 flex flex-col gap-2 sm:flex-row sm:items-center">
          <label className="shrink-0 text-xs font-medium text-muted-foreground">
            Confirm phrase
          </label>
          <input
            value={phrase}
            onChange={(e) => setPhrase(e.target.value)}
            placeholder="APPLY for dangerous fixes · ROLLBACK to undo"
            className="w-full max-w-md rounded-xl border border-border bg-background px-3.5 py-2.5 text-sm text-foreground outline-none ring-accent-blue/40 placeholder:text-muted-foreground/60 focus:ring-2"
          />
          <p className="text-xs text-muted-foreground">
            Dangerous fixes need <span className="text-foreground">APPLY</span>.
            Undo needs <span className="text-foreground">ROLLBACK</span>.
          </p>
        </div>

        {error && (
          <div className="mt-4 flex gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3">
            <AlertTriangle className="mt-0.5 size-4 shrink-0 text-rose-300" />
            <p className="text-sm leading-relaxed text-rose-100/95">{error}</p>
          </div>
        )}
        {message && (
          <div className="mt-4 flex gap-3 rounded-xl border border-emerald-500/25 bg-emerald-500/10 px-4 py-3">
            <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-emerald-300" />
            <p className="text-sm leading-relaxed text-emerald-100/95">
              {message}
            </p>
          </div>
        )}
        {!isLive && (
          <div className="mt-4 flex gap-3 rounded-xl border border-amber-500/25 bg-amber-500/10 px-4 py-3">
            <Info className="mt-0.5 size-4 shrink-0 text-amber-200" />
            <p className="text-sm text-amber-100/90">
              Run a scan first, then build a fix plan here.
            </p>
          </div>
        )}
      </section>

      <div className="grid gap-5 lg:grid-cols-12">
        {/* Main list */}
        <section className="rounded-2xl border border-border bg-panel lg:col-span-8">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/70 px-5 py-4">
            <div>
              <h3 className="text-sm font-semibold text-foreground">
                {job ? "Fix plan" : "No plan yet"}
              </h3>
              {job && (
                <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                  {job.job_id}
                </p>
              )}
            </div>
            {job && (
              <div className="flex flex-wrap gap-2">
                <span className="rounded-full bg-emerald-500/10 px-2.5 py-1 text-[11px] font-medium text-emerald-300 ring-1 ring-emerald-500/20">
                  {counts.applied} applied
                </span>
                <span className="rounded-full bg-rose-500/10 px-2.5 py-1 text-[11px] font-medium text-rose-300 ring-1 ring-rose-500/20">
                  {counts.failed} failed
                </span>
                <span className="rounded-full bg-white/5 px-2.5 py-1 text-[11px] font-medium text-muted-foreground ring-1 ring-white/10">
                  {counts.total} total
                </span>
              </div>
            )}
          </div>

          <div className="max-h-[560px] space-y-2.5 overflow-y-auto p-4">
            {!job || actions.length === 0 ? (
              <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
                <div className="flex size-12 items-center justify-center rounded-2xl bg-white/5 ring-1 ring-white/10">
                  <ListChecks className="size-5 text-muted-foreground" />
                </div>
                <p className="mt-4 text-sm font-medium text-foreground">
                  No fixes listed
                </p>
                <p className="mt-1 max-w-xs text-xs leading-relaxed text-muted-foreground">
                  Click <strong className="text-foreground">Plan all fixes</strong>{" "}
                  after a scan to generate this list.
                </p>
              </div>
            ) : (
              actions.map((a) => (
                <ActionCard
                  key={a.action_id}
                  action={a}
                  defaultOpen={a.status === "failed"}
                />
              ))
            )}
          </div>

          {cliScript && (
            <div className="border-t border-border/70 p-4">
              <button
                type="button"
                onClick={() => setCliOpen((v) => !v)}
                className="flex w-full items-center justify-between gap-3 rounded-xl border border-amber-500/25 bg-amber-500/[0.06] px-4 py-3 text-left transition hover:bg-amber-500/10"
              >
                <span className="flex items-center gap-2.5">
                  <Terminal className="size-4 text-amber-200" />
                  <span>
                    <span className="block text-sm font-semibold text-amber-100">
                      Manual CLI script
                    </span>
                    <span className="block text-xs text-muted-foreground">
                      Paste in a terminal with lab-account credentials
                    </span>
                  </span>
                </span>
                {cliOpen ? (
                  <ChevronDown className="size-4 text-muted-foreground" />
                ) : (
                  <ChevronRight className="size-4 text-muted-foreground" />
                )}
              </button>
              {cliOpen && (
                <div className="mt-3">
                  <div className="mb-2 flex justify-end">
                    <button
                      type="button"
                      onClick={async () => {
                        try {
                          await navigator.clipboard.writeText(cliScript);
                          setCopied(true);
                          setTimeout(() => setCopied(false), 2000);
                        } catch {
                          /* ignore */
                        }
                      }}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/30 bg-amber-500/15 px-3 py-1.5 text-xs font-semibold text-amber-100 hover:bg-amber-500/25"
                    >
                      {copied ? (
                        <Check className="size-3.5" />
                      ) : (
                        <Copy className="size-3.5" />
                      )}
                      {copied ? "Copied" : "Copy all"}
                    </button>
                  </div>
                  <pre className="max-h-72 overflow-auto rounded-xl border border-border bg-[#0a0b0e] p-4 font-mono text-[11px] leading-relaxed text-foreground/85">
                    {cliScript}
                  </pre>
                </div>
              )}
            </div>
          )}
        </section>

        {/* Side rail */}
        <aside className="space-y-4 lg:col-span-4">
          <div className="rounded-2xl border border-border bg-panel p-5">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground">
              <Info className="size-4 text-accent-blue" />
              How it works
            </h3>
            <ol className="mt-4 space-y-3">
              {[
                "Plan maps each finding to a safe automated fix",
                "Dry-run previews without changing AWS",
                "Apply runs allowlisted writes (type APPLY if dangerous)",
                "Re-scan proves posture improved",
                "Make as before restores snapshots from this job",
              ].map((t, i) => (
                <li key={t} className="flex gap-3 text-sm leading-snug text-muted-foreground">
                  <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-white/5 text-[11px] font-bold text-foreground/80 ring-1 ring-white/10">
                    {i + 1}
                  </span>
                  <span>{t}</span>
                </li>
              ))}
            </ol>
          </div>

          <div className="rounded-2xl border border-border bg-panel p-5">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-foreground">
              <History className="size-4 text-muted-foreground" />
              Recent jobs
            </h3>
            <ul className="mt-3 max-h-56 space-y-1.5 overflow-y-auto">
              {jobs.length === 0 && (
                <li className="py-6 text-center text-xs text-muted-foreground">
                  No jobs yet
                </li>
              )}
              {jobs.slice(0, 8).map((j) => (
                <li key={j.job_id}>
                  <button
                    type="button"
                    onClick={() => setJob(j)}
                    className={cn(
                      "flex w-full items-center justify-between gap-2 rounded-xl px-3 py-2.5 text-left text-xs transition",
                      job?.job_id === j.job_id
                        ? "bg-accent-blue/15 text-accent-blue ring-1 ring-accent-blue/30"
                        : "text-muted-foreground hover:bg-white/5 hover:text-foreground",
                    )}
                  >
                    <span className="font-mono">{j.job_id}</span>
                    <span className="capitalize opacity-80">
                      {j.status}
                      {j.rollback_available ? " · undo" : ""}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </div>

          {mode !== "simulate" && (
            <div className="rounded-2xl border border-border/80 bg-panel-alt/50 p-4">
              <p className="text-xs leading-relaxed text-muted-foreground">
                <strong className="text-foreground">Real AWS:</strong> Apply
                uses your Access Key + Secret to AssumeRole into the Settings
                Role ARN (same account as the scan). Keep your user on that
                role&apos;s trust policy — not <code className="text-foreground/80">*</code>.
              </p>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
