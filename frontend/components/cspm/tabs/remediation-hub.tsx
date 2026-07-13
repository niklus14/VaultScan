"use client";

import { useCallback, useEffect, useState } from "react";
import {
  CheckCircle2,
  Circle,
  Loader2,
  Sparkles,
  Shield,
  RotateCcw,
  Play,
  AlertTriangle,
  Wrench,
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
  safe: "border-success/40 bg-success/10 text-success",
  elevated: "border-warning/40 bg-warning/10 text-warning",
  dangerous: "border-danger/40 bg-danger/10 text-danger",
};

const statusLabel: Record<string, string> = {
  planned: "PLANNED",
  dry_run_ok: "DRY-RUN OK",
  dry_run_fail: "DRY-RUN FAIL",
  applied: "APPLIED",
  failed: "FAILED",
  skipped: "SKIPPED",
  rolled_back: "RESTORED",
  rollback_failed: "ROLLBACK FAIL",
};

export function RemediationHubTab() {
  const { scanId, isLive, score, mode } = useLiveData();
  const launchScan = useScanStore((s) => s.launchScan);

  const [job, setJob] = useState<RemediateJob | null>(null);
  const [jobs, setJobs] = useState<RemediateJob[]>([]);
  const [onlySafe, setOnlySafe] = useState(false);
  const [useAi, setUseAi] = useState(true);
  const [allowWrite, setAllowWrite] = useState(false);
  const [phrase, setPhrase] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

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
        mode: modePlan === "all_safe" ? "all_safe" : "all",
        use_ai: useAi,
      });
      setJob(res.job);
      setMessage(
        `Plan ready: ${res.counts.total} actions · ${res.counts.safe} safe · ${res.counts.auto} auto` +
          (res.ai_used ? " · AI notes added" : ""),
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
      setMessage("Dry-run complete — review previews before apply.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Dry-run failed");
    } finally {
      setBusy(null);
    }
  };

  const apply = async () => {
    if (!job) return;
    const needsDanger =
      !onlySafe &&
      (job.actions || []).some(
        (a) => a.risk === "dangerous" && a.auto_applicable,
      );
    if (needsDanger && phrase.trim().toUpperCase() !== "APPLY") {
      setError(
        'Dangerous fixes included — type APPLY in the box below, then click APPLY FIXES again.',
      );
      return;
    }
    setBusy("apply");
    setError(null);
    try {
      const res = await applyRemediation({
        job_id: job.job_id,
        confirm: true,
        confirm_phrase: needsDanger ? "APPLY" : phrase.trim() || undefined,
        only_safe: onlySafe,
        // Demo always writes to local fixed-set; live AWS needs checkbox
        allow_write_with_scan_creds: true,
        rescan: true,
      });
      setJob(res.job);
      const appliedN = (res.job.actions || []).filter(
        (a) => a.status === "applied",
      ).length;
      const failedN = (res.job.actions || []).filter(
        (a) => a.status === "failed",
      ).length;
      const skippedN = (res.job.actions || []).filter(
        (a) => a.status === "skipped",
      ).length;
      if (appliedN === 0) {
        setError(
          `No fixes were applied (${skippedN} skipped, ${failedN} failed). ` +
            "Uncheck “Only safe fixes”, use PLAN ALL AUTO-FIXES, or type APPLY for dangerous items. " +
            "In live AWS, the role must allow the write API.",
        );
      } else {
        setMessage(
          `Applied ${appliedN} fix(es)${failedN ? `, ${failedN} failed` : ""}${skippedN ? `, ${skippedN} skipped` : ""}. ` +
            "Re-scan completed — fixed misconfigs should be gone. Use Make as before to undo.",
        );
      }
      if (res.rescan && typeof res.rescan === "object" && "scan_id" in res.rescan) {
        useScanStore.setState({
          scan: res.rescan as never,
        });
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
      setError('Type ROLLBACK to restore everything as before this job.');
      return;
    }
    setBusy("rollback");
    setError(null);
    try {
      const res = await rollbackRemediation({
        job_id: job.job_id,
        confirm: true,
        confirm_phrase: "ROLLBACK",
        allow_write_with_scan_creds: allowWrite || mode === "simulate",
        rescan: true,
      });
      setJob(res.job);
      setMessage(
        res.message || "Restored previous configuration (make as before).",
      );
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
  const applied = actions.filter((a) => a.status === "applied").length;
  const failed = actions.filter((a) => a.status === "failed").length;

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-border bg-panel p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Wrench className="size-4 text-accent-blue" />
              <h3 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
                FIXING OPTIONS
              </h3>
            </div>
            <p className="mt-2 max-w-2xl text-xs leading-relaxed text-muted-foreground">
              Plan automated fixes from the latest scan, dry-run, then apply.
              After apply, a re-scan runs automatically — fixed items should
              disappear. Use{" "}
              <strong className="text-foreground">Make as before</strong> to
              undo this job and restore the previous configuration.
            </p>
          </div>
          <div className="font-mono text-[11px] text-muted-foreground">
            Posture now:{" "}
            <span className="font-bold text-foreground">{score ?? "—"}</span>
            {job?.score_before != null && (
              <>
                {" "}
                · before job:{" "}
                <span className="text-foreground">{job.score_before}</span>
              </>
            )}
            {job?.score_after != null && (
              <>
                {" "}
                · after:{" "}
                <span className="text-success">{job.score_after}</span>
              </>
            )}
          </div>
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
            <input
              type="checkbox"
              checked={onlySafe}
              onChange={(e) => setOnlySafe(e.target.checked)}
            />
            Only safe fixes on apply
          </label>
          <label className="flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
            <input
              type="checkbox"
              checked={useAi}
              onChange={(e) => setUseAi(e.target.checked)}
            />
            Cloud Assistant notes
          </label>
          {mode !== "simulate" && (
            <label className="flex items-center gap-2 font-mono text-[11px] text-warning">
              <input
                type="checkbox"
                checked={allowWrite}
                onChange={(e) => setAllowWrite(e.target.checked)}
              />
              Allow write with current scan credentials
            </label>
          )}
          {mode === "simulate" && (
            <span className="rounded border border-success/30 bg-success/10 px-2 py-1 font-mono text-[10px] text-success">
              DEMO MODE — apply/rollback are simulated
            </span>
          )}
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          <button
            type="button"
            disabled={!!busy || !isLive}
            onClick={() => void plan("all_safe")}
            className="flex items-center gap-2 rounded-md border border-accent-blue/40 bg-accent-blue/15 px-3 py-2 font-mono text-[11px] font-bold text-accent-blue hover:bg-accent-blue/25 disabled:opacity-40"
          >
            {busy === "plan" ? (
              <Loader2 className="size-3.5 animate-spin" />
            ) : (
              <Sparkles className="size-3.5" />
            )}
            PLAN SAFE ONLY
          </button>
          <button
            type="button"
            disabled={!!busy || !isLive}
            onClick={() => void plan("all")}
            className="flex items-center gap-2 rounded-md border border-border px-3 py-2 font-mono text-[11px] font-bold text-foreground hover:bg-panel-alt disabled:opacity-40"
          >
            PLAN ALL AUTO-FIXES
          </button>
          <span className="w-full font-mono text-[10px] text-muted-foreground sm:w-auto">
            Tip: PLAN ALL → type APPLY → APPLY FIXES → re-scan should clear fixed items.
          </span>
          <button
            type="button"
            disabled={!!busy || !job}
            onClick={() => void dryRun()}
            className="flex items-center gap-2 rounded-md border border-border px-3 py-2 font-mono text-[11px] font-bold text-muted-foreground hover:text-foreground disabled:opacity-40"
          >
            {busy === "dry" ? (
              <Loader2 className="size-3.5 animate-spin" />
            ) : (
              <Play className="size-3.5" />
            )}
            DRY-RUN
          </button>
          <button
            type="button"
            disabled={!!busy || !job}
            onClick={() => void apply()}
            className="flex items-center gap-2 rounded-md bg-accent-blue px-3 py-2 font-mono text-[11px] font-bold text-background disabled:opacity-40"
          >
            {busy === "apply" ? (
              <Loader2 className="size-3.5 animate-spin" />
            ) : (
              <Shield className="size-3.5" />
            )}
            APPLY FIXES
          </button>
          <button
            type="button"
            disabled={!!busy || !job?.rollback_available}
            onClick={() => void makeAsBefore()}
            className="flex items-center gap-2 rounded-md border border-warning/40 bg-warning/10 px-3 py-2 font-mono text-[11px] font-bold text-warning hover:bg-warning/20 disabled:opacity-40"
          >
            {busy === "rollback" ? (
              <Loader2 className="size-3.5 animate-spin" />
            ) : (
              <RotateCcw className="size-3.5" />
            )}
            MAKE AS BEFORE
          </button>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2">
          <input
            value={phrase}
            onChange={(e) => setPhrase(e.target.value)}
            placeholder='Type APPLY (dangerous) or ROLLBACK (make as before)'
            className="min-w-[280px] flex-1 rounded-md border border-border bg-background px-3 py-2 font-mono text-[11px] text-foreground outline-none focus:border-accent-blue/50"
          />
        </div>

        {error && (
          <p className="mt-3 flex items-start gap-2 font-mono text-[11px] text-danger">
            <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
            {error}
          </p>
        )}
        {message && (
          <p className="mt-3 font-mono text-[11px] text-success">{message}</p>
        )}
        {!isLive && (
          <p className="mt-3 font-mono text-[11px] text-warning">
            Launch a real or demo scan first to build a fix plan.
          </p>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="rounded-lg border border-border bg-panel p-4 lg:col-span-2">
          <div className="mb-3 flex items-center justify-between">
            <h4 className="font-mono text-[11px] font-bold tracking-wider text-foreground">
              {job ? `JOB ${job.job_id}` : "NO JOB YET"}
            </h4>
            {job && (
              <span className="font-mono text-[10px] text-muted-foreground">
                {applied} applied · {failed} failed · {actions.length} total
              </span>
            )}
          </div>
          {!job || actions.length === 0 ? (
            <p className="py-10 text-center font-mono text-xs text-muted-foreground">
              Generate a plan to see fix actions here.
            </p>
          ) : (
            <ul className="max-h-[480px] space-y-2 overflow-y-auto">
              {actions.map((a) => (
                <li
                  key={a.action_id}
                  className="rounded-md border border-border bg-panel-alt/50 px-3 py-2.5"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={cn(
                        "rounded-sm border px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase",
                        riskStyle[a.risk] || riskStyle.elevated,
                      )}
                    >
                      {a.risk}
                    </span>
                    <span className="font-mono text-[10px] text-muted-foreground">
                      {a.rule_id}
                    </span>
                    <span className="ml-auto font-mono text-[10px] text-muted-foreground">
                      {statusLabel[a.status] || a.status}
                    </span>
                    {a.auto_applicable ? (
                      <CheckCircle2 className="size-3.5 text-success" />
                    ) : (
                      <Circle className="size-3.5 text-muted-foreground" />
                    )}
                  </div>
                  <p className="mt-1 text-xs font-medium text-foreground">
                    {a.summary}
                  </p>
                  <p className="mt-0.5 font-mono text-[10px] text-muted-foreground">
                    {a.resource}
                  </p>
                  {a.ai_notes && (
                    <p className="mt-1.5 text-[11px] leading-relaxed text-accent-blue/90">
                      AI: {a.ai_notes}
                    </p>
                  )}
                  {a.preview && (
                    <p className="mt-1 font-mono text-[10px] text-muted-foreground">
                      {a.preview}
                    </p>
                  )}
                  {a.error && (
                    <p className="mt-1 font-mono text-[10px] text-danger">
                      {a.error}
                    </p>
                  )}
                  {a.cli_hint && !a.auto_applicable && (
                    <pre className="mt-1.5 overflow-x-auto rounded border border-border bg-background p-2 font-mono text-[10px] text-success/80">
                      {a.cli_hint}
                    </pre>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="space-y-4">
          <div className="rounded-lg border border-border bg-panel p-4">
            <h4 className="font-mono text-[11px] font-bold tracking-wider text-foreground">
              HOW IT WORKS
            </h4>
            <ol className="mt-3 space-y-2 font-mono text-[10px] leading-relaxed text-muted-foreground">
              <li>1. Plan — registry maps each finding to a fix (+ optional AI notes)</li>
              <li>2. Dry-run — preview without changing AWS</li>
              <li>3. Apply — executes allowlisted fixes (safe by default)</li>
              <li>4. Re-scan — proves posture improved</li>
              <li>
                5. <span className="text-warning">Make as before</span> — restores
                snapshots from this job
              </li>
            </ol>
          </div>
          <div className="rounded-lg border border-border bg-panel p-4">
            <h4 className="font-mono text-[11px] font-bold tracking-wider text-foreground">
              RECENT JOBS
            </h4>
            <ul className="mt-2 max-h-48 space-y-1 overflow-y-auto">
              {jobs.length === 0 && (
                <li className="font-mono text-[10px] text-muted-foreground">
                  No jobs yet
                </li>
              )}
              {jobs.slice(0, 8).map((j) => (
                <li key={j.job_id}>
                  <button
                    type="button"
                    onClick={() => setJob(j)}
                    className={cn(
                      "w-full rounded border px-2 py-1.5 text-left font-mono text-[10px]",
                      job?.job_id === j.job_id
                        ? "border-accent-blue/40 bg-accent-blue/10 text-accent-blue"
                        : "border-border text-muted-foreground hover:text-foreground",
                    )}
                  >
                    {j.job_id} · {j.status}
                    {j.rollback_available ? " · undoable" : ""}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
