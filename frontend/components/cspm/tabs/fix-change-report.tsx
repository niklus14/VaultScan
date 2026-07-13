"use client";

import { useState } from "react";
import {
  FileText,
  Loader2,
  Sparkles,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  ArrowRight,
  ShieldAlert,
  Terminal,
} from "lucide-react";
import type { FixChangeEntry, FixChangeReport } from "@/lib/api";
import { cn } from "@/lib/utils";

const statusTone: Record<string, string> = {
  applied: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  failed: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
  skipped: "bg-white/5 text-muted-foreground ring-white/10",
  rolled_back: "bg-amber-500/15 text-amber-200 ring-amber-500/30",
  planned: "bg-white/5 text-muted-foreground ring-white/10",
};

function ChangeBlock({ entry }: { entry: FixChangeEntry }) {
  const [open, setOpen] = useState(entry.status === "failed" || entry.status === "applied");
  const [copied, setCopied] = useState(false);
  const cli = entry.cli_text || (entry.cli_commands || []).join("\n");

  return (
    <article className="overflow-hidden rounded-xl border border-border/80 bg-panel-alt/30">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-3 px-4 py-3.5 text-left hover:bg-white/[0.02]"
      >
        <span className="mt-0.5 text-muted-foreground">
          {open ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-md bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
              {entry.rule_id}
            </span>
            <span
              className={cn(
                "rounded-full px-2 py-0.5 text-[10px] font-medium ring-1",
                statusTone[entry.status || "planned"] || statusTone.planned,
              )}
            >
              {entry.status}
            </span>
            {entry.risk && (
              <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
                {entry.risk}
              </span>
            )}
          </div>
          <p className="mt-1.5 text-sm font-medium text-foreground">
            {entry.title || entry.summary}
          </p>
          <p className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
            {entry.resource}
          </p>
        </div>
      </button>

      {open && (
        <div className="space-y-3 border-t border-border/60 px-4 py-4 pl-11">
          {(entry.ai_story || entry.ai_notes) && (
            <div className="rounded-lg border border-accent-blue/20 bg-accent-blue/5 px-3 py-2.5">
              <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-accent-blue/90">
                <Sparkles className="size-3" />
                Cloud Assistant
              </p>
              <p className="mt-1.5 text-xs leading-relaxed text-foreground/90">
                {entry.ai_story || entry.ai_notes}
              </p>
            </div>
          )}

          <div className="grid gap-3 md:grid-cols-3">
            <div className="rounded-lg border border-border/70 bg-background/40 p-3">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-rose-300/90">
                Before
              </p>
              <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-muted-foreground">
                {entry.before || "—"}
              </pre>
            </div>
            <div className="rounded-lg border border-accent-blue/25 bg-accent-blue/5 p-3">
              <p className="flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-accent-blue">
                What changed
                <ArrowRight className="size-3" />
              </p>
              <p className="mt-2 text-xs leading-relaxed text-foreground/90">
                {entry.what_changed || "—"}
              </p>
              {entry.error && (
                <p className="mt-2 text-xs leading-relaxed text-rose-300/90">
                  {entry.error}
                </p>
              )}
            </div>
            <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-emerald-300/90">
                After
              </p>
              <p className="mt-2 text-xs leading-relaxed text-foreground/90">
                {entry.after || "—"}
              </p>
            </div>
          </div>

          {cli && (
            <div>
              <div className="mb-1.5 flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  <Terminal className="size-3" />
                  CLI
                </span>
                <button
                  type="button"
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(cli);
                      setCopied(true);
                      setTimeout(() => setCopied(false), 1500);
                    } catch {
                      /* ignore */
                    }
                  }}
                  className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-0.5 text-[10px] text-muted-foreground hover:text-foreground"
                >
                  {copied ? <Check className="size-3 text-emerald-400" /> : <Copy className="size-3" />}
                  {copied ? "Copied" : "Copy"}
                </button>
              </div>
              <pre className="max-h-36 overflow-auto rounded-lg border border-border bg-[#0a0b0e] p-3 font-mono text-[11px] leading-relaxed text-emerald-400/90">
                {cli}
              </pre>
            </div>
          )}
        </div>
      )}
    </article>
  );
}

export function FixChangeReportPanel({
  report,
  loading,
  onGenerate,
  canGenerate,
}: {
  report: FixChangeReport | null;
  loading: boolean;
  onGenerate: () => void;
  canGenerate: boolean;
}) {
  const [copiedAll, setCopiedAll] = useState(false);

  return (
    <section className="rounded-2xl border border-border bg-panel">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border/70 px-5 py-4">
        <div className="flex items-start gap-3">
          <span className="flex size-9 items-center justify-center rounded-xl bg-violet-500/15 ring-1 ring-violet-500/25">
            <FileText className="size-4 text-violet-300" />
          </span>
          <div>
            <h3 className="text-sm font-semibold text-foreground">
              Fix change report
            </h3>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Before → what changed → after, with CLI and Cloud Assistant notes
            </p>
          </div>
        </div>
        <button
          type="button"
          disabled={!canGenerate || loading}
          onClick={onGenerate}
          className="inline-flex items-center gap-2 rounded-xl border border-violet-500/35 bg-violet-500/15 px-3.5 py-2 text-sm font-semibold text-violet-100 transition hover:bg-violet-500/25 disabled:opacity-40"
        >
          {loading ? (
            <Loader2 className="size-4 animate-spin" />
          ) : (
            <Sparkles className="size-4" />
          )}
          {report ? "Refresh report" : "Generate report"}
        </button>
      </div>

      {!report && !loading && (
        <div className="px-5 py-12 text-center">
          <ShieldAlert className="mx-auto size-8 text-muted-foreground/50" />
          <p className="mt-3 text-sm font-medium text-foreground">
            No report yet
          </p>
          <p className="mx-auto mt-1 max-w-md text-xs leading-relaxed text-muted-foreground">
            Plan or apply fixes first, then generate a report to see how AWS looked
            before, what the job changed, CLI to re-run, and AI explanations.
          </p>
        </div>
      )}

      {loading && !report && (
        <div className="flex items-center justify-center gap-2 px-5 py-14 text-sm text-muted-foreground">
          <Loader2 className="size-4 animate-spin" />
          Building change report…
        </div>
      )}

      {report && (
        <div className="space-y-5 p-5">
          {/* Score strip */}
          <div className="grid gap-3 sm:grid-cols-4">
            {[
              { label: "Score before", value: report.score_before ?? "—" },
              { label: "Score after", value: report.score_after ?? "—" },
              {
                label: "Delta",
                value:
                  report.score_delta != null
                    ? `${report.score_delta > 0 ? "+" : ""}${report.score_delta}`
                    : "—",
              },
              {
                label: "Actions",
                value: `${report.counts.applied}✓ / ${report.counts.failed}✗ / ${report.counts.total}`,
              },
            ].map((c) => (
              <div
                key={c.label}
                className="rounded-xl border border-border/70 bg-background/40 px-3 py-3"
              >
                <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                  {c.label}
                </p>
                <p className="mt-1 text-lg font-semibold tabular-nums text-foreground">
                  {c.value}
                </p>
              </div>
            ))}
          </div>

          <div className="rounded-xl border border-accent-blue/20 bg-gradient-to-br from-accent-blue/10 to-transparent p-4">
            <div className="flex items-center gap-2">
              <Sparkles className="size-3.5 text-accent-blue" />
              <p className="text-[10px] font-semibold uppercase tracking-wider text-accent-blue">
                Executive summary{report.ai_used ? " · AI" : ""}
              </p>
            </div>
            <p className="mt-2 text-sm leading-relaxed text-foreground/90">
              {report.executive_summary}
            </p>
            <p className="mt-2 font-mono text-[10px] text-muted-foreground">
              {report.report_id} · job {report.job_id} ·{" "}
              {report.generated_at?.replace("T", " ").replace("Z", " UTC")}
            </p>
          </div>

          {report.recommendations?.length > 0 && (
            <div>
              <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Recommendations
              </p>
              <ul className="space-y-1.5">
                {report.recommendations.map((r) => (
                  <li
                    key={r}
                    className="flex gap-2 rounded-lg border border-border/60 bg-background/30 px-3 py-2 text-xs leading-relaxed text-foreground/85"
                  >
                    <span className="mt-0.5 text-accent-blue">•</span>
                    <span>{r}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div>
            <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Detailed changes
            </p>
            <div className="space-y-2.5">
              {(report.changes || []).map((c) => (
                <ChangeBlock
                  key={c.action_id || `${c.rule_id}-${c.resource}`}
                  entry={c}
                />
              ))}
            </div>
          </div>

          {report.cli_script && (
            <div className="rounded-xl border border-amber-500/25 bg-amber-500/[0.05] p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="flex items-center gap-2 text-sm font-semibold text-amber-100">
                  <Terminal className="size-4" />
                  Full CLI script
                </p>
                <button
                  type="button"
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(report.cli_script || "");
                      setCopiedAll(true);
                      setTimeout(() => setCopiedAll(false), 2000);
                    } catch {
                      /* ignore */
                    }
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/30 bg-amber-500/15 px-3 py-1.5 text-xs font-semibold text-amber-100"
                >
                  {copiedAll ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
                  {copiedAll ? "Copied" : "Copy all"}
                </button>
              </div>
              <pre className="mt-3 max-h-56 overflow-auto rounded-lg border border-border bg-[#0a0b0e] p-3 font-mono text-[11px] leading-relaxed text-foreground/85">
                {report.cli_script}
              </pre>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
