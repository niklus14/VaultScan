"use client";

import { useState } from "react";
import {
  FileText,
  Loader2,
  FileDown,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Compact export panel — full report lives in PDF / Word, not on-page.
 */
export function FixChangeReportPanel({
  jobId,
  canGenerate,
  useAi,
  onExport,
}: {
  jobId: string | null;
  canGenerate: boolean;
  useAi: boolean;
  onExport: (format: "pdf" | "docx") => Promise<void>;
}) {
  const [busy, setBusy] = useState<"pdf" | "docx" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);

  const run = async (format: "pdf" | "docx") => {
    if (!jobId) return;
    setBusy(format);
    setError(null);
    setOk(null);
    try {
      await onExport(format);
      setOk(
        format === "pdf"
          ? "PDF downloaded — open it for before / after / CLI / AI notes."
          : "Word document downloaded — open it for the full change report.",
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Export failed");
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="rounded-2xl border border-border bg-panel p-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex max-w-xl items-start gap-3">
          <span className="flex size-10 items-center justify-center rounded-xl bg-violet-500/15 ring-1 ring-violet-500/30">
            <FileText className="size-5 text-violet-300" />
          </span>
          <div>
            <h3 className="text-sm font-semibold text-foreground">
              Fix change report
            </h3>
            <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
              Download a clear <strong className="text-foreground">PDF</strong> or{" "}
              <strong className="text-foreground">Word</strong> document with:
              how it was before, what changed, after state, CLI commands, and
              Cloud Assistant notes. Easier to read than a long page.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            disabled={!canGenerate || !!busy}
            onClick={() => void run("pdf")}
            className={cn(
              "inline-flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-semibold transition",
              "bg-rose-500/15 text-rose-100 ring-1 ring-rose-500/35 hover:bg-rose-500/25",
              "disabled:opacity-40",
            )}
          >
            {busy === "pdf" ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <FileDown className="size-4" />
            )}
            Download PDF
          </button>
          <button
            type="button"
            disabled={!canGenerate || !!busy}
            onClick={() => void run("docx")}
            className={cn(
              "inline-flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-semibold transition",
              "bg-sky-500/15 text-sky-100 ring-1 ring-sky-500/35 hover:bg-sky-500/25",
              "disabled:opacity-40",
            )}
          >
            {busy === "docx" ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <FileDown className="size-4" />
            )}
            Download Word
          </button>
        </div>
      </div>

      {!canGenerate && (
        <p className="mt-4 text-xs text-muted-foreground">
          Plan or apply fixes first — the report is built from the current job
          {useAi ? " (with AI notes when available)" : ""}.
        </p>
      )}

      {error && (
        <div className="mt-4 flex gap-2 rounded-xl border border-rose-500/30 bg-rose-500/10 px-3 py-2.5 text-sm text-rose-100">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          {error}
        </div>
      )}
      {ok && (
        <div className="mt-4 flex gap-2 rounded-xl border border-emerald-500/25 bg-emerald-500/10 px-3 py-2.5 text-sm text-emerald-100">
          <CheckCircle2 className="mt-0.5 size-4 shrink-0" />
          {ok}
        </div>
      )}

      <ul className="mt-4 grid gap-2 text-xs text-muted-foreground sm:grid-cols-2 lg:grid-cols-4">
        {[
          "Before — snapshot / misconfig",
          "What changed — apply result",
          "After — expected AWS state",
          "CLI + AI recommendations",
        ].map((t) => (
          <li
            key={t}
            className="rounded-lg border border-border/60 bg-background/30 px-3 py-2"
          >
            {t}
          </li>
        ))}
      </ul>
    </section>
  );
}
