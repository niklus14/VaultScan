"use client";

import { useLiveData } from "@/lib/scan-store";
import { cn } from "@/lib/utils";

function scoreColor(score: number) {
  if (score >= 90) return "text-success";
  if (score >= 70) return "text-warning";
  return "text-danger";
}

export function ScanHistoryTab() {
  const { history } = useLiveData();
  return (
    <div className="rounded-lg border border-border bg-panel">
      <div className="flex items-center justify-between border-b border-border px-5 py-3">
        <h3 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
          SCAN HISTORY — AUDIT LOG
        </h3>
        <span className="font-mono text-[11px] text-muted-foreground">
          {history.length} RECORDS
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left">
          <thead>
            <tr className="border-b border-border font-mono text-[10px] tracking-[0.14em] text-muted-foreground">
              <th className="px-5 py-3 font-medium">SCAN ID</th>
              <th className="px-5 py-3 font-medium">TIMESTAMP</th>
              <th className="px-5 py-3 font-medium">SCORE</th>
              <th className="px-5 py-3 font-medium">CRITICAL FINDINGS</th>
            </tr>
          </thead>
          <tbody>
            {history.map((s) => (
              <tr
                key={s.id || s.scan_id}
                className="border-b border-border/60 transition-colors last:border-0 hover:bg-white/[0.02]"
              >
                <td className="px-5 py-3 font-mono text-xs font-bold text-foreground">
                  {s.id || s.scan_id}
                </td>
                <td className="px-5 py-3 font-mono text-xs text-muted-foreground">
                  {s.timestamp}
                </td>
                <td className="px-5 py-3">
                  <span
                    className={cn(
                      "font-mono text-sm font-bold",
                      scoreColor(s.score),
                    )}
                  >
                    {s.score}%
                  </span>
                </td>
                <td className="px-5 py-3">
                  <span
                    className={cn(
                      "inline-flex min-w-6 justify-center rounded-sm border px-2 py-0.5 font-mono text-[11px] font-bold",
                      s.critical === 0
                        ? "border-success/40 bg-success/10 text-success"
                        : "border-danger/40 bg-danger/10 text-danger",
                    )}
                  >
                    {String(s.critical).padStart(2, "0")}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
