"use client";

import { CheckCircle2, XCircle } from "lucide-react";
import { useLiveData } from "@/lib/scan-store";
import { cn } from "@/lib/utils";

export function ComplianceRegistryTab() {
  const { compliance } = useLiveData();

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      {compliance.map((fw) => {
        const passing = fw.status === "PASSING";
        return (
          <div
            key={fw.name}
            className={cn(
              "rounded-lg border bg-panel p-5",
              passing ? "border-success/25" : "border-danger/25",
            )}
          >
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-foreground">{fw.name}</h3>
                <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                  {fw.version}
                </p>
              </div>
              <span
                className={cn(
                  "flex items-center gap-1.5 rounded-sm border px-2.5 py-1 font-mono text-[10px] font-bold tracking-wider",
                  passing
                    ? "border-success/40 bg-success/10 text-success"
                    : "border-danger/40 bg-danger/10 text-danger",
                )}
              >
                {passing ? (
                  <CheckCircle2 className="size-3.5" />
                ) : (
                  <XCircle className="size-3.5" />
                )}
                {fw.status}
              </span>
            </div>

            <div className="mt-4 flex items-end gap-2">
              <span className="font-mono text-3xl font-bold text-foreground">
                {fw.passed}
              </span>
              <span className="mb-1 font-mono text-sm text-muted-foreground">
                / {fw.total} CONTROLS
              </span>
            </div>

            <div className="mt-4 space-y-3">
              {fw.controls.map((c) => (
                <div key={c.label}>
                  <div className="mb-1 flex items-center justify-between font-mono text-[11px]">
                    <span className="text-muted-foreground">{c.label}</span>
                    <span
                      className={cn(
                        "font-bold",
                        c.value >= 80
                          ? "text-success"
                          : c.value >= 60
                            ? "text-warning"
                            : "text-danger",
                      )}
                    >
                      {c.value}%
                    </span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-panel-alt">
                    <div
                      className={cn(
                        "h-full rounded-full transition-all",
                        c.value >= 80
                          ? "bg-success"
                          : c.value >= 60
                            ? "bg-warning"
                            : "bg-danger",
                      )}
                      style={{ width: `${c.value}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
