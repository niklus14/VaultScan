"use client";

import { CheckCircle2, Circle, Terminal } from "lucide-react";
import { useLiveData } from "@/lib/scan-store";
import { cn } from "@/lib/utils";

export function RemediationHubTab() {
  const { remediation: pb } = useLiveData();
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <div className="rounded-lg border border-border bg-panel p-5">
        <h3 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
          AUTOMATION PLAYBOOK
        </h3>
        <p className="mt-1 mb-4 text-xs text-muted-foreground">{pb.title}</p>
        <ol className="space-y-2">
          {pb.steps.map((step) => (
            <li
              key={step.id}
              className={cn(
                "flex items-center gap-3 rounded-md border px-3 py-2.5",
                step.done
                  ? "border-success/30 bg-success/5"
                  : "border-border bg-panel-alt",
              )}
            >
              {step.done ? (
                <CheckCircle2 className="size-4 shrink-0 text-success" />
              ) : (
                <Circle className="size-4 shrink-0 text-muted-foreground" />
              )}
              <span
                className={cn(
                  "text-xs",
                  step.done ? "text-foreground" : "text-muted-foreground",
                )}
              >
                {step.label}
              </span>
            </li>
          ))}
        </ol>
      </div>

      <div className="overflow-hidden rounded-lg border border-border bg-[#0a0b0e] lg:col-span-2">
        <div className="flex items-center gap-2 border-b border-border bg-panel px-4 py-2.5">
          <div className="flex gap-1.5">
            <span className="size-2.5 rounded-full bg-danger" />
            <span className="size-2.5 rounded-full bg-warning" />
            <span className="size-2.5 rounded-full bg-success" />
          </div>
          <div className="ml-2 flex items-center gap-1.5 font-mono text-[11px] text-muted-foreground">
            <Terminal className="size-3.5" />
            vaultscan — {pb.target}
          </div>
        </div>
        <pre className="overflow-x-auto p-5 font-mono text-xs leading-6 text-success">
          {pb.lines.map((line, i) => (
            <div key={i}>
              {line}
              {i === pb.lines.length - 1 && (
                <span className="pulse-dot ml-0.5 inline-block h-3.5 w-2 translate-y-0.5 bg-success" />
              )}
            </div>
          ))}
        </pre>
      </div>
    </div>
  );
}
