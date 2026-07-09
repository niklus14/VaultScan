"use client";

import { Activity } from "lucide-react";
import { useLiveData } from "@/lib/scan-store";
import type { LogLevel } from "./data";
import { cn } from "@/lib/utils";

const levelStyles: Record<LogLevel, string> = {
  INF: "border-accent-blue/40 bg-accent-blue/10 text-accent-blue",
  MED: "border-warning/40 bg-warning/10 text-warning",
  CRIT: "border-danger/40 bg-danger/10 text-danger",
};

const accentBar: Record<LogLevel, string> = {
  INF: "bg-accent-blue",
  MED: "bg-warning",
  CRIT: "bg-danger",
};

export function AuditStream() {
  const { auditStream } = useLiveData();

  return (
    <aside className="flex h-full w-full flex-col border-l border-border bg-panel">
      <div className="flex items-center justify-between border-b border-border px-4 py-4">
        <div className="flex items-center gap-2">
          <Activity className="size-4 text-accent-blue" />
          <h2 className="font-mono text-xs font-bold tracking-[0.16em] text-foreground">
            LOG AUDIT STREAM
          </h2>
        </div>
        <span className="pulse-dot size-2 rounded-full bg-success" />
      </div>

      <div className="flex-1 overflow-y-auto px-3 py-3">
        <ul className="space-y-2">
          {auditStream.map((event, i) => (
            <li
              key={i}
              className="relative overflow-hidden rounded-md border border-border bg-panel-alt p-3 transition-colors hover:border-border-strong"
            >
              <span
                className={cn(
                  "absolute inset-y-0 left-0 w-0.5",
                  accentBar[event.level as LogLevel],
                )}
              />
              <div className="mb-1.5 flex items-center justify-between">
                <span
                  className={cn(
                    "rounded-sm border px-1.5 py-0.5 font-mono text-[10px] font-bold tracking-wider",
                    levelStyles[event.level as LogLevel],
                  )}
                >
                  {event.level}
                </span>
                <span className="font-mono text-[10px] text-muted-foreground">
                  {event.time}
                </span>
              </div>
              <p className="font-mono text-[11px] font-bold tracking-wide text-foreground">
                {event.header}
              </p>
              <p className="mt-1 text-[11px] leading-snug text-muted-foreground">
                {event.message}
              </p>
            </li>
          ))}
        </ul>
      </div>
    </aside>
  );
}
