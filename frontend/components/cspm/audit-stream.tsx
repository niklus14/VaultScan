"use client";

import { Activity, Filter } from "lucide-react";
import { useMemo, useState } from "react";
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

const FILTERS: Array<{ id: "ALL" | LogLevel; label: string }> = [
  { id: "ALL", label: "ALL" },
  { id: "CRIT", label: "CRIT" },
  { id: "MED", label: "MED" },
  { id: "INF", label: "INF" },
];

/**
 * @param variant "panel" = overview embedded (spacious, multi-col)
 *                "rail"  = optional narrow side rail
 */
export function AuditStream({
  variant = "panel",
}: {
  variant?: "panel" | "rail";
}) {
  const { auditStream } = useLiveData();
  const [filter, setFilter] = useState<"ALL" | LogLevel>("ALL");

  const events = useMemo(() => {
    if (filter === "ALL") return auditStream;
    return auditStream.filter((e) => e.level === filter);
  }, [auditStream, filter]);

  const counts = useMemo(() => {
    const c = { CRIT: 0, MED: 0, INF: 0, ALL: auditStream.length };
    for (const e of auditStream) {
      if (e.level === "CRIT") c.CRIT++;
      else if (e.level === "MED") c.MED++;
      else c.INF++;
    }
    return c;
  }, [auditStream]);

  if (variant === "rail") {
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
          <EventList events={events} dense />
        </div>
      </aside>
    );
  }

  // Full overview panel
  return (
    <section className="flex min-h-[320px] flex-col rounded-lg border border-border bg-panel lg:min-h-[380px]">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-5 py-3.5">
        <div className="flex items-center gap-2.5">
          <div className="flex size-8 items-center justify-center rounded-md bg-accent-blue/15 text-accent-blue">
            <Activity className="size-4" />
          </div>
          <div>
            <h3 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
              LOG AUDIT STREAM
            </h3>
            <p className="text-[11px] text-muted-foreground">
              Live scan events · {events.length} shown
              {filter !== "ALL" ? ` (filtered)` : ""}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="hidden items-center gap-1 font-mono text-[10px] text-muted-foreground sm:flex">
            <Filter className="size-3" />
            FILTER
          </span>
          {FILTERS.map((f) => (
            <button
              key={f.id}
              type="button"
              onClick={() => setFilter(f.id)}
              className={cn(
                "rounded-sm border px-2 py-1 font-mono text-[10px] font-bold tracking-wider transition",
                filter === f.id
                  ? f.id === "CRIT"
                    ? "border-danger/40 bg-danger/15 text-danger"
                    : f.id === "MED"
                      ? "border-warning/40 bg-warning/15 text-warning"
                      : f.id === "INF"
                        ? "border-accent-blue/40 bg-accent-blue/15 text-accent-blue"
                        : "border-accent-blue/40 bg-accent-blue/15 text-accent-blue"
                  : "border-border bg-panel-alt text-muted-foreground hover:text-foreground",
              )}
            >
              {f.label}
              <span className="ml-1 opacity-70">
                {f.id === "ALL" ? counts.ALL : counts[f.id]}
              </span>
            </button>
          ))}
          <span className="pulse-dot ml-1 size-2 rounded-full bg-success" />
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-4">
        {events.length === 0 ? (
          <div className="flex h-40 items-center justify-center rounded-md border border-dashed border-border font-mono text-xs text-muted-foreground">
            No events for this filter — run a scan or switch to ALL.
          </div>
        ) : (
          <EventList events={events} dense={false} />
        )}
      </div>
    </section>
  );
}

function EventList({
  events,
  dense,
}: {
  events: Array<{
    level: string;
    header: string;
    message: string;
    time: string;
  }>;
  dense: boolean;
}) {
  return (
    <ul
      className={cn(
        dense
          ? "space-y-2"
          : "grid grid-cols-1 gap-3 xl:grid-cols-2 2xl:grid-cols-3",
      )}
    >
      {events.map((event, i) => (
        <li
          key={`${event.time}-${event.header}-${i}`}
          className={cn(
            "relative overflow-hidden rounded-md border border-border bg-panel-alt transition-colors hover:border-border-strong",
            dense ? "p-3" : "p-4",
          )}
        >
          <span
            className={cn(
              "absolute inset-y-0 left-0 w-0.5",
              accentBar[event.level as LogLevel] || "bg-muted-foreground",
            )}
          />
          <div className="mb-1.5 flex items-center justify-between gap-2 pl-1">
            <span
              className={cn(
                "rounded-sm border px-1.5 py-0.5 font-mono text-[10px] font-bold tracking-wider",
                levelStyles[event.level as LogLevel] || levelStyles.INF,
              )}
            >
              {event.level}
            </span>
            <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
              {event.time}
            </span>
          </div>
          <p
            className={cn(
              "pl-1 font-mono font-bold tracking-wide text-foreground",
              dense ? "text-[11px]" : "text-xs sm:text-[13px]",
            )}
          >
            {event.header}
          </p>
          <p
            className={cn(
              "mt-1.5 pl-1 leading-relaxed text-muted-foreground",
              dense ? "text-[11px]" : "text-[12px] sm:text-[13px]",
            )}
          >
            {event.message}
          </p>
        </li>
      ))}
    </ul>
  );
}
