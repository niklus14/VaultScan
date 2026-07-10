"use client";

import { useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  ReferenceLine,
  Dot,
} from "recharts";
import {
  TrendingDown,
  TrendingUp,
  Minus,
  Activity,
  AlertTriangle,
} from "lucide-react";
import { cn } from "@/lib/utils";

export type TrendPoint = {
  t: string;
  label: string;
  score: number;
  scanId: string;
  critical: number;
  high?: number;
  total?: number;
  timestamp: string;
  delta?: number | null;
};

function formatTick(iso: string): string {
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso.slice(0, 10);
    return d.toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

function shortTick(iso: string): string {
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso.slice(11, 16) || iso.slice(0, 8);
    return d.toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

export function buildTrendFromHistory(
  history: Array<{
    scan_id?: string;
    id?: string;
    timestamp: string;
    score: number;
    critical?: number;
    summary?: Record<string, number>;
    total_findings?: number;
  }>,
): TrendPoint[] {
  // history is newest-first from API
  const chronological = [...history].reverse();
  return chronological.map((s, i, arr) => {
    const prev = i > 0 ? arr[i - 1].score : null;
    const score = s.score;
    return {
      t: shortTick(s.timestamp),
      label: formatTick(s.timestamp),
      score,
      scanId: s.scan_id || s.id || `scan-${i}`,
      critical: s.critical ?? s.summary?.CRITICAL ?? 0,
      high: s.summary?.HIGH,
      total: s.total_findings,
      timestamp: s.timestamp,
      delta: prev === null ? null : score - prev,
    };
  });
}

function ChartTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: Array<{ payload: TrendPoint }>;
}) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  const delta = p.delta;
  return (
    <div className="min-w-[180px] rounded-md border border-border-strong bg-panel-alt px-3 py-2.5 shadow-xl">
      <p className="font-mono text-[10px] text-muted-foreground">{p.label}</p>
      <p className="mt-1 font-mono text-[10px] text-muted-foreground">
        {p.scanId}
      </p>
      <p className="mt-1 font-mono text-lg font-bold text-foreground">
        {p.score}
        <span className="text-sm text-muted-foreground">/100</span>
      </p>
      {delta !== null && delta !== undefined && (
        <p
          className={cn(
            "mt-0.5 font-mono text-[11px] font-bold",
            delta > 0
              ? "text-success"
              : delta < 0
                ? "text-danger"
                : "text-muted-foreground",
          )}
        >
          {delta > 0 ? "▲" : delta < 0 ? "▼" : "●"}{" "}
          {delta > 0 ? "+" : ""}
          {delta} vs previous scan
        </p>
      )}
      <div className="mt-2 space-y-0.5 border-t border-border pt-2 font-mono text-[10px] text-muted-foreground">
        <p>
          Critical:{" "}
          <span className={p.critical > 0 ? "text-danger" : "text-success"}>
            {p.critical}
          </span>
        </p>
        {p.total !== undefined && <p>Total findings: {p.total}</p>}
      </div>
    </div>
  );
}

function ActiveDot(props: {
  cx?: number;
  cy?: number;
  payload?: TrendPoint;
  selectedId?: string | null;
}) {
  const { cx, cy, payload, selectedId } = props;
  if (cx == null || cy == null || !payload) return null;
  const selected = selectedId === payload.scanId;
  return (
    <circle
      cx={cx}
      cy={cy}
      r={selected ? 6 : 4}
      fill={selected ? "#00e676" : "#3874ff"}
      stroke="#0b0c10"
      strokeWidth={2}
    />
  );
}

export function PostureChart({
  data,
  onSelectScan,
}: {
  data?: TrendPoint[];
  onSelectScan?: (scanId: string) => void;
}) {
  const series = data ?? [];
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const insights = useMemo(() => {
    if (series.length === 0) return null;
    const scores = series.map((p) => p.score);
    const first = series[0];
    const last = series[series.length - 1];
    const best = series.reduce((a, b) => (a.score >= b.score ? a : b));
    const worst = series.reduce((a, b) => (a.score <= b.score ? a : b));
    const avg = Math.round(
      scores.reduce((a, b) => a + b, 0) / scores.length,
    );
    const change = last.score - first.score;
    const criticalTrend =
      last.critical - (series.length > 1 ? series[series.length - 2].critical : last.critical);
    return { first, last, best, worst, avg, change, criticalTrend, count: series.length };
  }, [series]);

  const yDomain = useMemo((): [number, number] => {
    if (!series.length) return [0, 100];
    const scores = series.map((p) => p.score);
    const min = Math.min(...scores, 0);
    const max = Math.max(...scores, 100);
    const pad = 8;
    return [Math.max(0, min - pad), Math.min(100, max + pad)];
  }, [series]);

  if (series.length === 0) {
    return (
      <div className="flex h-[280px] flex-col items-center justify-center gap-3 rounded-md border border-dashed border-border bg-panel-alt/40 px-6 text-center">
        <Activity className="size-8 text-muted-foreground/50" />
        <div>
          <p className="font-mono text-xs font-bold tracking-wider text-foreground">
            NO SCAN HISTORY YET
          </p>
          <p className="mt-2 max-w-sm text-[12px] leading-relaxed text-muted-foreground">
            This chart tracks your <strong className="text-foreground">real posture score</strong> after
            each scan. Run scans over time to see if security is improving or getting worse — and by how much.
          </p>
        </div>
        <p className="font-mono text-[10px] text-muted-foreground">
          Tip: Launch a scan, fix issues, re-scan — the line should climb toward 100.
        </p>
      </div>
    );
  }

  if (series.length === 1) {
    const p = series[0];
    return (
      <div className="space-y-4">
        <div className="flex h-[200px] flex-col items-center justify-center gap-2 rounded-md border border-border bg-panel-alt/30">
          <p className="font-mono text-[10px] tracking-wider text-muted-foreground">
            SINGLE BASELINE SCAN
          </p>
          <p className={cn("font-mono text-5xl font-bold", scoreColor(p.score))}>
            {p.score}
            <span className="text-xl text-muted-foreground">%</span>
          </p>
          <p className="font-mono text-[11px] text-muted-foreground">
            {p.scanId} · {p.label}
          </p>
          <p className="max-w-md px-4 text-center text-[12px] text-muted-foreground">
            Run another scan after remediating findings to start a real trend.
            Improvement or regression will appear here automatically.
          </p>
        </div>
        <InsightStrip insights={insights!} />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="h-[220px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={series}
            margin={{ top: 12, right: 12, left: -8, bottom: 0 }}
            onClick={(state) => {
              const id = (state as { activePayload?: Array<{ payload: TrendPoint }> })
                ?.activePayload?.[0]?.payload?.scanId;
              if (id) {
                setSelectedId(id);
                onSelectScan?.(id);
              }
            }}
          >
            <defs>
              <linearGradient id="postureFillLive" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#3874ff" stopOpacity={0.4} />
                <stop offset="100%" stopColor="#3874ff" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
            <XAxis
              dataKey="t"
              stroke="#6b7280"
              tickLine={false}
              axisLine={false}
              fontSize={10}
              fontFamily="var(--font-ubuntu-mono)"
              interval="preserveStartEnd"
              minTickGap={28}
            />
            <YAxis
              domain={yDomain}
              stroke="#6b7280"
              tickLine={false}
              axisLine={false}
              fontSize={10}
              fontFamily="var(--font-ubuntu-mono)"
              width={36}
              tickFormatter={(v) => `${v}`}
            />
            <ReferenceLine
              y={insights?.avg ?? 0}
              stroke="rgba(255,255,255,0.15)"
              strokeDasharray="4 4"
              label={{
                value: `avg ${insights?.avg}`,
                position: "insideTopRight",
                fill: "#6b7280",
                fontSize: 9,
              }}
            />
            <Tooltip content={<ChartTooltip />} cursor={{ stroke: "#3874ff", strokeDasharray: "4 4" }} />
            <Area
              type="monotone"
              dataKey="score"
              stroke="#3874ff"
              strokeWidth={2.5}
              fill="url(#postureFillLive)"
              dot={<ActiveDot selectedId={selectedId} />}
              activeDot={{ r: 6, fill: "#00e676", stroke: "#0b0c10", strokeWidth: 2 }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <InsightStrip insights={insights!} />

      {/* Compact history table under chart */}
      <div className="overflow-x-auto rounded-md border border-border">
        <table className="w-full min-w-[480px] border-collapse text-left">
          <thead>
            <tr className="border-b border-border bg-panel-alt font-mono text-[10px] tracking-wider text-muted-foreground">
              <th className="px-3 py-2 font-medium">WHEN</th>
              <th className="px-3 py-2 font-medium">SCAN</th>
              <th className="px-3 py-2 font-medium">SCORE</th>
              <th className="px-3 py-2 font-medium">Δ</th>
              <th className="px-3 py-2 font-medium">CRITICAL</th>
            </tr>
          </thead>
          <tbody>
            {[...series].reverse().map((p) => (
              <tr
                key={p.scanId}
                className={cn(
                  "border-t border-border/60 font-mono text-[11px] transition hover:bg-white/[0.03]",
                  selectedId === p.scanId && "bg-accent-blue/10",
                )}
                onClick={() => {
                  setSelectedId(p.scanId);
                  onSelectScan?.(p.scanId);
                }}
              >
                <td className="px-3 py-2 text-muted-foreground">{p.label}</td>
                <td className="px-3 py-2 font-bold text-foreground">{p.scanId}</td>
                <td className={cn("px-3 py-2 font-bold", scoreColor(p.score))}>
                  {p.score}%
                </td>
                <td className="px-3 py-2">
                  {p.delta === null || p.delta === undefined ? (
                    <span className="text-muted-foreground">—</span>
                  ) : (
                    <span
                      className={cn(
                        "font-bold",
                        p.delta > 0
                          ? "text-success"
                          : p.delta < 0
                            ? "text-danger"
                            : "text-muted-foreground",
                      )}
                    >
                      {p.delta > 0 ? "+" : ""}
                      {p.delta}
                    </span>
                  )}
                </td>
                <td
                  className={cn(
                    "px-3 py-2 font-bold",
                    p.critical > 0 ? "text-danger" : "text-success",
                  )}
                >
                  {String(p.critical).padStart(2, "0")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function scoreColor(score: number) {
  if (score >= 90) return "text-success";
  if (score >= 70) return "text-warning";
  return "text-danger";
}

function InsightStrip({
  insights,
}: {
  insights: {
    first: TrendPoint;
    last: TrendPoint;
    best: TrendPoint;
    worst: TrendPoint;
    avg: number;
    change: number;
    criticalTrend: number;
    count: number;
  };
}) {
  const { change, avg, best, worst, last, count, criticalTrend } = insights;
  const TrendIcon =
    change > 0 ? TrendingUp : change < 0 ? TrendingDown : Minus;
  const trendLabel =
    change > 0
      ? `Improved +${change} pts since first scan`
      : change < 0
        ? `Declined ${change} pts since first scan`
        : "No net change since first scan";

  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
      <div className="rounded-md border border-border bg-panel-alt px-3 py-2.5">
        <p className="font-mono text-[9px] tracking-wider text-muted-foreground">
          TREND ({count} SCANS)
        </p>
        <div className="mt-1 flex items-center gap-1.5">
          <TrendIcon
            className={cn(
              "size-3.5",
              change > 0
                ? "text-success"
                : change < 0
                  ? "text-danger"
                  : "text-muted-foreground",
            )}
          />
          <p
            className={cn(
              "font-mono text-[11px] font-bold leading-snug",
              change > 0
                ? "text-success"
                : change < 0
                  ? "text-danger"
                  : "text-muted-foreground",
            )}
          >
            {trendLabel}
          </p>
        </div>
      </div>
      <div className="rounded-md border border-border bg-panel-alt px-3 py-2.5">
        <p className="font-mono text-[9px] tracking-wider text-muted-foreground">
          LATEST / AVG
        </p>
        <p className="mt-1 font-mono text-sm font-bold text-foreground">
          <span className={scoreColor(last.score)}>{last.score}</span>
          <span className="text-muted-foreground"> / {avg}</span>
        </p>
      </div>
      <div className="rounded-md border border-border bg-panel-alt px-3 py-2.5">
        <p className="font-mono text-[9px] tracking-wider text-muted-foreground">
          BEST · WORST
        </p>
        <p className="mt-1 font-mono text-sm font-bold">
          <span className="text-success">{best.score}</span>
          <span className="text-muted-foreground"> · </span>
          <span className="text-danger">{worst.score}</span>
        </p>
      </div>
      <div className="rounded-md border border-border bg-panel-alt px-3 py-2.5">
        <p className="font-mono text-[9px] tracking-wider text-muted-foreground">
          CRITICAL Δ (LAST STEP)
        </p>
        <p
          className={cn(
            "mt-1 flex items-center gap-1 font-mono text-sm font-bold",
            criticalTrend > 0
              ? "text-danger"
              : criticalTrend < 0
                ? "text-success"
                : "text-muted-foreground",
          )}
        >
          {criticalTrend !== 0 && (
            <AlertTriangle className="size-3.5 opacity-80" />
          )}
          {criticalTrend > 0 ? "+" : ""}
          {criticalTrend} critical
        </p>
      </div>
    </div>
  );
}
