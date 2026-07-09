"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { postureTrend as defaultTrend } from "./data";

function ChartTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: { value: number }[];
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="border border-border-strong bg-panel-alt px-3 py-2 font-mono text-xs">
      <div className="text-muted-foreground">{label}</div>
      <div className="text-success font-bold">
        SCORE: {payload[0].value}%
      </div>
    </div>
  );
}

export function PostureChart({
  data,
}: {
  data?: Array<{ t: string; score: number }>;
}) {
  const series = data?.length ? data : defaultTrend;
  return (
    <div className="h-[220px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={series}
          margin={{ top: 10, right: 8, left: -20, bottom: 0 }}
        >
          <defs>
            <linearGradient id="postureFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#3874ff" stopOpacity={0.35} />
              <stop offset="100%" stopColor="#3874ff" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid
            stroke="rgba(255,255,255,0.05)"
            vertical={false}
          />
          <XAxis
            dataKey="t"
            stroke="#6b7280"
            tickLine={false}
            axisLine={false}
            fontSize={10}
            fontFamily="var(--font-ubuntu-mono)"
            interval={1}
          />
          <YAxis
            domain={[40, 100]}
            stroke="#6b7280"
            tickLine={false}
            axisLine={false}
            fontSize={10}
            fontFamily="var(--font-ubuntu-mono)"
            width={40}
          />
          <Tooltip
            content={<ChartTooltip />}
            cursor={{ stroke: "#3874ff", strokeDasharray: "4 4" }}
          />
          <Area
            type="monotone"
            dataKey="score"
            stroke="#3874ff"
            strokeWidth={2}
            fill="url(#postureFill)"
            dot={false}
            activeDot={{ r: 4, fill: "#3874ff", stroke: "#0b0c10", strokeWidth: 2 }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
