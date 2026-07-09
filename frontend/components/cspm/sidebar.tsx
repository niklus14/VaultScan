"use client";

import {
  ShieldHalf,
  Radar,
  Loader2,
  Settings2,
  Link2,
  ShieldCheck,
  Hexagon,
} from "lucide-react";
import { NAV_ITEMS, type TabId } from "./data";
import { useLiveData } from "@/lib/scan-store";
import { cn } from "@/lib/utils";

export function Sidebar({
  active,
  onSelect,
}: {
  active: TabId;
  onSelect: (id: TabId) => void;
}) {
  const {
    launchScan,
    loading,
    mode,
    connection,
    error,
    isLive,
    score,
    config,
  } = useLiveData();

  const onLaunch = async () => {
    try {
      await launchScan();
    } catch {
      // error is in store
    }
  };

  const connected =
    mode === "simulate" ||
    connection?.connected ||
    config?.ready_to_scan;

  const statusText =
    mode === "simulate"
      ? "DEMO MODE"
      : connection?.connected
        ? `AWS ${connection.account_id || "CONNECTED"}`
        : config?.credentials_configured
          ? "KEYS SAVED · UNVERIFIED"
          : "NOT CONNECTED";

  return (
    <aside className="flex h-full w-full flex-col border-r border-border bg-panel">
      {/* Premium brand header */}
      <div className="relative overflow-hidden border-b border-border px-5 py-5">
        <div
          className="pointer-events-none absolute inset-0 opacity-40"
          style={{
            background:
              "radial-gradient(ellipse 80% 70% at 10% 0%, rgba(56,116,255,0.22), transparent 55%)",
          }}
        />
        <div className="relative flex items-center gap-3">
          <div className="relative">
            <div className="glow-blue flex size-11 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-accent-blue to-[#1e4fd6] shadow-lg">
              <ShieldHalf className="size-5 text-white" strokeWidth={2.4} />
            </div>
            <span className="absolute -bottom-0.5 -right-0.5 flex size-3.5 items-center justify-center rounded-full border-2 border-panel bg-success">
              <span className="size-1 rounded-full bg-panel" />
            </span>
          </div>
          <div className="min-w-0 leading-tight">
            <div className="flex items-center gap-2">
              <h1 className="bg-gradient-to-r from-foreground via-foreground to-accent-blue bg-clip-text font-mono text-[13px] font-bold tracking-[0.14em] text-transparent">
                VAULTSCAN
              </h1>
              <span className="rounded border border-accent-blue/30 bg-accent-blue/10 px-1.5 py-px font-mono text-[8px] font-bold tracking-wider text-accent-blue">
                CSPM
              </span>
            </div>
            <p className="mt-1 text-[10px] font-medium tracking-[0.12em] text-muted-foreground">
              Cloud Security Posture
            </p>
          </div>
        </div>
      </div>

      <nav className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <div className="flex-1 overflow-y-auto px-3 py-5">
          <p className="mb-3 px-2 font-mono text-[10px] tracking-[0.24em] text-muted-foreground">
            // MONITOR MATRIX
          </p>
          <ul className="space-y-1">
            {NAV_ITEMS.map((item) => {
              const isActive = active === item.id;
              return (
                <li key={item.id}>
                  <button
                    onClick={() => onSelect(item.id)}
                    className={cn(
                      "group flex w-full items-center gap-3 rounded-md border px-3 py-2.5 text-left transition-colors",
                      isActive
                        ? "border-accent-blue/40 bg-accent-blue/10"
                        : "border-transparent hover:border-border hover:bg-white/[0.03]",
                    )}
                  >
                    <span
                      className={cn(
                        "font-mono text-[10px]",
                        isActive
                          ? "text-accent-blue"
                          : "text-muted-foreground",
                      )}
                    >
                      {item.code}
                    </span>
                    <span
                      className={cn(
                        "flex-1 text-xs font-medium tracking-wide",
                        isActive
                          ? "text-foreground"
                          : "text-muted-foreground group-hover:text-foreground",
                      )}
                    >
                      {item.label}
                    </span>
                    {isActive && (
                      <span className="pulse-dot size-1.5 rounded-full bg-accent-blue" />
                    )}
                  </button>
                </li>
              );
            })}
          </ul>

          <div className="mt-6 space-y-2 rounded-md border border-border bg-panel-alt p-3">
            <div className="flex items-center gap-2">
              <Link2 className="size-3.5 text-accent-blue" />
              <p className="font-mono text-[10px] tracking-[0.18em] text-muted-foreground">
                CLOUD LINK
              </p>
            </div>
            <div className="flex items-center gap-1.5 font-mono text-[10px]">
              <span
                className={cn(
                  "size-1.5 rounded-full",
                  connected ? "bg-success" : "bg-warning",
                )}
              />
              <span className="truncate text-muted-foreground">{statusText}</span>
            </div>
            {config?.connection_name && (
              <p className="truncate font-mono text-[10px] text-foreground">
                {config.connection_name}
              </p>
            )}
            {isLive && (
              <p className="font-mono text-[10px] text-success">
                LAST SCORE {score}%
              </p>
            )}
            <button
              type="button"
              onClick={() => onSelect("settings")}
              className="mt-1 flex w-full items-center justify-center gap-1.5 rounded border border-border bg-background px-2 py-1.5 font-mono text-[10px] font-bold tracking-wider text-muted-foreground transition hover:border-accent-blue/40 hover:text-accent-blue"
            >
              <Settings2 className="size-3" />
              MANAGE CONNECTION
            </button>
          </div>

          <button
            onClick={onLaunch}
            disabled={loading}
            className="glow-success mt-4 flex w-full items-center justify-center gap-2 rounded-md border border-success bg-success/5 px-4 py-3 font-mono text-xs font-bold tracking-[0.14em] text-success transition-colors hover:bg-success/12 disabled:opacity-50"
          >
            {loading ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <Radar className="size-4" />
            )}
            {loading ? "SCANNING…" : "LAUNCH ACTIVE SCAN"}
          </button>

          {error && (
            <p className="mt-2 px-1 font-mono text-[10px] leading-snug text-danger">
              {error}
              {" — "}
              <button
                type="button"
                className="underline"
                onClick={() => onSelect("settings")}
              >
                open Settings
              </button>
            </p>
          )}
        </div>

        {/* Pro brand footer — bottom left */}
        <div className="shrink-0 border-t border-border p-3">
          <div className="relative overflow-hidden rounded-xl border border-border bg-gradient-to-br from-[#12141c] via-panel-alt to-[#0d1528] p-3.5">
            <div
              className="pointer-events-none absolute -right-4 -top-4 size-20 rounded-full opacity-30"
              style={{
                background:
                  "radial-gradient(circle, rgba(56,116,255,0.45), transparent 70%)",
              }}
            />
            <div className="relative flex items-start gap-3">
              <div className="relative flex size-10 shrink-0 items-center justify-center rounded-lg border border-accent-blue/25 bg-accent-blue/10">
                <Hexagon
                  className="absolute size-8 text-accent-blue/25"
                  strokeWidth={1.2}
                />
                <ShieldCheck className="relative size-4 text-accent-blue" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5">
                  <p className="font-mono text-[11px] font-bold tracking-[0.16em] text-foreground">
                    VAULTSCAN
                  </p>
                  <span className="rounded-sm bg-success/15 px-1 py-px font-mono text-[8px] font-bold tracking-wider text-success">
                    PRO
                  </span>
                </div>
                <p className="mt-0.5 text-[10px] leading-snug text-muted-foreground">
                  Enterprise cloud posture · continuous assurance
                </p>
                <div className="mt-2 flex items-center gap-2">
                  <span className="inline-flex items-center gap-1 rounded-full border border-border bg-background/50 px-2 py-0.5 font-mono text-[8px] tracking-wider text-muted-foreground">
                    <span className="pulse-dot size-1 rounded-full bg-success" />
                    ENGINE v1.0
                  </span>
                  <span className="font-mono text-[8px] tracking-wider text-muted-foreground/70">
                    SECURE BY DESIGN
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </nav>
    </aside>
  );
}
