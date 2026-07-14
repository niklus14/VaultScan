"use client";

import {
  Radar,
  Loader2,
  Settings2,
  Link2,
  LogOut,
} from "lucide-react";
import { NAV_ITEMS, type TabId } from "./data";
import { useLiveData } from "@/lib/scan-store";
import { BrandCloud } from "./brand-cloud";
import { cn } from "@/lib/utils";
import { getStoredUser } from "@/lib/auth";
import { logoutRequest } from "@/lib/api";
import { clearSession } from "@/lib/auth";

export function Sidebar({
  active,
  onSelect,
  onLogout,
}: {
  active: TabId;
  onSelect: (id: TabId) => void;
  onLogout?: () => void;
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
      {/* Google Cloud–style mark + revolving shields */}
      <div className="relative overflow-hidden border-b border-border px-3 pb-3 pt-4">
        <div
          className="pointer-events-none absolute inset-0 opacity-50"
          style={{
            background:
              "radial-gradient(ellipse 90% 80% at 50% 30%, rgba(66,133,244,0.22), transparent 62%)",
          }}
        />
        <BrandCloud />
        <p className="relative mt-0.5 text-center font-mono text-[10px] font-bold tracking-[0.28em] text-foreground/80">
          VAULTSCAN
        </p>
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

          <div className="mt-3 border-t border-border pt-3">
            <p className="mb-2 truncate px-1 font-mono text-[10px] text-muted-foreground">
              {getStoredUser()?.display_name || getStoredUser()?.username || "Operator"}
            </p>
            <button
              type="button"
              onClick={() => {
                void (async () => {
                  try {
                    await logoutRequest();
                  } catch {
                    /* still clear local session */
                  }
                  clearSession();
                  onLogout?.();
                })();
              }}
              className="flex w-full items-center justify-center gap-1.5 rounded border border-border bg-background px-2 py-1.5 font-mono text-[10px] font-bold tracking-wider text-muted-foreground transition hover:border-danger/40 hover:text-danger"
            >
              <LogOut className="size-3" />
              SIGN OUT
            </button>
          </div>
        </div>

      </nav>
    </aside>
  );
}
